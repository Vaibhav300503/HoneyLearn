"""
Honeypot v2 — Main Application.
SOC-grade AI-powered web honeypot with deep attacker tracking,
attack classification, session replay, MITRE mapping, honeytokens,
threat intelligence export, auto-blocking, and alerting.
"""
import json
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from .database import engine, Base, SessionLocal, get_db
from .models import (
    HoneypotLog, BlockedIP, AttackerFingerprint, AttackerSession,
    SessionEvent, Honeytoken, MitreMapping, AlertLog, BlockEvent
)
from .config import settings
from .ml.anomaly_detector import anomaly_detector
from .ml.attack_classifier import attack_classifier
from .blocking import block_manager
from .fingerprint import upsert_fingerprint, generate_fingerprint_id
from .session_tracker import (
    get_or_create_session, record_event,
    get_session_timeline, get_active_sessions, get_all_sessions
)
from .mitre import record_mitre_mapping, get_session_mitre_summary, get_global_mitre_summary
from .honeytokens import (
    check_for_honeytoken, trigger_honeytoken, create_token_set, get_all_honeytokens
)
from .alerting import dispatch_alert
from .incident_report import generate_incident_report
from .export import export_json, export_csv, export_stix21
from .sanitizer import sanitize_payload

import os

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Honeypot v2 — SOC Threat Detection Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# STARTUP
# ──────────────────────────────────────────────

@app.on_event("startup")
def on_startup():
    block_manager.load_blocked_ips()

    # Train anomaly detector if no model exists
    if anomaly_detector.model is None:
        from .ml.train import train_isolation_forest
        train_isolation_forest()

    # Train attack classifier if no model exists
    if attack_classifier.model is None:
        try:
            from .ml.classifier_train import train_attack_classifier
            train_attack_classifier()
            attack_classifier.reload_model()
        except Exception as e:
            print(f"[STARTUP] Classifier training failed: {e}")


# ──────────────────────────────────────────────
# CORE MIDDLEWARE — The Honeypot Brain
# ──────────────────────────────────────────────

@app.middleware("http")
async def honeypot_middleware(request: Request, call_next):
    """
    Main middleware that processes every request through the honeypot pipeline:
    1. IP check (block list)
    2. Fingerprinting
    3. Session tracking
    4. Honeytoken detection
    5. AI analysis (anomaly + classification)
    6. MITRE mapping
    7. Alerting
    8. Logging
    """
    # 1. Extract client IP
    client_ip = request.client.host
    if request.headers.get("X-Forwarded-For"):
        client_ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()

    # Check block list
    if block_manager.is_blocked(client_ip):
        return Response(
            content="Forbidden: Your IP has been blocked due to malicious activity.",
            status_code=status.HTTP_403_FORBIDDEN
        )

    # Allow dashboard/admin requests from whitelisted IPs
    path = request.url.path
    if client_ip in block_manager.whitelist and path.startswith(("/dashboard", "/api/admin", "/api/fingerprint")):
        return await call_next(request)

    # 2. Extract request data
    method = request.method
    headers_dict = dict(request.headers)
    headers_json = json.dumps(headers_dict)
    user_agent = headers_dict.get("user-agent", "")

    body_bytes = await request.body()
    payload = body_bytes.decode("utf-8", errors="ignore")

    # Combine all text for scanning
    full_request_text = f"{path} {headers_json} {payload}"

    # 3. Open DB session for this request
    db = SessionLocal()
    response_code = 200
    try:
        # 4. Fingerprint the attacker
        fp_id, fingerprint = upsert_fingerprint(
            db, client_ip, user_agent, headers_dict
        )

        # 5. Get/create session
        session_id = get_or_create_session(db, fp_id)

        # 6. Check honeytokens
        token_match = check_for_honeytoken(db, full_request_text)
        honeytoken_triggered = False
        if token_match:
            trigger_honeytoken(db, token_match, client_ip, fp_id)
            honeytoken_triggered = True
            # Record MITRE mapping for token theft
            record_mitre_mapping(db, session_id, None, "honeytoken_triggered", 0.95)

        # 7. AI Analysis
        threat_score, features = anomaly_detector.predict(path, method, headers_json, payload)

        # 8. Attack classification
        classification = attack_classifier.classify(path, method, payload, user_agent)
        attack_type = classification["attack_type"]
        attack_confidence = classification["confidence"]
        detected_patterns = classification["detected_patterns"]

        # Boost threat score if honeytoken was triggered
        if honeytoken_triggered:
            threat_score = max(threat_score, 95)

        is_anomaly = threat_score > 60

        # 9. MITRE mapping for classified attacks
        if attack_type != "benign" and attack_confidence > 0.4:
            record_mitre_mapping(db, session_id, None, attack_type, attack_confidence)

        # 10. Save log entry
        log_entry = HoneypotLog(
            ip_address=client_ip,
            user_agent=user_agent,
            method=method,
            path=path,
            headers=headers_json,
            payload=sanitize_payload(payload),
            threat_score=threat_score,
            anomaly_flag=is_anomaly,
            is_blocked=False,
            fingerprint_id=fp_id,
            session_id=session_id,
            attack_type=attack_type if attack_type != "benign" else None,
            attack_confidence=attack_confidence if attack_type != "benign" else None,
            detected_patterns=json.dumps(detected_patterns) if detected_patterns else None,
        )
        db.add(log_entry)
        db.flush()

        # Update MITRE mapping with log_id
        if attack_type != "benign":
            last_mitre = db.query(MitreMapping).filter(
                MitreMapping.session_id == session_id,
                MitreMapping.log_id == None
            ).order_by(desc(MitreMapping.detected_at)).first()
            if last_mitre:
                last_mitre.log_id = log_entry.id

        # 11. Record session event
        record_event(
            db, session_id, method, path, payload,
            response_code=None,  # We'll update after response
            threat_score=threat_score,
            attack_type=attack_type if attack_type != "benign" else None
        )

        # 12. Check if we need to block (score > threshold)
        if threat_score > settings.THREAT_BLOCK_THRESHOLD:
            block_manager.block_ip(
                client_ip,
                f"High threat score: {threat_score:.0f}. Attack: {attack_type}. Target: {path}",
                auto=True
            )
            db.commit()

            # Dispatch alert for blocking
            dispatch_alert(
                db, f"IP BLOCKED - Score {threat_score:.0f}",
                client_ip, fp_id, threat_score, attack_type, path, session_id
            )
            db.commit()

            return Response(
                content="Forbidden: Suspicious activity detected.",
                status_code=status.HTTP_403_FORBIDDEN
            )

        # 13. Dispatch alert if threshold exceeded or honeytoken triggered
        if threat_score > settings.ALERT_THRESHOLD or honeytoken_triggered:
            reason = "HONEYTOKEN TRIGGERED" if honeytoken_triggered else f"High threat score: {threat_score:.0f}"
            dispatch_alert(
                db, reason, client_ip, fp_id, threat_score, attack_type, path, session_id
            )

        db.commit()

    except Exception as e:
        print(f"[MIDDLEWARE ERROR] {e}")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()

    # Re-inject request body for downstream handlers
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive

    response = await call_next(request)
    return response


# ──────────────────────────────────────────────
# FAKE HONEYPOT ENDPOINTS
# ──────────────────────────────────────────────

@app.get("/admin-login")
@app.post("/admin-login")
async def fake_admin_login(request: Request):
    """Fake admin login page with embedded honeytokens."""
    db = SessionLocal()
    tokens = {}
    try:
        # Generate honeytokens for this visitor
        client_ip = request.client.host
        fp_id = generate_fingerprint_id(client_ip, request.headers.get("user-agent", ""), dict(request.headers))
        tokens = create_token_set(db, fingerprint_id=fp_id)
        db.commit()
    except Exception as e:
        print(f"Error generating tokens: {e}")
    finally:
        db.close()

    html = f"""
    <html>
    <head><title>Admin Panel Login</title></head>
    <body style="font-family: sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; background:#1a1a2e; color:#eee;">
        <div style="border: 1px solid #333; padding: 2rem; border-radius: 8px; background:#16213e; min-width:320px;">
            <h2 style="color:#0f3460;">Admin Login</h2>
            <form method="POST" action="/admin-login">
                <input type="text" name="username" placeholder="Username" required style="width:100%;padding:8px;margin:4px 0;background:#0f3460;color:#eee;border:1px solid #333;border-radius:4px;"><br>
                <input type="password" name="password" placeholder="Password" required style="width:100%;padding:8px;margin:4px 0;background:#0f3460;color:#eee;border:1px solid #333;border-radius:4px;"><br>

                <!-- HONEYPOT TRAP FIELDS (invisible to humans) -->
                <input type="text" name="debug_token" value="" style="display:none;" />
                <input type="hidden" name="api_key" value="{tokens.get('api_key', '')}" />
                <input type="hidden" name="session_token" value="{tokens.get('session_cookie', '')}" />

                <input type="submit" value="Login" style="width:100%;padding:10px;margin-top:8px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:bold;">
            </form>
            <!-- Hidden comment with fake credentials for attacker to find -->
            <!-- DEBUG: API_KEY={tokens.get('api_key', '')} -->
            <!-- TODO: Remove before production - JWT={tokens.get('jwt', '')} -->
            <!-- AWS_ACCESS_KEY={tokens.get('aws_key', '')} -->
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/wp-admin")
@app.get("/wp-login.php")
@app.post("/wp-login.php")
async def fake_wp():
    return JSONResponse(
        {"error": "Database error establishing connection"},
        status_code=500
    )


@app.get("/phpmyadmin")
@app.get("/.env")
@app.get("/config.json")
@app.get("/config.yml")
@app.get("/backup.zip")
@app.get("/.git/config")
@app.get("/.htpasswd")
@app.get("/server-status")
@app.get("/actuator/health")
async def fake_sensitives():
    return Response(content="Forbidden", status_code=status.HTTP_403_FORBIDDEN)


@app.post("/api/upload")
async def fake_upload():
    return JSONResponse({"status": "success", "file_url": "/uploads/1"})


@app.post("/api/fingerprint")
async def receive_browser_fingerprint(request: Request):
    """Receive browser-side fingerprint data from fingerprint.js."""
    try:
        data = await request.json()
        client_ip = request.client.host
        ua = request.headers.get("user-agent", "")

        db = SessionLocal()
        try:
            fp_id = generate_fingerprint_id(client_ip, ua, dict(request.headers))
            fp = db.query(AttackerFingerprint).filter(
                AttackerFingerprint.id == fp_id
            ).first()
            if fp:
                fp.browser_fingerprint = json.dumps(data)
                db.commit()
        finally:
            db.close()

        return JSONResponse({"status": "ok"})
    except Exception:
        return JSONResponse({"status": "ok"})  # Never reveal errors


# ──────────────────────────────────────────────
# ADMIN DASHBOARD API ENDPOINTS
# ──────────────────────────────────────────────

@app.get("/api/admin/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get overview statistics for dashboard."""
    total_attacks = db.query(func.count(HoneypotLog.id)).scalar()
    blocked_count = db.query(func.count(BlockedIP.id)).scalar()
    active_sessions = db.query(func.count(AttackerSession.id)).filter(
        AttackerSession.is_active == True
    ).scalar()
    unique_fingerprints = db.query(func.count(AttackerFingerprint.id)).scalar()
    honeytokens_triggered = db.query(func.count(Honeytoken.id)).filter(
        Honeytoken.triggered == True
    ).scalar()

    top_ips = db.query(
        HoneypotLog.ip_address,
        func.count(HoneypotLog.id).label("count")
    ).group_by(HoneypotLog.ip_address).order_by(desc("count")).limit(5).all()

    top_paths = db.query(
        HoneypotLog.path,
        func.count(HoneypotLog.id).label("count")
    ).group_by(HoneypotLog.path).order_by(desc("count")).limit(5).all()

    avg_score = db.query(func.avg(HoneypotLog.threat_score)).scalar() or 0.0

    # Attack type distribution
    attack_dist = db.query(
        HoneypotLog.attack_type,
        func.count(HoneypotLog.id).label("count")
    ).filter(
        HoneypotLog.attack_type != None
    ).group_by(HoneypotLog.attack_type).order_by(desc("count")).all()

    return {
        "total_attacks": total_attacks,
        "blocked_count": blocked_count,
        "active_sessions": active_sessions,
        "unique_fingerprints": unique_fingerprints,
        "honeytokens_triggered": honeytokens_triggered,
        "average_threat_score": float(avg_score),
        "top_ips": [{"ip": item[0], "count": item[1]} for item in top_ips],
        "top_paths": [{"path": item[0], "count": item[1]} for item in top_paths],
        "attack_distribution": [
            {"type": item[0], "count": item[1]} for item in attack_dist
        ],
    }


@app.get("/api/admin/logs")
def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Get recent honeypot logs."""
    logs = db.query(HoneypotLog).order_by(desc(HoneypotLog.timestamp)).limit(limit).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "method": log.method,
            "path": log.path,
            "payload": log.payload[:200] if log.payload else None,
            "threat_score": log.threat_score,
            "anomaly_flag": log.anomaly_flag,
            "fingerprint_id": log.fingerprint_id,
            "session_id": log.session_id,
            "attack_type": log.attack_type,
            "attack_confidence": log.attack_confidence,
            "detected_patterns": json.loads(log.detected_patterns) if log.detected_patterns else [],
        }
        for log in logs
    ]


@app.get("/api/admin/blocked")
def get_blocked(db: Session = Depends(get_db)):
    """Get all blocked IPs."""
    blocked = db.query(BlockedIP).order_by(desc(BlockedIP.blocked_at)).all()
    return [
        {
            "id": b.id,
            "ip_address": b.ip_address,
            "reason": b.reason,
            "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None
        }
        for b in blocked
    ]


@app.post("/api/admin/block")
async def manual_block(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if not ip:
        return {"error": "IP required"}
    success = block_manager.block_ip(ip, "Manual block from dashboard", auto=False)
    return {"success": success}


@app.post("/api/admin/unblock")
async def manual_unblock(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if not ip:
        return {"error": "IP required"}
    success = block_manager.unblock_ip(ip)
    return {"success": success}


# ── Sessions ──

@app.get("/api/admin/sessions")
def list_sessions(limit: int = 100, db: Session = Depends(get_db)):
    """List all attacker sessions."""
    return get_all_sessions(db, limit)


@app.get("/api/admin/sessions/active")
def list_active_sessions(db: Session = Depends(get_db)):
    """List currently active sessions."""
    return get_active_sessions(db)


@app.get("/api/admin/sessions/{session_id}/timeline")
def session_timeline(session_id: str, db: Session = Depends(get_db)):
    """Get session replay timeline."""
    return get_session_timeline(db, session_id)


# ── Fingerprints ──

@app.get("/api/admin/fingerprints")
def list_fingerprints(limit: int = 50, db: Session = Depends(get_db)):
    """List attacker fingerprints."""
    fps = db.query(AttackerFingerprint).order_by(
        desc(AttackerFingerprint.last_seen)
    ).limit(limit).all()
    return [
        {
            "id": fp.id,
            "ip_address": fp.ip_address,
            "user_agent": fp.user_agent[:100] if fp.user_agent else None,
            "header_hash": fp.header_hash,
            "confidence_score": fp.confidence_score,
            "threat_level": fp.threat_level,
            "total_requests": fp.total_requests,
            "first_seen": fp.first_seen.isoformat() if fp.first_seen else None,
            "last_seen": fp.last_seen.isoformat() if fp.last_seen else None,
        }
        for fp in fps
    ]


# ── MITRE ATT&CK ──

@app.get("/api/admin/mitre")
def mitre_summary(db: Session = Depends(get_db)):
    """Get global MITRE ATT&CK summary."""
    return get_global_mitre_summary(db)


@app.get("/api/admin/mitre/{session_id}")
def mitre_session(session_id: str, db: Session = Depends(get_db)):
    """Get MITRE ATT&CK mapping for a specific session."""
    return get_session_mitre_summary(db, session_id)


# ── Honeytokens ──

@app.get("/api/admin/honeytokens")
def list_honeytokens(db: Session = Depends(get_db)):
    """List all honeytokens."""
    return get_all_honeytokens(db)


# ── Attack Classification ──

@app.get("/api/admin/attack-types")
def attack_type_stats(db: Session = Depends(get_db)):
    """Get attack type distribution statistics."""
    results = db.query(
        HoneypotLog.attack_type,
        func.count(HoneypotLog.id).label("count"),
        func.avg(HoneypotLog.attack_confidence).label("avg_confidence")
    ).filter(
        HoneypotLog.attack_type != None
    ).group_by(HoneypotLog.attack_type).order_by(desc("count")).all()

    return [
        {
            "attack_type": r.attack_type,
            "count": r.count,
            "avg_confidence": round(float(r.avg_confidence), 3) if r.avg_confidence else 0.0
        }
        for r in results
    ]


# ── Export ──

@app.get("/api/admin/export/{fmt}")
def export_intelligence(fmt: str, days: int = 7, db: Session = Depends(get_db)):
    """Export threat intelligence in JSON, CSV, or STIX 2.1 format."""
    if fmt == "json":
        content = export_json(db, days)
        return Response(content=content, media_type="application/json",
                       headers={"Content-Disposition": "attachment; filename=threat_intel.json"})
    elif fmt == "csv":
        content = export_csv(db, days)
        return Response(content=content, media_type="text/csv",
                       headers={"Content-Disposition": "attachment; filename=threat_intel.csv"})
    elif fmt == "stix":
        content = export_stix21(db, days)
        return Response(content=content, media_type="application/json",
                       headers={"Content-Disposition": "attachment; filename=threat_intel_stix.json"})
    else:
        return JSONResponse({"error": f"Unknown format: {fmt}. Use json, csv, or stix."}, status_code=400)


# ── Incident Reports ──

@app.get("/api/admin/incident/{session_id}")
def get_incident_report(session_id: str, db: Session = Depends(get_db)):
    """Generate an incident report for a session."""
    report = generate_incident_report(db, session_id)
    return PlainTextResponse(content=report, media_type="text/markdown")


# ── Alerts ──

@app.get("/api/admin/alerts")
def list_alerts(limit: int = 50, db: Session = Depends(get_db)):
    """List recent alert history."""
    alerts = db.query(AlertLog).order_by(desc(AlertLog.sent_at)).limit(limit).all()
    return [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "trigger_reason": a.trigger_reason,
            "fingerprint_id": a.fingerprint_id,
            "session_id": a.session_id,
            "sent_at": a.sent_at.isoformat() if a.sent_at else None,
            "success": a.success,
        }
        for a in alerts
    ]


# ── Model Training ──

@app.post("/api/admin/retrain")
def retrain_anomaly_model():
    """Retrain the anomaly detection model."""
    from .ml.train import train_isolation_forest
    success = train_isolation_forest()
    return {"success": success, "message": "Anomaly model retrained!" if success else "Failed or not enough data."}


@app.post("/api/admin/retrain-classifier")
def retrain_classifier():
    """Retrain the attack classification model."""
    try:
        from .ml.classifier_train import train_attack_classifier
        success = train_attack_classifier()
        if success:
            attack_classifier.reload_model()
        return {"success": success, "message": "Classifier retrained!" if success else "Training failed."}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ──────────────────────────────────────────────
# STATIC FILES & CATCH-ALL
# ──────────────────────────────────────────────

os.makedirs("app/static", exist_ok=True)
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="static")


@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request, path_name: str):
    """Catch-all route for any unmatched paths — part of the honeypot trap."""
    if "api/admin" in path_name or "dashboard" in path_name:
        return Response(status_code=404)
    if "api/" in path_name:
        return JSONResponse({"error": "Unauthorized endpoint access"}, status_code=401)
    return HTMLResponse(
        content="<h1>Not Found</h1><p>The requested URL was not found on this server.</p>",
        status_code=404
    )
