import json
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List

from .database import engine, Base, SessionLocal, get_db
from .models import HoneypotLog, BlockedIP
from .ml.anomaly_detector import anomaly_detector
from .blocking import block_manager
from .ml.train import train_isolation_forest
import os

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Defensive Web Honeypot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event
@app.on_event("startup")
def on_startup():
    block_manager.load_blocked_ips()
    # Try initial training if we have some data but no model
    if anomaly_detector.model is None:
        train_isolation_forest()

# Middleware for ALL requests (The Core Honeypot Trap)
@app.middleware("http")
async def honeypot_middleware(request: Request, call_next):
    # 1. IP Check
    client_ip = request.client.host
    if request.headers.get("X-Forwarded-For"):
        client_ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()

    if block_manager.is_blocked(client_ip):
        return Response(content="Forbidden: Your IP has been blocked due to malicious activity.", status_code=status.HTTP_403_FORBIDDEN)

    # Allow dashboard requests to bypass logging if they are legitimate admin IPs (local)
    if client_ip in block_manager.whitelist and request.url.path.startswith(("/dashboard", "/api/admin")):
        return await call_next(request)

    # 2. Extract Data
    method = request.method
    path = request.url.path
    headers_dict = dict(request.headers)
    headers_json = json.dumps(headers_dict)
    user_agent = headers_dict.get("user-agent", "")
    
    # Read payload safely
    body_bytes = await request.body()
    payload = body_bytes.decode('utf-8', errors='ignore')
    
    # 3. Analyze Request
    threat_score, features = anomaly_detector.predict(path, method, headers_json, payload)
    
    is_anomaly = threat_score > 60
    
    # 4. Save to Database
    db = SessionLocal()
    try:
        log_entry = HoneypotLog(
            ip_address=client_ip,
            user_agent=user_agent,
            method=method,
            path=path,
            headers=headers_json,
            payload=payload[:2000], # Sanitize/truncate very large payloads
            threat_score=threat_score,
            anomaly_flag=is_anomaly,
            is_blocked=False
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        print(f"Error saving log: {e}")
    finally:
        db.close()

    # 5. Check if we need to block dynamically (score > 85)
    if threat_score > 85:
        block_manager.block_ip(client_ip, f"High threat score: {threat_score}. Targeted {path}")
        return Response(content="Forbidden: Suspicious activity detected.", status_code=status.HTTP_403_FORBIDDEN)

    # Re-inject the body for downstream consumers since we read it
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive

    # Process request
    response = await call_next(request)
    return response


# ==============================================================
# FAKE HONEYPOT ENDPOINTS
# ==============================================================

@app.get("/admin-login")
@app.post("/admin-login")
async def fake_admin_login(request: Request):
    # Fake admin login form with hidden honeypot fields
    html = """
    <html>
    <head><title>Admin Panel Login</title></head>
    <body style="font-family: sans-serif; display:flex; justify-content:center; align-items:center; height:100vh;">
        <div style="border: 1px solid #ccc; padding: 2rem; border-radius: 8px;">
            <h2>Admin Login</h2>
            <form method="POST" action="/admin-login">
                <input type="text" name="username" placeholder="Username" required><br><br>
                <input type="password" name="password" placeholder="Password" required><br><br>
                
                <!-- HONEYPOT FIELD INVISIBLE TO HUMANS -->
                <input type="text" name="debug_token" value="" style="display:none;" />
                
                <input type="submit" value="Login">
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/wp-admin")
@app.get("/wp-login.php")
@app.post("/wp-login.php")
async def fake_wp():
    return JSONResponse({"error": "Database error establishing connection"}, status_code=500)

@app.get("/phpmyadmin")
@app.get("/.env")
@app.get("/config.json")
@app.get("/backup.zip")
async def fake_sensitives():
    return Response(content="Forbidden", status_code=status.HTTP_403_FORBIDDEN)

@app.post("/api/upload")
async def fake_upload():
    return JSONResponse({"status": "success", "file_url": "/uploads/1"})

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request, path_name: str):
    # This catches anything else scanners are looking for
    if "api/" in path_name:
        return JSONResponse({"error": "Unauthorized endpoint access"}, status_code=401)
    return HTMLResponse(content="<h1>Not Found</h1><p>The requested URL was not found on this server.</p>", status_code=404)


# ==============================================================
# ADMIN DASHBOARD API ENDPOINTS
# ==============================================================

@app.get("/api/admin/stats")
def get_stats(db: Session = Depends(get_db)):
    total_attacks = db.query(func.count(HoneypotLog.id)).scalar()
    blocked_count = db.query(func.count(BlockedIP.id)).scalar()
    
    # Needs to be careful with sqlite vs postgres for GroupBy
    top_ips = db.query(HoneypotLog.ip_address, func.count(HoneypotLog.id).label('count')) \
                .group_by(HoneypotLog.ip_address).order_by(desc('count')).limit(5).all()
                
    top_paths = db.query(HoneypotLog.path, func.count(HoneypotLog.id).label('count')) \
                 .group_by(HoneypotLog.path).order_by(desc('count')).limit(5).all()
                 
    avg_score = db.query(func.avg(HoneypotLog.threat_score)).scalar() or 0.0

    return {
        "total_attacks": total_attacks,
        "blocked_count": blocked_count,
        "average_threat_score": float(avg_score),
        "top_ips": [{"ip": item[0], "count": item[1]} for item in top_ips],
        "top_paths": [{"path": item[0], "count": item[1]} for item in top_paths],
    }

@app.get("/api/admin/logs")
def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(HoneypotLog).order_by(desc(HoneypotLog.timestamp)).limit(limit).all()
    return logs

@app.get("/api/admin/blocked")
def get_blocked(db: Session = Depends(get_db)):
    return db.query(BlockedIP).order_by(desc(BlockedIP.blocked_at)).all()

@app.post("/api/admin/block")
async def manual_block(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if not ip: return {"error": "IP required"}
    success = block_manager.block_ip(ip, "Manual block from dashboard")
    return {"success": success}

@app.post("/api/admin/unblock")
async def manual_unblock(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if not ip: return {"error": "IP required"}
    success = block_manager.unblock_ip(ip)
    return {"success": success}

@app.post("/api/admin/retrain")
def retrain_model():
    success = train_isolation_forest()
    return {"success": success, "message": "Model retrained!" if success else "Not enough data or error."}


# Mount Static Files for Dashboard
import os
os.makedirs("app/static", exist_ok=True)
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="static")

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request, path_name: str):
    # This catches anything else scanners are looking for
    if "api/admin" in path_name or "dashboard" in path_name:
        return Response(status_code=404) # Let FastAPI handle its own 404s for proper routes
    if "api/" in path_name:
        return JSONResponse({"error": "Unauthorized endpoint access"}, status_code=401)
    return HTMLResponse(content="<h1>Not Found</h1><p>The requested URL was not found on this server.</p>", status_code=404)

