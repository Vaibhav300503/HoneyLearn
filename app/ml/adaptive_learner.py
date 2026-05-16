"""
HoneyLearn — Adaptive Learning Engine
========================================
The brain of HoneyLearn. This module:
1. Ingests every classified request as a real-world training sample
2. Buffers samples until a retrain threshold is reached
3. Triggers incremental retraining (synthetic + real data)
4. Tracks model accuracy evolution over time
5. Logs learning milestones for the dashboard

The goal: the more attacks HoneyLearn receives, the smarter it gets.
"""
import os
import json
import time
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, func


class AdaptiveLearner:
    """
    Real-time adaptive learning engine for HoneyLearn.
    Buffers classified attack samples and periodically retrains the ML
    classifier with a mix of synthetic + real-world attack data.
    """

    def __init__(self):
        self.sample_buffer: List[Dict[str, Any]] = []
        self.total_samples_ingested: int = 0
        self.total_retrains: int = 0
        self.is_training: bool = False
        self.last_retrain_time: Optional[datetime] = None
        self.current_model_version: int = 0
        self._lock = threading.Lock()

        # Track unique patterns seen (for "new pattern discovered" events)
        self._seen_patterns: set = set()
        self._novel_patterns: List[Dict[str, Any]] = []

        # In-memory learning events (last 100)
        self._learning_events: List[Dict[str, Any]] = []

        # Model accuracy history
        self._accuracy_history: List[Dict[str, Any]] = []

        print("[HONEYLEARN] Adaptive Learning Engine initialized.")

    def ingest_sample(
        self,
        path: str,
        method: str,
        payload: str,
        user_agent: str,
        attack_type: str,
        confidence: float,
        threat_score: float,
        detected_patterns: List[str],
        ip_address: str,
    ):
        """
        Called after every classified request to feed the learning pipeline.
        Only ingests samples where the classifier had reasonable confidence.
        """
        # Skip benign with low confidence (noise)
        if attack_type == "benign" and confidence < 0.7:
            return

        # Skip very low confidence classifications (unreliable labels)
        if attack_type != "benign" and confidence < 0.4:
            return

        with self._lock:
            sample = {
                "path": path,
                "method": method,
                "payload": (payload or "")[:1000],
                "user_agent": (user_agent or "")[:200],
                "attack_type": attack_type,
                "confidence": confidence,
                "threat_score": threat_score,
                "detected_patterns": detected_patterns,
                "ip_address": ip_address,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }
            self.sample_buffer.append(sample)
            self.total_samples_ingested += 1

            # Check for novel patterns
            for pattern in detected_patterns:
                if pattern not in self._seen_patterns:
                    self._seen_patterns.add(pattern)
                    novel = {
                        "pattern": pattern,
                        "attack_type": attack_type,
                        "discovered_at": datetime.now(timezone.utc).isoformat(),
                        "source_ip": ip_address,
                    }
                    self._novel_patterns.append(novel)
                    self._add_learning_event(
                        "new_pattern",
                        f"New attack pattern discovered: '{pattern}' in {attack_type} attack from {ip_address}",
                        {"pattern": pattern, "attack_type": attack_type},
                    )

    def check_retrain(self, retrain_threshold: int = 50) -> bool:
        """
        Check if we should trigger a retrain based on buffer size.
        Returns True if retraining was triggered.
        """
        if self.is_training:
            return False

        if len(self.sample_buffer) >= retrain_threshold:
            # Trigger async retraining
            thread = threading.Thread(target=self._do_retrain, daemon=True)
            thread.start()
            return True

        return False

    def _do_retrain(self):
        """Execute the incremental retraining in a background thread."""
        with self._lock:
            if self.is_training:
                return
            self.is_training = True
            samples_to_train = list(self.sample_buffer)
            self.sample_buffer.clear()

        try:
            self._add_learning_event(
                "retrain_started",
                f"Incremental retraining started with {len(samples_to_train)} new real-world samples.",
                {"sample_count": len(samples_to_train)},
            )

            print(f"[HONEYLEARN] Retraining with {len(samples_to_train)} real samples...")

            from .classifier_train import train_hybrid
            result = train_hybrid(samples_to_train)

            if result and result.get("success"):
                self.total_retrains += 1
                self.current_model_version += 1
                self.last_retrain_time = datetime.now(timezone.utc)

                accuracy = result.get("accuracy", 0.0)
                self._accuracy_history.append({
                    "version": self.current_model_version,
                    "accuracy": accuracy,
                    "real_samples": len(samples_to_train),
                    "total_samples": result.get("total_samples", 0),
                    "trained_at": self.last_retrain_time.isoformat(),
                })

                self._add_learning_event(
                    "retrain_complete",
                    f"Model v{self.current_model_version} trained! "
                    f"Accuracy: {accuracy:.1%} | "
                    f"Real samples: {len(samples_to_train)} | "
                    f"Total training set: {result.get('total_samples', 0)}",
                    {
                        "version": self.current_model_version,
                        "accuracy": accuracy,
                        "real_samples": len(samples_to_train),
                    },
                )

                # Reload the classifier model
                try:
                    from .attack_classifier import attack_classifier
                    attack_classifier.reload_model()
                    print(f"[HONEYLEARN] Model v{self.current_model_version} loaded successfully. Accuracy: {accuracy:.3f}")
                except Exception as e:
                    print(f"[HONEYLEARN] Model reload error: {e}")
            else:
                self._add_learning_event(
                    "retrain_failed",
                    f"Retraining failed: {result.get('error', 'Unknown error')}",
                    {"error": result.get("error", "Unknown")},
                )

        except Exception as e:
            print(f"[HONEYLEARN] Retraining error: {e}")
            self._add_learning_event(
                "retrain_error",
                f"Retraining encountered an error: {str(e)}",
                {"error": str(e)},
            )
        finally:
            self.is_training = False

    def _add_learning_event(self, event_type: str, description: str, metadata: dict = None):
        """Add a learning event to the in-memory log."""
        event = {
            "id": len(self._learning_events) + 1,
            "type": event_type,
            "description": description,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._learning_events.append(event)
        # Keep only last 200 events in memory
        if len(self._learning_events) > 200:
            self._learning_events = self._learning_events[-200:]

        print(f"[HONEYLEARN] [{event_type.upper()}] {description}")

    def _persist_to_db(self, db: Session, samples: List[Dict]):
        """Persist attack samples to the database for long-term storage."""
        try:
            from ..models import AttackSample
            for sample in samples:
                db_sample = AttackSample(
                    path=sample["path"],
                    method=sample["method"],
                    payload=sample["payload"],
                    user_agent=sample["user_agent"],
                    attack_type=sample["attack_type"],
                    confidence=sample["confidence"],
                    threat_score=sample["threat_score"],
                    detected_patterns=json.dumps(sample.get("detected_patterns", [])),
                    source_ip=sample["ip_address"],
                )
                db.add(db_sample)
            db.commit()
        except Exception as e:
            print(f"[HONEYLEARN] DB persist error: {e}")
            try:
                db.rollback()
            except Exception:
                pass

    # ─────────────────────────────────────────────
    # Dashboard API Data
    # ─────────────────────────────────────────────

    def get_learning_stats(self) -> Dict[str, Any]:
        """Return overall learning statistics for the dashboard."""
        return {
            "total_samples_ingested": self.total_samples_ingested,
            "buffer_size": len(self.sample_buffer),
            "total_retrains": self.total_retrains,
            "current_model_version": self.current_model_version,
            "is_training": self.is_training,
            "last_retrain_time": self.last_retrain_time.isoformat() if self.last_retrain_time else None,
            "novel_patterns_count": len(self._novel_patterns),
            "accuracy_history": self._accuracy_history[-20:],  # Last 20 versions
            "learning_active": True,
        }

    def get_learning_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent learning events for the dashboard feed."""
        return list(reversed(self._learning_events[-limit:]))

    def get_model_history(self) -> List[Dict[str, Any]]:
        """Return model version history with accuracy progression."""
        return list(self._accuracy_history)

    def get_novel_patterns(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Return recently discovered novel attack patterns."""
        return list(reversed(self._novel_patterns[-limit:]))

    def get_buffer_breakdown(self) -> Dict[str, int]:
        """Return breakdown of buffered samples by attack type."""
        breakdown = {}
        for sample in self.sample_buffer:
            at = sample.get("attack_type", "unknown")
            breakdown[at] = breakdown.get(at, 0) + 1
        return breakdown


# Singleton
adaptive_learner = AdaptiveLearner()
