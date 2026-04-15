"""
Attack Classifier — TF-IDF + LinearSVC pipeline that classifies requests 
into attack categories with confidence scores and pattern explanations.
Falls back to regex-based rules when model confidence is low.
"""
import os
import json
import joblib
from typing import Dict, Any, Optional

from .feature_extractor import (
    extract_all_patterns, is_bad_path, BOT_SCANNER_UAS
)

MODEL_DIR = os.path.dirname(__file__)
CLASSIFIER_PATH = os.path.join(MODEL_DIR, "attack_classifier.joblib")

# Attack categories
ATTACK_TYPES = [
    "sql_injection",
    "xss",
    "brute_force",
    "directory_traversal",
    "rce_attempt",
    "bot_scanner",
    "credential_stuffing",
    "benign",
]

# Brute-force detection: paths associated with login attempts
BRUTE_FORCE_PATHS = [
    "/admin-login", "/wp-login", "/login", "/signin", "/auth",
    "/api/login", "/api/auth", "/user/login", "/account/login",
]

CREDENTIAL_STUFFING_PATHS = BRUTE_FORCE_PATHS  # Same endpoints, differentiated by volume


class AttackClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self._load_model()

    def _load_model(self):
        """Load trained classifier if available."""
        if os.path.exists(CLASSIFIER_PATH):
            try:
                data = joblib.load(CLASSIFIER_PATH)
                self.model = data["model"]
                self.vectorizer = data["vectorizer"]
                print(f"[CLASSIFIER] Loaded attack classifier from {CLASSIFIER_PATH}")
            except Exception as e:
                print(f"[CLASSIFIER] Failed to load model: {e}")

    def _build_text_feature(self, path: str, method: str, payload: str, user_agent: str) -> str:
        """Combine request components into a single text string for TF-IDF."""
        parts = [
            f"PATH:{path}",
            f"METHOD:{method}",
            f"UA:{user_agent[:200]}",
            f"PAYLOAD:{payload[:1000]}",
        ]
        return " ".join(parts)

    def _rule_based_classify(
        self, path: str, method: str, payload: str, user_agent: str
    ) -> Dict[str, Any]:
        """
        Fallback regex-based classification when model is unavailable or low confidence.
        """
        patterns = extract_all_patterns(path, payload, user_agent)
        detected = []

        # Priority order: most specific first
        if patterns["rce"]:
            return {
                "attack_type": "rce_attempt",
                "confidence": 0.85,
                "detected_patterns": patterns["rce"]
            }

        if patterns["sqli"]:
            return {
                "attack_type": "sql_injection",
                "confidence": 0.80,
                "detected_patterns": patterns["sqli"]
            }

        if patterns["xss"]:
            return {
                "attack_type": "xss",
                "confidence": 0.80,
                "detected_patterns": patterns["xss"]
            }

        if patterns["directory_traversal"]:
            return {
                "attack_type": "directory_traversal",
                "confidence": 0.80,
                "detected_patterns": patterns["directory_traversal"]
            }

        if patterns["bot_scanner"]:
            return {
                "attack_type": "bot_scanner",
                "confidence": 0.75,
                "detected_patterns": patterns["bot_scanner"]
            }

        # Brute force: POST to login endpoints
        if method == "POST" and any(bp in path.lower() for bp in BRUTE_FORCE_PATHS):
            return {
                "attack_type": "brute_force",
                "confidence": 0.60,
                "detected_patterns": ["POST to login endpoint"]
            }

        # Bad path probe
        if is_bad_path(path):
            return {
                "attack_type": "bot_scanner",
                "confidence": 0.55,
                "detected_patterns": ["Known honeypot path probe"]
            }

        return {
            "attack_type": "benign",
            "confidence": 0.5,
            "detected_patterns": []
        }

    def classify(
        self, path: str, method: str, payload: str, user_agent: str
    ) -> Dict[str, Any]:
        """
        Classify a request into an attack category.
        Returns: { attack_type, confidence, detected_patterns }
        """
        # Always run rule-based as fallback / explanation source
        rule_result = self._rule_based_classify(path, method, payload, user_agent)

        # Try ML model if available
        if self.model and self.vectorizer:
            try:
                text = self._build_text_feature(path, method, payload, user_agent)
                X = self.vectorizer.transform([text])

                # Get predicted class and probability
                prediction = self.model.predict(X)[0]
                probas = self.model.predict_proba(X)[0]
                max_prob = float(max(probas))

                if max_prob >= 0.5:
                    # ML is confident — use its prediction but add rule-based patterns
                    patterns = extract_all_patterns(path, payload, user_agent)
                    all_detected = []
                    for cat_patterns in patterns.values():
                        all_detected.extend(cat_patterns)

                    return {
                        "attack_type": prediction,
                        "confidence": round(max_prob, 3),
                        "detected_patterns": all_detected if all_detected else rule_result["detected_patterns"]
                    }
            except Exception as e:
                print(f"[CLASSIFIER] ML prediction error: {e}")

        # Fallback to rule-based
        return rule_result

    def reload_model(self):
        """Reload model from disk (after retraining)."""
        self._load_model()


# Singleton
attack_classifier = AttackClassifier()
