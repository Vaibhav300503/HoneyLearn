import os
import re
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'isolation_forest.joblib')

class AnomalyDetector:
    def __init__(self):
        self.model = None
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"Failed to load model: {e}")

    def extract_features(self, path: str, method: str, headers: str, payload: str):
        """
        Extract numerical features from request for the AI model.
        Returns a list of floats.
        """
        payload = str(payload or "").lower()
        path = str(path or "").lower()
        headers = str(headers or "").lower()

        # 1. Suspicious Paths
        bad_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/config', '/.env', '/backup']
        is_bad_path = any(bp in path for bp in bad_paths)

        # 2. SQL Injection Signatures
        sqli_patterns = [r"select\s+.*\s+from", r"union\s+select", r"insert\s+into", r"'\s*or\s*1\s*=\s*1", r"--\s*$"]
        sqli_count = sum(1 for p in sqli_patterns if re.search(p, payload) or re.search(p, path))

        # 3. XSS / LFI signatures
        xss_lfi_patterns = [r"<script>", r"javascript:", r"onerror=", r"\.\./\.\./", r"etc/passwd"]
        xss_lfi_count = sum(1 for p in xss_lfi_patterns if re.search(p, payload) or re.search(p, path))

        # 4. Payload Length
        payload_length = len(payload)

        # 5. Method Anomaly (POST/PUT on weird endpoints)
        is_suspicious_method = 1 if method in ['OPTIONS', 'PUT', 'DELETE', 'TRACE'] else 0
        
        # 6. Auto tools user agents (curl, nmap, nikto, sqlmap)
        bad_uas = ['nmap', 'sqlmap', 'nikto', 'curl', 'python-requests', 'wget']
        has_bad_ua = any(ua in headers for ua in bad_uas)

        return [
            float(is_bad_path),
            float(sqli_count),
            float(xss_lfi_count),
            float(payload_length),
            float(is_suspicious_method),
            float(has_bad_ua)
        ]

    def rule_based_score(self, features):
        """
        Fallback rule-based scoring (0-100) if AI model is not trained yet.
        """
        score = 0
        score += features[0] * 30 # is_bad_path
        score += features[1] * 50 # sqli_count
        score += features[2] * 50 # xss_lfi_count
        score += min(features[3] / 1000.0, 10) # payload length anomaly (small contribution)
        score += features[4] * 20 # suspicious method
        score += features[5] * 40 # bad user agent
        
        return min(max(score, 0), 100)

    def predict(self, path_val, method_val, headers_val, payload_val):
        """
        Calculates threat score (0-100).
        """
        features = self.extract_features(path_val, method_val, headers_val, payload_val)

        # Fallback to rule-based if AI isn't trained
        if self.model is None:
            return self.rule_based_score(features), features

        try:
            # IsolationForest predict returns 1 (normal) or -1 (anomaly)
            # decision_function gives distance. Lower is more anomalous.
            X = np.array([features])
            decision_score = self.model.decision_function(X)[0]
            
            # Map decision score to 0-100 (Simplified mapping)
            # Typically decision scores are near 0. -0.5 is very anomalous, 0.1 is normal.
            # Convert decision_score to threat: lower decision score -> higher threat
            threat_prob = 1.0 / (1.0 + np.exp(decision_score * 10)) # Sigmoid mapping
            ai_score = int(threat_prob * 100)

            # Boost with rule based to be safe
            rule_score = self.rule_based_score(features)
            final_score = max(ai_score, rule_score)

            return min(final_score, 100), features

        except Exception as e:
            print(f"Prediction error: {e}")
            return self.rule_based_score(features), features

anomaly_detector = AnomalyDetector()
