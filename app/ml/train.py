import os
import joblib
import pandas as pd
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from .anomaly_detector import AnomalyDetector, MODEL_PATH
from ..models import HoneypotLog
from ..database import SessionLocal

def train_isolation_forest():
    print("Starting AI training...")
    db: Session = SessionLocal()
    
    try:
        # Fetch logs
        logs = db.query(HoneypotLog).limit(10000).all()
        if not logs:
            print("No data available to train the model.")
            return False

        detector = AnomalyDetector()
        features_list = []
        
        for log in logs:
            feats = detector.extract_features(log.path, log.method, log.headers, log.payload)
            features_list.append(feats)

        # If we have very little data, randomly bootstrap normal background noise 
        # (simulating regular users) to help Isolation Forest distinguish
        # An Isolation Forest needs a mostly "normal" dataset to find anomalies.
        if len(features_list) < 100:
            for _ in range(100 - len(features_list)):
                features_list.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0]) # Perfect normal request

        # Add some extreme anomalies manually to ensure the model knows what they look like
        # High SQLi, High XSS, Bad UA, etc.
        features_list.append([1.0, 5.0, 0.0, 200.0, 1.0, 1.0])
        features_list.append([1.0, 0.0, 3.0, 150.0, 0.0, 1.0])

        df = pd.DataFrame(features_list)
        
        # Train Isolation Forest
        # contamination represents the expected proportion of outliers
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(df)

        # Save model
        joblib.dump(model, MODEL_PATH)
        print(f"Model trained successfully on {len(features_list)} samples and saved to {MODEL_PATH}")
        
        # Reload the instance dynamically
        import app.ml.anomaly_detector as ad
        ad.anomaly_detector.model = model
        
        return True

    except Exception as e:
        print(f"Error during training: {e}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    train_isolation_forest()
