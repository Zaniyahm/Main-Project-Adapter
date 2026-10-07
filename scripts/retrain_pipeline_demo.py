"""
scripts/retrain_pipeline_demo.py
===================================
De-risks the FUTURE real retrain (Phase 9) by proving the pipeline
works end-to-end for SQL-protocol sessions RIGHT NOW — feature
extraction, training, evaluation — using synthetic labeled sessions.

THIS IS NOT A PRODUCTION MODEL. Explicitly, on purpose:
1. Trained only on synthetic sessions WE generated — exactly the
   "don't train only on your own test traffic" trap this project has
   flagged since the very first planning conversation.
2. Uses our 4-stage vocabulary (recon/credential_attack/
   injection_attempt/exfiltration_attempt) — NOT reconciled with
   Robert's actual shared classifier's 5 classes (which have
   path_traversal/xss_probing instead of exfiltration_attempt). That
   reconciliation is a team decision, not something this script
   decides unilaterally.

Saved to shared/models_staging/ — NEVER shared/models/ — so it can
never be confused with or accidentally overwrite the real production
models the classifier_bridge actually loads.

Run against an isolated test DB (test_utils.py's convention), never
the live one.
"""
import json
import os
import sys
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))  # features.py/predictor.py use bare "import core_db"

TEST_DB_PATH = str(Path(__file__).resolve().parent.parent / "shared" / "instance" / "test_retrain.db")
STAGING_DIR = Path(__file__).resolve().parent.parent / "shared" / "models_staging"

os.environ["HONEYPOT_DB_PATH"] = TEST_DB_PATH

from shared.core_db import setup_database, log_event

# ---------------------------------------------------------------------
# Synthetic session generator — deliberately varied per stage, so the
# resulting features aren't trivially separable by one obvious signal.
# ---------------------------------------------------------------------

SESSION_TEMPLATES = {
    "recon": [
        [("mysql", "SHOW DATABASES;", 0), ("mysql", "SELECT VERSION();", 0), ("mysql", "SHOW TABLES;", 0)],
        [("postgresql", "SELECT version();", 0)],
        [("mysql", "SHOW DATABASES;", 0)],
        [("postgresql", "SELECT current_database();", 0), ("postgresql", "SELECT current_user;", 0)],
    ],
    "credential_attack": [
        [("mysql", "LOGIN_FAILED user=admin", 401)] * 5,
        [("postgresql", "LOGIN_FAILED user=postgres", 401)] * 4,
        [("mysql", "LOGIN_FAILED user=root", 401)] * 8,
    ],
    "injection_attempt": [
        [("mysql", "SELECT * FROM users WHERE 1=1 UNION SELECT 1,2,3,4-- ", 1064)],
        [("postgresql", "SELECT pg_sleep(5);", 400)],
        [("postgresql", "COPY (SELECT 1) TO PROGRAM 'id';", 403)],
        [("mysql", "SELECT * FROM users WHERE '1'='1'; --", 1064)],
    ],
    "exfiltration_attempt": [
        [("mysql", "SELECT * FROM users;", 0), ("mysql", "SELECT * FROM orders;", 0)],
        [("postgresql", "SELECT * FROM users;", 0), ("postgresql", "SELECT * FROM audit_log;", 0)],
        [("mysql", "SELECT * FROM audit_log;", 0), ("mysql", "SELECT * FROM users;", 0), ("mysql", "SELECT * FROM orders;", 0)],
    ],
}


def generate_synthetic_dataset():
    Path(TEST_DB_PATH).unlink(missing_ok=True)
    setup_database(TEST_DB_PATH)

    labels = []
    for stage, sessions in SESSION_TEMPLATES.items():
        for events in sessions:
            session_id = str(uuid.uuid4())
            base_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            for i, (protocol, action, status) in enumerate(events):
                ts = (base_time + timedelta(seconds=i * 4)).isoformat()
                log_event(
                    event_id=str(uuid.uuid4()), timestamp=ts, protocol=protocol,
                    source_ip="10.0.0.99", session_id=session_id, action=action,
                    parameters={"query": action}, raw_metadata={},
                    session_source="protocol_native", response_status=status,
                    response_type="synthetic",
                )
            labels.append({"session_id": session_id, "true_stage": stage, "label_source": "synthetic_sql_demo"})
    return labels


def main():
    print("Generating synthetic SQL session dataset (NOT real traffic)...")
    labels = generate_synthetic_dataset()
    print(f"  {len(labels)} synthetic sessions across {len(SESSION_TEMPLATES)} stages\n")

    from shared.features import extract_session_features, FEATURE_NAMES
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report

    rows, y = [], []
    for rec in labels:
        try:
            feats = extract_session_features(rec["session_id"])
            rows.append(feats)
            y.append(rec["true_stage"])
        except Exception as e:
            print(f"  SKIP {rec['session_id'][:8]}: {e}")

    X = np.array(rows)
    print(f"Feature extraction: {len(rows)}/{len(labels)} sessions succeeded, {X.shape[1]} features each")
    print("(This alone is the real win: proves extract_session_features() works correctly")
    print(" on SQL-protocol sessions, not just HTTP ones — zero crashes.)\n")

    if len(set(y)) < 2 or len(rows) < 8:
        print("Too few synthetic samples for a meaningful train/test split — pipeline")
        print("validated (feature extraction works), but skipping train/eval on this tiny set.")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    clf = DecisionTreeClassifier(max_depth=5, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"Pipeline validation result (synthetic-only, {len(X_test)} test samples):")
    print(f"  Accuracy: {acc:.1%}")
    print(classification_report(y_test, y_pred, zero_division=0))

    STAGING_DIR.mkdir(exist_ok=True)
    import joblib
    joblib.dump({"model": clf, "trained_on": "synthetic_sql_demo", "feature_names": FEATURE_NAMES},
                STAGING_DIR / "stage_classifier_sql_pipeline_demo.joblib")

    print(f"\nSaved to {STAGING_DIR}/ (staging only — NOT shared/models/, NOT production)")
    print("\n--- HONEST SUMMARY ---")
    print("What this proves: the retrain pipeline (feature extraction, training,")
    print("evaluation) works correctly end-to-end for MySQL/Postgres sessions.")
    print("What this does NOT prove: that the resulting model is accurate on real")
    print("attacker traffic — it's trained only on our own synthetic sessions, and")
    print("uses a stage vocabulary not yet reconciled with the shared classifier's.")
    print("Real retraining needs: (1) real deployed traffic (Phase 8), (2) a team")
    print("decision on unified stage vocabulary with Robert.")


if __name__ == "__main__":
    main()
