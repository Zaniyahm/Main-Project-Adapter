"""Live inference functions for the Stage/Intent Classifier and Markov Predictor.

These functions load persisted models and extract features to provide
real-time predictions callable from the Flask app. They fall back
gracefully if model files are missing or feature extraction fails.
"""
import json
import logging
from pathlib import Path

import joblib
import numpy as np

from features import extract_session_features, FEATURE_NAMES

MODELS_DIR = Path(__file__).parent / "models"
logger = logging.getLogger(__name__)


def predict_stage_intent(session_id: str) -> tuple:
    stage_path = MODELS_DIR / "stage_classifier.joblib"
    intent_path = MODELS_DIR / "intent_classifier.joblib"

    if not stage_path.exists() or not intent_path.exists():
        logger.warning("Model files missing — falling back to rule-based")
        return (None, None, 0.0)

    try:
        features = extract_session_features(session_id)
    except Exception as e:
        logger.warning(f"Feature extraction failed for {session_id}: {e}")
        return (None, None, 0.0)

    X = np.array([features])

    try:
        stage_model = joblib.load(stage_path)
        intent_model = joblib.load(intent_path)

        stage_pred = stage_model["model"].predict(X)[0]
        intent_pred = intent_model["model"].predict(X)[0]

        stage_proba = stage_model["model"].predict_proba(X)[0]
        intent_proba = intent_model["model"].predict_proba(X)[0]
        confidence = min(float(np.max(stage_proba)), float(np.max(intent_proba)))

        return (stage_pred, intent_pred, confidence)
    except Exception as e:
        logger.warning(f"Model prediction failed: {e}")
        return (None, None, 0.0)


def detect_anomaly(session_id: str) -> tuple:
    model_path = MODELS_DIR / "anomaly_detector.joblib"

    if not model_path.exists():
        logger.warning("Anomaly detector model missing")
        return (False, 0.0)

    try:
        features = extract_session_features(session_id)
    except Exception as e:
        logger.warning(f"Feature extraction failed for anomaly detection {session_id}: {e}")
        return (False, 0.0)

    try:
        model_data = joblib.load(model_path)
        iso_forest = model_data["model"]
        scaler = model_data["scaler"]

        anomaly_idx = model_data.get("anomaly_feature_idx")
        if anomaly_idx is not None:
            features = [features[i] for i in anomaly_idx]

        X = np.array([features])
        X_scaled = scaler.transform(X)

        score = float(iso_forest.score_samples(X_scaled)[0])
        is_anomalous = bool(iso_forest.predict(X_scaled)[0] == -1)

        return (is_anomalous, score)
    except Exception as e:
        logger.warning(f"Anomaly detection failed: {e}")
        return (False, 0.0)


def predict_next_categories(session_id: str, top_k: int = 3) -> list:
    table_path = MODELS_DIR / "action_transition_table.json"

    if not table_path.exists():
        logger.warning("Transition table missing — falling back to rule-based")
        return []

    try:
        with open(table_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        transition_table = data["transition_table"]
        categories = data["categories"]
    except Exception as e:
        logger.warning(f"Failed to load transition table: {e}")
        return []

    try:
        import core_db
        db = core_db.get_db()

        row = db.execute(
            "SELECT action, parameters FROM logs WHERE session_id = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (session_id,),
        ).fetchone()

        if row is None:
            return categories[:top_k] if categories else []

        from build_markov import classify_action
        params = json.loads(row["parameters"]) if isinstance(row["parameters"], str) else row["parameters"]
        current_cat = classify_action(row["action"], params)

        probs = transition_table.get(current_cat, {})
        if not probs:
            return categories[:top_k] if categories else []

        sorted_cats = sorted(probs.keys(), key=lambda k: probs[k], reverse=True)
        return sorted_cats[:top_k]
    except Exception as e:
        logger.warning(f"Markov prediction failed: {e}")
        return categories[:top_k] if 'categories' in dir() else []
