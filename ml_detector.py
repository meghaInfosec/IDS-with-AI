"""
ml_detector.py
---------------
Loads the Random Forest model + scaler + feature schema that train_model.py
produced, and exposes one function: score(feature_dict) -> (label, confidence).

This is the piece that was MISSING from the original sniffer.py - the
trained .pkl files existed but nothing ever loaded them for live traffic.
"""

import os
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_model = None
_scaler = None
_feature_names = None


def load():
    global _model, _scaler, _feature_names
    model_path = os.path.join(BASE_DIR, "ids_rf_model.pkl")
    scaler_path = os.path.join(BASE_DIR, "ids_scaler.pkl")
    config_path = os.path.join(BASE_DIR, "ids_model_config.pkl")

    if not (os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(config_path)):
        raise FileNotFoundError(
            "Model files not found. Run train_model.py first to create "
            "ids_rf_model.pkl, ids_scaler.pkl and ids_model_config.pkl."
        )

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    config = joblib.load(config_path)
    _feature_names = config["feature_names"]
    print(f"[*] ML model loaded ({len(_feature_names)} features expected)")


def is_loaded():
    return _model is not None


def score(feature_dict):
    """feature_dict: output of Flow.to_feature_dict().
    Returns (label, confidence) where label is 'Normal' or 'Malicious'
    and confidence is 0-100 (the model's own probability for that class)."""
    if _model is None:
        raise RuntimeError("Call ml_detector.load() before score().")

    # Build the feature row in the EXACT order the model was trained on.
    # Any feature this flow tracker didn't fill in defaults to 0.
    import pandas as pd
    row = {name: feature_dict.get(name, 0) for name in _feature_names}
    X = pd.DataFrame([row], columns=_feature_names)
    X_scaled = _scaler.transform(X)

    prediction = _model.predict(X_scaled)[0]
    probabilities = _model.predict_proba(X_scaled)[0]
    confidence = probabilities[prediction] * 100

    label = "Malicious" if prediction == 1 else "Normal"
    return label, round(confidence, 1)
