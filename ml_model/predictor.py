"""
ml_model/predictor.py

Loads the trained XGBoost model and exposes predict() to the IDS engine.
Returns (label, confidence, proba_vector) so the UI can show full
per-class probability bars.
"""

import logging
import os
import threading

import numpy as np
import xgboost as xgb

from ml_model.train_model import FEATURE_COLUMNS, CLASS_NAMES, MODEL_PATH

logger = logging.getLogger("ai_idps.predictor")

# Returned when a prediction can't be produced at all (bad input, a model/
# class-count mismatch, an XGBoost internal error, ...) so the IDS
# packet-processing loop never crashes on one malformed sample - it just
# logs the failure and keeps going with a clearly "unknown" result.
_FALLBACK_LABEL = CLASS_NAMES[0] if CLASS_NAMES else "Unknown"


def _sanitize_feature_value(value):
    """Coerce a single feature value to a finite float, defaulting to 0.0
    for None, NaN, +/-inf, or anything that can't be cast to float. A
    single bad/missing feature (e.g. a stalled aggregator counter) should
    degrade gracefully, not corrupt the whole feature vector or crash
    predict_proba()."""
    if value is None:
        return 0.0
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not np.isfinite(f):
        return 0.0
    return f


class Predictor:
    def __init__(self, model_path=MODEL_PATH):
        if not FEATURE_COLUMNS:
            raise ValueError("FEATURE_COLUMNS is empty - cannot build feature vectors")
        if not CLASS_NAMES:
            raise ValueError("CLASS_NAMES is empty - cannot map predictions to labels")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                "Run `python -m ml_model.train_model` first."
            )
        try:
            self.model = xgb.XGBClassifier()
            self.model.load_model(model_path)
        except Exception as e:
            # xgb.load_model() can raise on a corrupt file, a version
            # mismatch between the training and serving XGBoost builds, or
            # a truncated download - surface a clear, specific error
            # instead of letting a raw XGBoostError bubble up.
            raise RuntimeError(
                f"Failed to load XGBoost model from {model_path}: {e}"
            ) from e
        logger.info("XGBoost model loaded from %s", model_path)

    def predict(self, feature_dict):
        """
        Args:
            feature_dict: dict with keys matching FEATURE_COLUMNS
        Returns:
            (label_name, confidence, proba_vector_dict)

            On any failure (bad/missing features, a model/class-count
            mismatch, an internal XGBoost error) this returns a safe
            fallback result instead of raising, so a single bad sample
            can't take down the caller's processing loop.
        """
        try:
            # Build the vector in FEATURE_COLUMNS order, sanitizing every
            # value so missing keys, None, NaN, or inf can't reach XGBoost.
            row = [_sanitize_feature_value(feature_dict.get(c, 0.0)) for c in FEATURE_COLUMNS]
            vec = np.array([row], dtype=np.float64)

            proba = self.model.predict_proba(vec)[0]
            # np.argmax over an array containing NaN is undefined/unstable
            # (NaN comparisons are always False), so clean the probability
            # vector before ranking it.
            proba = np.nan_to_num(proba, nan=0.0, posinf=0.0, neginf=0.0)

            if len(proba) != len(CLASS_NAMES):
                logger.error(
                    "Model output size (%d) does not match CLASS_NAMES (%d); "
                    "the model was likely retrained with a different class "
                    "set than this build of train_model.py defines. "
                    "Returning fallback prediction.",
                    len(proba), len(CLASS_NAMES),
                )
                return _FALLBACK_LABEL, 0.0, {}

            idx = int(np.argmax(proba))
            proba_vector = {
                CLASS_NAMES[i]: round(float(proba[i]), 4) for i in range(len(CLASS_NAMES))
            }
            return CLASS_NAMES[idx], float(proba[idx]), proba_vector
        except Exception as e:
            logger.error("Prediction failed, returning fallback result: %s", e)
            return _FALLBACK_LABEL, 0.0, {}


_predictor_instance = None
_predictor_lock = threading.Lock()


def get_predictor():
    """Thread-safe singleton accessor.

    Previously this was a bare check-then-create with no locking: if the
    capture loop, a background analysis thread, and a Flask request all
    called get_predictor() at nearly the same time before the first
    instance was assigned, each one would construct its own Predictor and
    load the model file independently - wasted I/O/memory, and a race on
    which instance ends up as the "final" singleton.

    Double-checked locking keeps the common case (instance already built)
    lock-free while making first-time construction safe under concurrency.
    """
    global _predictor_instance
    if _predictor_instance is None:
        with _predictor_lock:
            if _predictor_instance is None:
                _predictor_instance = Predictor()
    return _predictor_instance