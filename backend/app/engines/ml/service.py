from __future__ import annotations

from pathlib import Path

from app.engines.ml.exceptions import MLModelUnavailableError
from app.engines.ml.model import MODEL_NAME, EmailTextModel
from app.engines.ml.preprocessing import prepare_email_text

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.joblib"
CLASSIFIER_PATH = ARTIFACTS_DIR / "logistic_regression.joblib"
_MODEL_CACHE: dict[tuple[str, str], EmailTextModel] = {}


def _load_model(artifacts_dir: Path) -> EmailTextModel:
    vectorizer_path = artifacts_dir / "tfidf_vectorizer.joblib"
    classifier_path = artifacts_dir / "logistic_regression.joblib"
    cache_key = (str(vectorizer_path.resolve()), str(classifier_path.resolve()))
    if cache_key not in _MODEL_CACHE:
        _MODEL_CACHE[cache_key] = EmailTextModel(vectorizer_path, classifier_path)
    return _MODEL_CACHE[cache_key]


def get_model_status(artifacts_dir: Path | None = None) -> tuple[str, str | None]:
    artifacts_dir = artifacts_dir or ARTIFACTS_DIR
    try:
        _load_model(artifacts_dir)
    except MLModelUnavailableError as exc:
        return "unavailable", str(exc)
    return "available", None


def classify_email(parsed: dict, artifacts_dir: Path | None = None) -> dict:
    artifacts_dir = artifacts_dir or ARTIFACTS_DIR
    body = parsed.get("body") or {}
    message = parsed.get("message") or {}
    text = prepare_email_text(message.get("subject"), body.get("plain_text"))
    try:
        model = _load_model(artifacts_dir)
    except MLModelUnavailableError as exc:
        return {
            "available": False,
            "prediction": None,
            "probability": None,
            "model": MODEL_NAME,
            "message": str(exc),
        }
    try:
        prediction, probability = model.predict(text)
    except RuntimeError:
        return {
            "available": False,
            "prediction": None,
            "probability": None,
            "model": MODEL_NAME,
            "message": "ML model artifacts are incompatible with this email.",
        }
    return {
        "available": True,
        "prediction": prediction,
        "probability": probability,
        "model": MODEL_NAME,
        "message": None,
    }
