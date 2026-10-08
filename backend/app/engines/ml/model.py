from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from app.engines.ml.exceptions import MLModelUnavailableError

MODEL_NAME = "TF-IDF + Logistic Regression"


class EmailTextModel:
    def __init__(self, vectorizer_path: Path, classifier_path: Path) -> None:
        if not vectorizer_path.is_file() or not classifier_path.is_file():
            raise MLModelUnavailableError(
                "ML model artifacts are unavailable. Run the training command first."
            )
        try:
            self.vectorizer: Any = joblib.load(vectorizer_path)
            self.classifier: Any = joblib.load(classifier_path)
        except Exception as exc:
            raise MLModelUnavailableError(
                "ML model artifacts could not be loaded."
            ) from exc

    def predict(self, text: str) -> tuple[str, float]:
        try:
            features = self.vectorizer.transform([text])
            probabilities = self.classifier.predict_proba(features)[0]
            class_index = int(self.classifier.predict(features)[0])
            phishing_index = list(self.classifier.classes_).index(1)
            phishing_probability = float(probabilities[phishing_index])
        except Exception as exc:
            raise RuntimeError("ML model prediction failed.") from exc
        return ("PHISHING" if class_index == 1 else "LEGITIMATE", phishing_probability)
