from pathlib import Path

import pytest

from app.engines.ml.exceptions import MLModelUnavailableError
from app.engines.ml.model import EmailTextModel
from app.engines.ml.preprocessing import prepare_email_text
from app.engines.ml.service import classify_email
from app.engines.ml.training.train import train_model
from app.engines.ml.training.train import SMOKE_DATASET_PATH


def test_preprocessing_normalizes_without_removing_signals():
    text = prepare_email_text("  URGENT  ", "Provide\n your password at http://example.test ")
    assert text == "urgent provide your password at http://example.test"


def test_missing_artifacts_return_explicit_unavailable_state(tmp_path: Path):
    result = classify_email(
        {"message": {"subject": "Hello"}, "body": {"plain_text": "Normal note"}},
        artifacts_dir=tmp_path,
    )
    assert result["available"] is False
    assert result["prediction"] is None
    assert "unavailable" in result["message"].lower()


def test_training_and_prediction_probability_range(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "app.engines.ml.training.train.ARTIFACTS_DIR",
        tmp_path,
    )
    metrics = train_model(
        dataset_path=SMOKE_DATASET_PATH,
        external_validation_path=None,
    )
    assert metrics["dataset_size"] == 20
    assert metrics["class_distribution"] == {"legitimate": 10, "phishing": 10}
    model = EmailTextModel(
        tmp_path / "tfidf_vectorizer.joblib",
        tmp_path / "logistic_regression.joblib",
    )
    prediction, probability = model.predict("urgent confirm your password immediately")
    assert prediction in {"PHISHING", "LEGITIMATE"}
    assert 0 <= probability <= 1


def test_corrupt_artifacts_are_not_treated_as_prediction(tmp_path: Path):
    (tmp_path / "tfidf_vectorizer.joblib").write_bytes(b"not a model")
    (tmp_path / "logistic_regression.joblib").write_bytes(b"not a model")
    with pytest.raises(MLModelUnavailableError):
        EmailTextModel(
            tmp_path / "tfidf_vectorizer.joblib",
            tmp_path / "logistic_regression.joblib",
        )


def test_training_is_reproducible(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "app.engines.ml.training.train.ARTIFACTS_DIR",
        tmp_path,
    )
    first = train_model(
        dataset_path=SMOKE_DATASET_PATH,
        external_validation_path=None,
    )
    second = train_model(
        dataset_path=SMOKE_DATASET_PATH,
        external_validation_path=None,
    )
    first.pop("training_timestamp_utc")
    second.pop("training_timestamp_utc")
    assert first == second


def test_real_dataset_training_metadata_and_external_validation(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "app.engines.ml.training.train.ARTIFACTS_DIR",
        tmp_path,
    )
    metrics = train_model()
    assert metrics["dataset_size"] == 6543
    assert metrics["class_distribution"] == {"legitimate": 5000, "phishing": 1543}
    assert metrics["train_size"] == 5234
    assert metrics["test_size"] == 1309
    assert metrics["external_validation"]["dataset_size"] == 20
    assert set(metrics["tfidf_configuration"]) == {"lowercase", "ngram_range"}
    assert "source" not in metrics["tfidf_configuration"]
    assert (tmp_path / "metrics.json").exists()
