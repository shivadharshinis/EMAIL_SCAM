from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from app.engines.ml.preprocessing import prepare_email_text

PACKAGE_DIR = Path(__file__).resolve().parents[1]
REAL_DATASET_PATH = PACKAGE_DIR / "data" / "derived" / "email_dataset.csv"
EXTERNAL_VALIDATION_PATH = PACKAGE_DIR / "data" / "derived" / "external_validation.csv"
SMOKE_DATASET_PATH = PACKAGE_DIR / "data" / "email_dataset.csv"
DATASET_PATH = REAL_DATASET_PATH
ARTIFACTS_DIR = PACKAGE_DIR / "artifacts"
CORE_COLUMNS = {"subject", "text", "label"}
RANDOM_STATE = 42
TEST_SIZE = 0.20
VECTORIZER_CONFIG = {
    "lowercase": True,
    "ngram_range": (1, 1),
}
CLASSIFIER_CONFIG = {
    "max_iter": 1000,
    "random_state": RANDOM_STATE,
    "C": 1.0,
}


def _read_rows(path: Path) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        required = CORE_COLUMNS | ({"source"} if path != SMOKE_DATASET_PATH else set())
        missing = required - columns
        if missing:
            raise ValueError(
                f"Dataset {path} is missing required columns: {sorted(missing)}"
            )
        return list(reader)


def load_dataset(path: Path = DATASET_PATH) -> tuple[list[str], list[int]]:
    rows = _read_rows(path)
    texts: list[str] = []
    labels: list[int] = []
    for row in rows:
        try:
            label = int(row["label"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid label in {path}: {row['label']!r}") from exc
        if label not in (0, 1):
            raise ValueError(f"Labels must be 0 or 1; got {label!r} in {path}")
        # Deliberately read only subject and text. Source is provenance metadata,
        # not a classifier feature.
        texts.append(prepare_email_text(row["subject"], row["text"]))
        labels.append(label)
    if not texts or len(set(labels)) != 2:
        raise ValueError(f"Dataset {path} must contain both classes and at least one row.")
    return texts, labels


def _evaluate(labels: list[int], predictions: Any) -> dict[str, Any]:
    report = classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        zero_division=0,
        output_dict=True,
    )
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1_score": float(f1_score(labels, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=[0, 1]).tolist(),
        "classification_report": report,
        "class_support": {
            "legitimate": int(report["legitimate"]["support"]),
            "phishing": int(report["phishing"]["support"]),
        },
        "phishing_precision": float(report["phishing"]["precision"]),
        "phishing_recall": float(report["phishing"]["recall"]),
        "phishing_f1": float(report["phishing"]["f1-score"]),
    }


def _class_counts(labels: list[int]) -> dict[str, int]:
    return {"legitimate": labels.count(0), "phishing": labels.count(1)}


def train_model(
    dataset_path: Path = DATASET_PATH,
    external_validation_path: Path | None = EXTERNAL_VALIDATION_PATH,
) -> dict[str, Any]:
    texts, labels = load_dataset(dataset_path)
    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    vectorizer = TfidfVectorizer(**VECTORIZER_CONFIG)
    x_train_features = vectorizer.fit_transform(x_train)
    classifier = LogisticRegression(**CLASSIFIER_CONFIG)
    classifier.fit(x_train_features, y_train)

    test_predictions = classifier.predict(vectorizer.transform(x_test))
    test_metrics = _evaluate(y_test, test_predictions)
    external_metrics: dict[str, Any] | None = None
    external_size = 0
    if external_validation_path is not None and external_validation_path.is_file():
        external_texts, external_labels = load_dataset(external_validation_path)
        external_predictions = classifier.predict(vectorizer.transform(external_texts))
        external_metrics = _evaluate(external_labels, external_predictions)
        external_size = len(external_labels)

    metrics: dict[str, Any] = {
        "model_name": "TF-IDF + Logistic Regression",
        "dataset_path": str(dataset_path),
        "dataset_size": len(labels),
        "class_distribution": _class_counts(labels),
        "train_size": len(y_train),
        "test_size": len(y_test),
        "train_class_distribution": _class_counts(y_train),
        "test_class_distribution": _class_counts(y_test),
        "random_state": RANDOM_STATE,
        "test_size_fraction": TEST_SIZE,
        "tfidf_configuration": {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in VECTORIZER_CONFIG.items()
        },
        "logistic_regression_configuration": CLASSIFIER_CONFIG,
        "test_metrics": test_metrics,
        # Retain the original top-level fields for smoke-test and tooling
        # compatibility while the structured test_metrics remains canonical.
        "accuracy": test_metrics["accuracy"],
        "precision": test_metrics["precision"],
        "recall": test_metrics["recall"],
        "f1_score": test_metrics["f1_score"],
        "confusion_matrix": test_metrics["confusion_matrix"],
        "classification_report": test_metrics["classification_report"],
        "external_validation": {
            "dataset_path": str(external_validation_path)
            if external_validation_path is not None
            else None,
            "dataset_size": external_size,
            "metrics": external_metrics,
            "note": (
                "Small external sanity check; not used for fitting, tuning, "
                "or model selection."
            ),
        },
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, ARTIFACTS_DIR / "tfidf_vectorizer.joblib")
    joblib.dump(classifier, ARTIFACTS_DIR / "logistic_regression.joblib")
    (ARTIFACTS_DIR / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    return metrics


def _print_summary(metrics: dict[str, Any]) -> None:
    test = metrics["test_metrics"]
    external = metrics["external_validation"]["metrics"]
    print(
        f"Trained {metrics['model_name']} on {metrics['dataset_size']} rows "
        f"({metrics['class_distribution']})."
    )
    print(
        f"Test: accuracy={test['accuracy']:.4f}, precision={test['precision']:.4f}, "
        f"recall={test['recall']:.4f}, f1={test['f1_score']:.4f}"
    )
    if external:
        print(
            f"External validation ({metrics['external_validation']['dataset_size']} rows): "
            f"accuracy={external['accuracy']:.4f}, precision={external['precision']:.4f}, "
            f"recall={external['recall']:.4f}, f1={external['f1_score']:.4f}"
        )


if __name__ == "__main__":
    _print_summary(train_model())
