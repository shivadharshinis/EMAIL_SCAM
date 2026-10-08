from __future__ import annotations

import csv
import hashlib
import html
import json
import random
import re
import sys
from collections import Counter, defaultdict
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable

DATA_DIR = Path(__file__).resolve().parent
RAW_DIR = DATA_DIR / "raw"
DERIVED_DIR = DATA_DIR / "derived"
REPORTS_DIR = DATA_DIR / "reports"
SEED = 42
PREPROCESSING_VERSION = "1.0"

NAZARIO_FILES = ("Nazario.csv", "Nazario_5.csv")
TWENTE_FILE = "Phishing_validation_emails.csv"
LEGITIMATE_FILES = ("Enron.csv", "SpamAssasin.csv")


def normalize_text(value: object) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def html_to_text(value: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    text = re.sub(r"(?s)<[^>]*>", " ", text)
    return normalize_text(text)


def _message_parts(message: Message) -> tuple[str, str]:
    plain: list[str] = []
    html_parts: list[str] = []
    for part in message.walk() if message.is_multipart() else (message,):
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        value = payload.decode(charset, errors="replace")
        if part.get_content_type() == "text/html":
            html_parts.append(value)
        elif part.get_content_type() == "text/plain":
            plain.append(value)
    return normalize_text("\n".join(plain)), html_to_text("\n".join(html_parts))


def parse_raw_email(raw: bytes | str) -> tuple[str, str, bool]:
    data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    message = BytesParser(policy=policy.default).parsebytes(data)
    plain, html_body = _message_parts(message)
    return normalize_text(message.get("Subject", "")), plain or html_body, bool(message.items())


def _header(row: dict[str, str], *names: str) -> str:
    lowered = {key.strip().lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return ""


def _read_rows(path: Path) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _record(subject: str, text: str, label: int, source: str, index: int, *, has_headers: bool = False) -> dict:
    subject = normalize_text(subject)
    text = normalize_text(text)
    return {
        "subject": subject,
        "text": text,
        "label": label,
        "source": source,
        "source_id": f"{source}:{index}",
        "has_headers": has_headers,
        "normalized_subject": subject.casefold(),
        "normalized_body": text.casefold(),
    }


def _csv_record(row: dict[str, str], label: int, source: str, index: int) -> dict:
    subject = _header(row, "subject")
    body = _header(row, "body", "text", "email text", "email_text")
    raw_email = _header(row, "raw", "raw_email", "email")
    if raw_email and not body:
        subject, body, has_headers = parse_raw_email(raw_email)
    else:
        has_headers = bool(_header(row, "sender", "receiver", "date", "from", "to"))
    return _record(subject, body, label, source, index, has_headers=has_headers)


def load_sources(raw_dir: Path = RAW_DIR) -> tuple[list[dict], Counter, Counter]:
    records: list[dict] = []
    original = Counter()
    removed = Counter()

    for filename in NAZARIO_FILES:
        path = raw_dir / filename
        if not path.exists():
            continue
        source = Path(filename).stem
        for index, row in enumerate(_read_rows(path)):
            original[source] += 1
            label = int(_header(row, "label") or "1")
            records.append(_csv_record(row, label, source, index))

    twente = raw_dir / TWENTE_FILE
    if twente.exists():
        for index, row in enumerate(_read_rows(twente)):
            original["Twente"] += 1
            value = _header(row, "email type").casefold()
            if value == "phishing email":
                records.append(_csv_record(row, 1, "Twente", index))
            elif value == "safe email":
                records.append(_csv_record(row, 0, "Twente", index))
            else:
                removed["unknown_label"] += 1

    for filename in LEGITIMATE_FILES:
        path = raw_dir / filename
        if not path.exists():
            continue
        source = Path(filename).stem
        for index, row in enumerate(_read_rows(path)):
            original[source] += 1
            # These files are explicitly used only for their ham/legitimate rows.
            label = _header(row, "label").strip().casefold()
            if label and label not in {"0", "ham", "legitimate", "legit"}:
                removed[f"{source}_non_ham"] += 1
                continue
            records.append(_csv_record(row, 0, source, index))
    return records, original, removed


def _hashes(record: dict) -> tuple[str, str]:
    subject_hash = hashlib.sha256(
        f"{record['normalized_subject']}\n{record['normalized_body']}".encode()
    ).hexdigest()
    body_hash = hashlib.sha256(record["normalized_body"].encode()).hexdigest()
    return subject_hash, body_hash


def deduplicate(records: Iterable[dict]) -> tuple[list[dict], dict]:
    kept: list[dict] = []
    seen_subject_body: dict[str, dict] = {}
    seen_body: dict[str, dict] = {}
    seen_message_ids: set[str] = set()
    stats = Counter()
    duplicate_sources: Counter = Counter()
    cross_source = 0

    for record in records:
        if not record["subject"] and not record["text"]:
            stats["empty"] += 1
            continue
        subject_hash, body_hash = _hashes(record)
        record["content_hash"] = subject_hash
        record["body_hash"] = body_hash
        duplicate = seen_subject_body.get(subject_hash) or seen_body.get(body_hash)
        if duplicate:
            stats["duplicates_removed"] += 1
            duplicate_sources[f"{duplicate['source']}->{record['source']}"] += 1
            if duplicate["source"] != record["source"]:
                cross_source += 1
            continue
        seen_subject_body[subject_hash] = record
        seen_body[body_hash] = record
        kept.append(record)
    stats["cross_source_duplicates"] = cross_source
    return kept, {
        "counts": dict(stats),
        "duplicate_sources": dict(duplicate_sources),
    }


def near_duplicate_audit(records: Iterable[dict]) -> dict:
    # This intentionally conservative signature finds campaign-like groups without
    # deleting them or performing network lookups.
    groups: defaultdict[tuple[int, str], list[dict]] = defaultdict(list)
    for record in records:
        body = record["normalized_body"]
        signature = (len(body) // 80, body[:120])
        if body:
            groups[signature].append(record)
    candidates = [group for group in groups.values() if len(group) > 1]
    largest = sorted(
        (
            {
                "size": len(group),
                "sources": dict(Counter(item["source"] for item in group)),
                "labels": dict(Counter(str(item["label"]) for item in group)),
            }
            for group in candidates
        ),
        key=lambda item: item["size"],
        reverse=True,
    )[:20]
    return {
        "potential_group_count": len(candidates),
        "largest_groups": largest,
    }


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["subject", "text", "label", "source"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)


def _sample_legitimate(rows: list[dict], limit: int = 5000) -> list[dict]:
    if len(rows) <= limit:
        return rows
    rng = random.Random(SEED)
    by_source: defaultdict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_source[row["source"]].append(row)
    selected: list[dict] = []
    sources = sorted(by_source)
    while len(selected) < limit:
        made_progress = False
        for source in sources:
            if by_source[source]:
                selected.append(by_source[source].pop(rng.randrange(len(by_source[source]))))
                made_progress = True
                if len(selected) == limit:
                    break
        if not made_progress:
            break
    return selected


def prepare_dataset(raw_dir: Path = RAW_DIR, data_dir: Path = DATA_DIR) -> dict:
    records, original_counts, load_removed = load_sources(raw_dir)
    deduped, duplicate_stats = deduplicate(records)

    twente_rows = [row for row in deduped if row["source"] == "Twente"]
    rng = random.Random(SEED)
    validation_count = min(400, len(twente_rows) // 5)
    validation_indices = set(rng.sample(range(len(twente_rows)), validation_count))
    validation = [row for index, row in enumerate(twente_rows) if index in validation_indices]
    validation_ids = {row["source_id"] for row in validation}
    training_pool = [
        row for index, row in enumerate(deduped)
        if row["source_id"] not in validation_ids
    ]
    training = _sample_legitimate([row for row in training_pool if row["label"] == 0])
    training.extend(row for row in training_pool if row["label"] == 1)

    _write_csv(data_dir / "derived" / "email_dataset.csv", training)
    _write_csv(data_dir / "derived" / "external_validation.csv", validation)

    counts = Counter(row["label"] for row in training)
    report = {
        "preprocessing_version": PREPROCESSING_VERSION,
        "random_seed": SEED,
        "original_counts": dict(original_counts),
        "load_removed": dict(load_removed),
        "parsed_count": len(records),
        "parsed_source_distribution": dict(Counter(row["source"] for row in records)),
        "empty_removed": duplicate_stats["counts"].get("empty", 0),
        "duplicates_removed": duplicate_stats["counts"].get("duplicates_removed", 0),
        "cross_source_duplicates": duplicate_stats["counts"].get("cross_source_duplicates", 0),
        "duplicate_sources": duplicate_stats["duplicate_sources"],
        "near_duplicate_audit": near_duplicate_audit(deduped),
        "final_training_count": len(training),
        "final_validation_count": len(validation),
        "final_usable_source_distribution": dict(
            Counter(row["source"] for row in deduped)
        ),
        "training_class_distribution": {"legitimate": counts.get(0, 0), "phishing": counts.get(1, 0)},
        "training_source_distribution": dict(Counter(row["source"] for row in training)),
        "validation_class_distribution": dict(Counter("legitimate" if row["label"] == 0 else "phishing" for row in validation)),
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "notes": [
            "Twente validation rows are excluded from training.",
            "SpamAssassin spam and Nigerian Fraud are not used as phishing.",
            "Near-duplicate candidates are audited but not removed.",
        ],
    }
    reports = data_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "preparation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (reports / "preparation_report.md").write_text(_markdown_report(report), encoding="utf-8")
    return report


def _markdown_report(report: dict) -> str:
    return "\n".join(
        [
            "# Dataset preparation report",
            "",
            f"- Preparation version: `{report['preprocessing_version']}`",
            f"- Random seed: `{report['random_seed']}`",
            f"- Parsed rows: **{report['parsed_count']}**",
            f"- Parsed source distribution: `{json.dumps(report['parsed_source_distribution'], sort_keys=True)}`",
            f"- Empty rows removed: **{report['empty_removed']}**",
            f"- Exact duplicates removed: **{report['duplicates_removed']}**",
            f"- Cross-source duplicates: **{report['cross_source_duplicates']}**",
            f"- Potential near-duplicate groups: **{report['near_duplicate_audit']['potential_group_count']}**",
            f"- Training rows: **{report['final_training_count']}**",
            f"- External validation rows: **{report['final_validation_count']}**",
            "",
            "## Counts",
            "",
            f"- Original: `{json.dumps(report['original_counts'], sort_keys=True)}`",
            f"- Training labels: `{json.dumps(report['training_class_distribution'], sort_keys=True)}`",
            f"- Training sources: `{json.dumps(report['training_source_distribution'], sort_keys=True)}`",
            f"- Usable source distribution before holdout/sampling: `{json.dumps(report['final_usable_source_distribution'], sort_keys=True)}`",
            f"- Validation labels: `{json.dumps(report['validation_class_distribution'], sort_keys=True)}`",
            "",
            "Rows are parsed offline. URLs are preserved as text only; no URLs are opened, resolved, or contacted.",
            "Attachments are not executed or unpacked.",
            "",
        ]
    )


if __name__ == "__main__":
    print(json.dumps(prepare_dataset(), indent=2))
