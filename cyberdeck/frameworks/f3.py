from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from typing import Any

from cyberdeck.settings import PROJECT_ROOT


F3_VERSION = "1.1"
F3_SOURCE = "MITRE Fight Fraud Framework (F3)"
F3_SOURCE_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "fight-fraud-framework/main/public/f3-v1.1.json"
)
F3_REFERENCE_URL = "https://ctid.mitre.org/fraud"
F3_REPOSITORY_URL = (
    "https://github.com/center-for-threat-informed-defense/fight-fraud-framework"
)
F3_LAST_MODIFIED = "2026-06-23"
F3_DATA_PATH = PROJECT_ROOT / "data" / "frameworks" / "mitre_f3_v1_1.json"

F3_TACTIC_LABELS_ES = {
    "TA0043": "Reconocimiento",
    "TA0042": "Desarrollo de recursos",
    "TA0001": "Acceso inicial",
    "TA0005": "Sigilo",
    "TA0112": "Deterioro de defensas",
    "FA0001": "Posicionamiento",
    "TA0002": "Ejecución",
    "FA0002": "Monetización",
}


@lru_cache(maxsize=1)
def load_f3_catalog() -> dict[str, Any]:
    try:
        records = json.loads(F3_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        records = []
    if not isinstance(records, list):
        records = []
    valid_records = [
        item
        for item in records
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("name"), str)
    ]
    tactics = [item for item in valid_records if item.get("tactic") is True]
    techniques = [item for item in valid_records if item.get("tactic") is not True]
    raw = json.dumps(valid_records, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return {
        "framework": F3_SOURCE,
        "version": F3_VERSION,
        "source_url": F3_SOURCE_URL,
        "reference_url": F3_REFERENCE_URL,
        "repository_url": F3_REPOSITORY_URL,
        "last_modified": F3_LAST_MODIFIED,
        "sha256": hashlib.sha256(raw).hexdigest() if valid_records else "",
        "tactics": tactics,
        "techniques": techniques,
        "record_count": len(valid_records),
    }


def validate_f3_records(records: Any) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError("MITRE F3 payload must be a JSON array.")
    normalized: list[dict[str, Any]] = []
    ids: set[str] = set()
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("MITRE F3 record must be an object.")
        identifier = str(raw.get("id") or "").strip()
        name = str(raw.get("name") or "").strip()
        version = str(raw.get("version") or "").strip()
        if not identifier or not name or version != F3_VERSION:
            raise ValueError(f"Invalid MITRE F3 record: {identifier or 'missing-id'}")
        if identifier in ids:
            raise ValueError(f"Duplicate MITRE F3 identifier: {identifier}")
        ids.add(identifier)
        normalized.append(raw)
    tactic_count = sum(item.get("tactic") is True for item in normalized)
    technique_count = len(normalized) - tactic_count
    if tactic_count != 8 or technique_count < 100:
        raise ValueError(
            f"Unexpected MITRE F3 catalog size: {tactic_count} tactics, "
            f"{technique_count} techniques."
        )
    return normalized
