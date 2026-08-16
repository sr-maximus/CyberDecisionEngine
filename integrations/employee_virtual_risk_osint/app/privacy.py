from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any


TRUE_VALUES = {"true", "1", "yes", "y", "si", "sí", "approved", "aprobado", "autorizado", "consentido"}
FALSE_VALUES = {"false", "0", "no", "n", "rejected", "rechazado", "not_provided", ""}


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text


def normalize_column_name(value: str) -> str:
    value = normalize_text(value)
    value = value.replace(" ", "_").replace("-", "_")
    value = re.sub(r"[^a-z0-9_]", "", value)
    return value


def parse_bool(value: Any) -> bool:
    return normalize_text(value) in TRUE_VALUES


def has_valid_consent(value: Any) -> bool:
    return normalize_text(value) in TRUE_VALUES


def hash_identifier(identifier: Any, salt: str) -> str:
    raw = str(identifier or "").strip()
    if not raw:
        return ""
    if not salt.strip():
        raise ValueError("HASH_SALT must be configured before hashing identifiers")
    payload = f"{salt}:{raw}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def mask_email(email: str) -> str:
    email = str(email or "").strip()
    if "@" not in email:
        return ""
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[:1] + "*"
    else:
        masked_user = user[:2] + "*" * max(2, len(user) - 2)
    return f"{masked_user}@{domain}"


def safe_filename(value: str) -> str:
    value = normalize_text(value)
    value = re.sub(r"[^a-z0-9_.-]+", "_", value)
    return value.strip("_") or "file"


def email_domain(email: str) -> str:
    email = str(email or "").strip().lower()
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1]
