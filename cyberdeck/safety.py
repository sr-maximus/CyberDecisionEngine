from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Union

from cyberdeck.settings import load_yaml, resolve_path


SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*['\"]?[^'\"\s]+"),
    re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"\b\d{6,12}\b"),
]


def redact_text(value: Any) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def redact_mapping(data: Dict[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            redacted[key] = redact_mapping(value)
        elif isinstance(value, list):
            redacted[key] = [redact_text(item) if not isinstance(item, dict) else redact_mapping(item) for item in value]
        else:
            redacted[key] = redact_text(value)
    return redacted


def enforce_authorized_scope(org_path: Union[str, Path]) -> Dict[str, Any]:
    data = load_yaml(org_path)
    organization = data.get("organization", {})
    if not organization.get("authorized_scope"):
        raise PermissionError(
            "Organization profile must contain organization.authorized_scope: true before analysis."
        )
    return data


def validate_darkweb_import(path: Union[str, Path], allow_tor: bool = False) -> Path:
    if allow_tor:
        raise PermissionError("Tor access is intentionally disabled. Use authorized redacted feeds only.")
    resolved = resolve_path(path)
    if resolved.suffix.lower() not in {".csv", ".json"}:
        raise ValueError("Dark Web authorized import only accepts redacted CSV or JSON metadata.")
    if not resolved.exists():
        raise FileNotFoundError(f"Authorized import file not found: {resolved}")
    return resolved


def data_mode_label(is_demo: bool) -> str:
    return "DEMO/SIMULADO" if is_demo else "RECOLECCION AUTORIZADA"
