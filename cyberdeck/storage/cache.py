from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberdeck.settings import resolve_path


def write_cache(path: str, data: Any) -> Path:
    resolved = resolve_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return resolved


def read_cache(path: str) -> Any:
    resolved = resolve_path(path)
    if not resolved.exists():
        return None
    return json.loads(resolved.read_text(encoding="utf-8"))
