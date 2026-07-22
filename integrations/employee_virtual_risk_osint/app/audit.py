from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def write_audit_log(output_dir: str | Path, records: List[Dict[str, Any]]) -> Path:
    path = Path(output_dir) / "audit_log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **record,
            }
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return path
