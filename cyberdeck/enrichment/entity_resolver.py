from __future__ import annotations

from typing import Dict


def resolve_entity(name: str) -> Dict[str, str]:
    normalized = " ".join(name.lower().split())
    return {"input": name, "normalized": normalized, "entity_type": "organization"}
