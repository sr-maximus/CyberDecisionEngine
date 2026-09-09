from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from typing import Any, Mapping


SNAPSHOT_HASH_ALGORITHM = "sha256-canonical-json-v1"


def snapshot_hash(snapshot: Mapping[str, Any] | Any) -> str:
    """Return a deterministic digest of every published snapshot field."""
    payload = _snapshot_payload(snapshot)
    payload.pop("snapshot_hash", None)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def seal_snapshot(snapshot: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Copy and seal the exact payload that dashboard and reports publish."""
    payload = _snapshot_payload(snapshot)
    payload["snapshot_hash_algorithm"] = SNAPSHOT_HASH_ALGORITHM
    payload["snapshot_hash"] = snapshot_hash(payload)
    return payload


def verify_snapshot(snapshot: Mapping[str, Any] | Any) -> bool:
    payload = _snapshot_payload(snapshot)
    declared = str(payload.get("snapshot_hash") or "")
    algorithm = str(payload.get("snapshot_hash_algorithm") or "")
    if algorithm != SNAPSHOT_HASH_ALGORITHM or len(declared) != 64:
        return False
    return hmac.compare_digest(declared, snapshot_hash(payload))


def _snapshot_payload(snapshot: Mapping[str, Any] | Any) -> dict[str, Any]:
    if hasattr(snapshot, "model_dump"):
        value = snapshot.model_dump(mode="json")
    elif isinstance(snapshot, Mapping):
        value = dict(snapshot)
    else:
        raise TypeError("Snapshot must be a mapping or a model with model_dump().")
    return deepcopy(value)
