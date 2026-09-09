from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import yaml

from cyberdeck.settings import PROJECT_ROOT, load_yaml


MANIFEST_VERSION = "cti-knowledge-manifest-v1"


def build_knowledge_manifest(
    *, generated_at: datetime | str | None = None
) -> dict[str, Any]:
    sources = _source_config()
    rows = [_source_manifest(source) for source in sources]
    mandatory = [row for row in rows if row.get("required")]
    usable = [row for row in mandatory if row.get("status") in {"active", "last_known_good"}]
    return {
        "schema_version": MANIFEST_VERSION,
        "generated_at": _manifest_timestamp(generated_at),
        "status": "ready" if len(usable) == len(mandatory) else "degraded",
        "mandatory_count": len(mandatory),
        "mandatory_usable_count": len(usable),
        "sources": rows,
    }


def sync_knowledge_sources(source_ids: list[str] | None = None) -> dict[str, Any]:
    selected = set(source_ids or [])
    results: list[dict[str, Any]] = []
    for source in _source_config():
        source_id = str(source.get("id") or "")
        if selected and source_id not in selected:
            continue
        if not source.get("download", True):
            results.append({"source_id": source_id, "status": "reference_only"})
            continue
        results.append(_sync_source(source))
    manifest = build_knowledge_manifest()
    manifest["sync_results"] = results
    return manifest


def rollback_knowledge_source(source_id: str) -> dict[str, Any]:
    source = next((row for row in _source_config() if row.get("id") == source_id), None)
    if source is None:
        raise ValueError(f"Unknown CTI knowledge source: {source_id}")
    destination = PROJECT_ROOT / str(source["path"])
    backup = destination.with_suffix(destination.suffix + ".lkg")
    if not backup.is_file():
        raise ValueError(f"No last-known-good backup exists for {source_id}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup, destination)
    return _source_manifest(source)


def _source_config() -> list[dict[str, Any]]:
    try:
        rows = load_yaml("config/cti.yml").get("knowledge", {}).get("sources", [])
    except (FileNotFoundError, ValueError):
        rows = []
    return [row for row in rows if isinstance(row, dict) and row.get("id")]


def _source_manifest(source: dict[str, Any]) -> dict[str, Any]:
    path = PROJECT_ROOT / str(source.get("path") or "")
    backup = path.with_suffix(path.suffix + ".lkg")
    active_path = path if path.is_file() else backup if backup.is_file() else None
    if not bool(source.get("download", True)):
        status = "reference"
    else:
        status = "active" if path.is_file() else "last_known_good" if backup.is_file() else "missing"
    checksum = _sha256(active_path) if active_path else None
    return {
        "source_id": source.get("id"),
        "name": source.get("name"),
        "family": source.get("family"),
        "url": source.get("url"),
        "path": str(path.relative_to(PROJECT_ROOT)) if source.get("path") else None,
        "required": bool(source.get("required", False)),
        "download": bool(source.get("download", True)),
        "status": status,
        "record_count": _record_count(active_path),
        "sha256": checksum,
        "updated_at": datetime.fromtimestamp(active_path.stat().st_mtime, timezone.utc).isoformat()
        if active_path
        else None,
        "version": _version(active_path, source),
        "license": source.get("license"),
    }


def _sync_source(source: dict[str, Any]) -> dict[str, Any]:
    source_id = str(source["id"])
    destination = PROJECT_ROOT / str(source["path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(
        str(source["url"]),
        headers={"User-Agent": "CyberDecisionEngine-CTI/1.0", "Accept": "application/json,text/plain,*/*"},
    )
    fd, temporary_name = tempfile.mkstemp(prefix=f"{source_id}-", dir=str(destination.parent))
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with urlopen(request, timeout=int(source.get("timeout_seconds", 90))) as response:
            payload = response.read(int(source.get("max_bytes", 80_000_000)))
        if not payload:
            raise ValueError("Empty response")
        temporary.write_bytes(payload)
        _validate_payload(temporary, source)
        if destination.is_file():
            shutil.copy2(destination, destination.with_suffix(destination.suffix + ".lkg"))
        os.replace(temporary, destination)
        row = _source_manifest(source)
        row["sync_status"] = "updated"
        return row
    except Exception as exc:
        return {
            "source_id": source_id,
            "status": "last_known_good" if destination.is_file() else "failed",
            "error": str(exc),
        }
    finally:
        temporary.unlink(missing_ok=True)


def _validate_payload(path: Path, source: dict[str, Any]) -> None:
    payload_type = str(source.get("format") or "json")
    if payload_type == "json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, (dict, list)):
            raise ValueError("JSON root must be an object or array")
        if source.get("family") == "ATT&CK" and not (
            isinstance(payload, dict) and isinstance(payload.get("objects"), list)
        ):
            raise ValueError("ATT&CK source is not a STIX bundle")
    elif payload_type in {"yaml", "yml"}:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, (dict, list)):
            raise ValueError("YAML root must be an object or array")
    elif payload_type == "zip":
        with zipfile.ZipFile(path) as archive:
            if not any(name.lower().endswith(".xml") for name in archive.namelist()):
                raise ValueError("Archive does not contain an XML catalog")
            if archive.testzip() is not None:
                raise ValueError("Archive integrity check failed")
    else:
        if len(path.read_bytes()) < int(source.get("min_bytes", 32)):
            raise ValueError("Downloaded reference is unexpectedly small")


def _record_count(path: Path | None) -> int:
    if path is None or not path.is_file():
        return 0
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            matrix = (payload.get("matrices") or [{}])[0] if isinstance(payload, dict) else {}
            return len(matrix.get("tactics", [])) + len(matrix.get("techniques", []))
        except (OSError, TypeError, ValueError, yaml.YAMLError):
            return 0
    if path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                xml_name = next(name for name in archive.namelist() if name.lower().endswith(".xml"))
                payload = archive.read(xml_name)
            return len(re.findall(br"<(?:\w+:)?(?:Attack_Pattern|Weakness)\b", payload))
        except (OSError, StopIteration, zipfile.BadZipFile):
            return 0
    if path.suffix.lower() not in {".json", ".stix"}:
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        bindings = (
            payload.get("results", {}).get("bindings")
            if isinstance(payload.get("results"), dict)
            else None
        )
        if isinstance(bindings, list):
            return len(bindings)
        for key in ("objects", "techniques", "records", "items"):
            if isinstance(payload.get(key), list):
                return len(payload[key])
        return len(payload)
    return 0


def _version(path: Path | None, source: dict[str, Any]) -> str:
    configured = str(source.get("version") or "rolling")
    if path is None or not path.is_file() or path.suffix.lower() != ".json":
        return configured
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return configured
    if isinstance(payload, dict):
        for key in ("version", "x_mitre_version", "spec_version", "release"):
            if payload.get(key):
                return str(payload[key])
    return configured


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_timestamp(value: datetime | str | None) -> str:
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.isoformat()
    if value:
        return str(value)
    return datetime.now(timezone.utc).isoformat()
