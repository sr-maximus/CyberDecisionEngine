from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Union

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_path(path: Union[str, Path]) -> Path:
    path_obj = Path(path)
    if path_obj.is_absolute():
        return path_obj
    return PROJECT_ROOT / path_obj


def load_yaml(path: Union[str, Path]) -> Dict[str, Any]:
    resolved = resolve_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"YAML file not found: {resolved}")
    with resolved.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {resolved}")
    return data


def write_yaml(path: Union[str, Path], data: Dict[str, Any]) -> Path:
    resolved = resolve_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
    return resolved


def load_app_config() -> Dict[str, Any]:
    return load_yaml("config/app.yml")


def load_sources_config() -> Dict[str, Any]:
    return load_yaml("config/sources.yml")


def load_frameworks_config() -> Dict[str, Any]:
    return load_yaml("config/frameworks.yml")
