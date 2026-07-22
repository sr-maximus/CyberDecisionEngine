from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"No existe el catálogo: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_catalogs(base_dir: Path | str = "catalogs") -> Dict[str, Dict[str, Any]]:
    base = Path(base_dir)
    return {
        "keywords": load_yaml(base / "keywords.yaml"),
        "risk_weights": load_yaml(base / "risk_weights.yaml"),
        "decision_matrix": load_yaml(base / "decision_matrix.yaml"),
    }
