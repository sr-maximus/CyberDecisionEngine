from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

from .models import QuerySpec, SearchResult


DEFAULT_DIMENSION_KEY = "digital_identity_discovery"
DEFAULT_DIMENSION_LABEL = "Descubrimiento de identidad digital"


def _read_dataframe(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo de resultados manuales: {path}")
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    if path.suffix.lower() in {".csv", ".txt"}:
        return pd.read_csv(path)
    raise ValueError("Los resultados manuales deben estar en CSV/XLS/XLSX")


def load_manual_results(path: str | Path) -> Dict[str, List[Tuple[QuerySpec, SearchResult]]]:
    """Carga resultados recolectados manualmente desde Google u otro buscador.

    Columnas mínimas: employee_id, url.
    Columnas opcionales: title, snippet, query, keyword, dimension_key, dimension_label, query_type, source.
    """
    df = _read_dataframe(Path(path)).fillna("")
    if "employee_id" not in df.columns or "url" not in df.columns:
        raise ValueError("El archivo de resultados manuales requiere columnas employee_id y url")

    by_employee: Dict[str, List[Tuple[QuerySpec, SearchResult]]] = {}
    for _, row in df.iterrows():
        employee_id = str(row.get("employee_id", "")).strip()
        url = str(row.get("url", "")).strip()
        if not employee_id or not url:
            continue
        query = str(row.get("query", "manual_import")).strip() or "manual_import"
        dimension_key = str(row.get("dimension_key", DEFAULT_DIMENSION_KEY)).strip() or DEFAULT_DIMENSION_KEY
        dimension_label = str(row.get("dimension_label", DEFAULT_DIMENSION_LABEL)).strip() or DEFAULT_DIMENSION_LABEL
        keyword = str(row.get("keyword", "manual_seed")).strip() or "manual_seed"
        query_type = str(row.get("query_type", "manual_result")).strip() or "manual_result"
        title = str(row.get("title", "Resultado importado manualmente")).strip() or "Resultado importado manualmente"
        snippet = str(row.get("snippet", "")).strip()
        source = str(row.get("source", "manual_import")).strip() or "manual_import"
        spec = QuerySpec(
            query=query,
            employee_id=employee_id,
            dimension_key=dimension_key,
            dimension_label=dimension_label,
            keyword=keyword,
            query_type=query_type,
        )
        result = SearchResult(
            query=query,
            url=url,
            title=title,
            snippet=snippet,
            source=source,
        )
        by_employee.setdefault(employee_id, []).append((spec, result))
    return by_employee
