from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import pandas as pd

from .models import Employee
from .privacy import hash_identifier, normalize_column_name, parse_bool, has_valid_consent


COLUMN_ALIASES = {
    "employee_id": {"employee_id", "id_empleado", "id", "codigo", "codigo_empleado"},
    "full_name": {"full_name", "nombre_completo", "nombre", "nombres", "empleado"},
    "personal_email": {"personal_email", "correo_personal", "email_personal"},
    "corporate_email": {"corporate_email", "correo_corporativo", "email_corporativo", "correo_empresa"},
    "identification_document": {"identification_document", "documento", "documento_identificacion", "cedula", "dni", "id_document"},
    "role": {"role", "cargo", "puesto"},
    "department": {"department", "area", "departamento"},
    "organization": {"organization", "organizacion", "empresa", "company"},
    "country": {"country", "pais"},
    "city": {"city", "ciudad"},
    "access_level": {"access_level", "nivel_acceso", "nivel_de_acceso"},
    "access_category": {"access_category", "categoria_acceso", "tipo_formacion", "tipo_informacion", "tipo_de_formacion", "tipo_de_informacion"},
    "consent_status": {"consent_status", "estado_consentimiento", "consentimiento", "autorizacion"},
    "consent_date": {"consent_date", "fecha_consentimiento", "fecha_autorizacion"},
    "authorized_personal_email": {"authorized_personal_email", "autoriza_correo_personal", "usar_correo_personal"},
}

REQUIRED_CANONICAL_COLUMNS = {"employee_id", "full_name", "consent_status"}


def _read_dataframe(input_path: Path) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"No existe el archivo de entrada: {input_path}")
    suffix = input_path.suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(input_path)
    if suffix in {".csv", ".txt"}:
        return pd.read_csv(input_path)
    raise ValueError("Formato no soportado. Usa CSV, XLS o XLSX.")


def _canonicalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    original_to_normalized = {col: normalize_column_name(col) for col in df.columns}
    df = df.rename(columns=original_to_normalized)
    normalized_cols = set(df.columns)

    rename_map = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized_cols:
                rename_map[alias] = canonical
                break
    df = df.rename(columns=rename_map)
    return df


def read_employees(input_path: str | Path, hash_salt: str) -> List[Employee]:
    path = Path(input_path)
    df = _canonicalize_columns(_read_dataframe(path))

    missing = REQUIRED_CANONICAL_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Faltan columnas obligatorias: {', '.join(sorted(missing))}")

    employees: List[Employee] = []
    for _, row in df.fillna("").iterrows():
        raw_doc = row.get("identification_document", "")
        try:
            access_level = int(float(row.get("access_level", 1) or 1))
        except ValueError:
            access_level = 1
        access_level = max(1, min(5, access_level))
        employees.append(
            Employee(
                employee_id=str(row.get("employee_id", "")).strip(),
                full_name=str(row.get("full_name", "")).strip(),
                personal_email=str(row.get("personal_email", "")).strip(),
                corporate_email=str(row.get("corporate_email", "")).strip(),
                identification_document_hash=hash_identifier(raw_doc, hash_salt),
                role=str(row.get("role", "")).strip(),
                department=str(row.get("department", "")).strip(),
                organization=str(row.get("organization", "")).strip(),
                country=str(row.get("country", "")).strip(),
                city=str(row.get("city", "")).strip(),
                access_level=access_level,
                access_category=str(row.get("access_category", "publico")).strip() or "publico",
                consent_status=str(row.get("consent_status", "")).strip(),
                consent_date=str(row.get("consent_date", "")).strip(),
                authorized_personal_email=parse_bool(row.get("authorized_personal_email", False)),
            )
        )
    return employees


def validate_employee_records(employees: List[Employee]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    seen_ids = set()
    for idx, employee in enumerate(employees, start=1):
        prefix = f"Fila {idx} / employee_id={employee.employee_id or 'SIN_ID'}"
        if not employee.employee_id:
            errors.append(f"{prefix}: falta employee_id")
        if employee.employee_id in seen_ids:
            errors.append(f"{prefix}: employee_id duplicado")
        seen_ids.add(employee.employee_id)
        if not employee.full_name:
            errors.append(f"{prefix}: falta full_name")
        if not has_valid_consent(employee.consent_status):
            warnings.append(f"{prefix}: consentimiento no aprobado; el análisis se omitirá")
        if not employee.corporate_email:
            warnings.append(f"{prefix}: falta corporate_email; se reducirá la confianza de identidad")
        if employee.authorized_personal_email and not employee.personal_email:
            warnings.append(f"{prefix}: autoriza correo personal pero no hay personal_email")
    return errors, warnings


def create_template(output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "employee_id",
        "full_name",
        "personal_email",
        "corporate_email",
        "identification_document",
        "role",
        "department",
        "organization",
        "country",
        "city",
        "access_level",
        "access_category",
        "consent_status",
        "consent_date",
        "authorized_personal_email",
    ]
    sample = [[
        "SYN-001",
        "Synthetic Employee 001",
        "employee-001@example.invalid",
        "employee-001@organization.example.invalid",
        "",
        "Security Analyst",
        "Security",
        "Authorized Organization",
        "",
        "",
        4,
        "confidential",
        "approved",
        "2026-01-01",
        True,
    ]]
    df = pd.DataFrame(sample, columns=columns)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="empleados")
        ws = writer.book["empleados"]
        ws.freeze_panes = "A2"
        for col in ws.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            ws.column_dimensions[col[0].column_letter].width = min(max_len + 3, 45)
    return path
