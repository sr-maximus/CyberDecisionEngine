from __future__ import annotations

import ast
import csv
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_ENV_KEY = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|API_ID|USERNAME|USER|HASH_SALT)$"
)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _env_values(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in _read(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def test_public_env_examples_do_not_publish_credentials():
    for path in (
        ".env.example",
        "integrations/employee_virtual_risk_osint/.env.example",
    ):
        exposed = {
            key: value
            for key, value in _env_values(path).items()
            if SENSITIVE_ENV_KEY.search(key) and value
        }
        assert exposed == {}


def test_public_auth_has_no_seeded_accounts_or_password_hashes():
    auth_source = _read("web/src/data/auth.ts")
    licensing_source = _read("cyberdeck_api/licensing.py")
    licensing_tree = ast.parse(licensing_source)
    seed_function = next(
        node
        for node in licensing_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_seed_state"
    )
    seed_source = ast.get_source_segment(licensing_source, seed_function) or ""

    assert "seededUsers" not in auth_source
    password_literal = r"passwordHash\s*:\s*[\"'][0-9a-fA-F]{64}[\"']"
    assert re.search(password_literal, auth_source) is None
    assert "LicenseControlUser(" not in seed_source
    assert "password_hash=" not in seed_source


def test_public_access_instructions_require_direct_contact():
    login_source = _read("web/src/components/LoginView.tsx")
    readme = _read("README.md")

    assert 'const ACCESS_REQUEST_URL = `mailto:${ACCESS_REQUEST_EMAIL}' in login_source
    assert "edwinjavpenuela@gmail.com" in login_source
    assert "edwinjavpenuela@gmail.com" in readme
    assert "solicitarse al propietario" in readme.lower()
    assert "no incluyen usuarios, contraseñas ni" in readme.lower()


def test_public_organization_profile_is_generic_and_has_no_domain():
    profile = yaml.safe_load(_read("config/orgs/example_organization.yml"))
    organization = profile["organization"]

    assert organization["name"] == "Organization Under Assessment"
    assert organization["country"] == "ZZ"
    assert not any("domain" in key.lower() for key in organization)


def test_employee_examples_are_synthetic_and_do_not_include_identifiers():
    fixtures = (
        "integrations/employee_virtual_risk_osint/data/input/sample_employees.csv",
        "integrations/employee_virtual_risk_osint/data/input/nombres_autorizados.csv",
    )
    for fixture in fixtures:
        with (ROOT / fixture).open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows
        for row in rows:
            assert row["full_name"].startswith("Synthetic ")
            assert row["identification_document"] == ""
            for field in ("personal_email", "corporate_email"):
                assert not row[field] or row[field].endswith(".invalid")


def test_private_generated_outputs_are_not_part_of_the_public_tree():
    assert sorted(path.name for path in (ROOT / "artifacts").iterdir()) == ["README.md"]
    assert sorted(path.name for path in (ROOT / "docs/design").iterdir()) == ["README.md"]
    assert list((ROOT / "docs/auditoria/00-evidencia-visual").glob("*.png")) == []
    assert list((ROOT / "docs/manual").glob("*.docx")) == []
    assert list((ROOT / "reports").glob("*.docx")) == []
