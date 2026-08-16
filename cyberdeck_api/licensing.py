from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from cyberdeck.settings import PROJECT_ROOT
from cyberdeck_api.models import utcnow_iso


LicenseStatus = Literal["active", "trial", "suspended", "expired"]
ControlUserStatus = Literal["active", "inactive"]
ControlRole = Literal["super_admin", "admin", "analyst", "executive", "viewer"]

SELLABLE_MODULES = [
    "overview",
    "dashboards",
    "scenarios",
    "brand",
    "attackSurface",
    "employeeRisk",
    "disinformation",
    "osint",
    "socmint",
    "relationshipGraph",
    "darkweb",
    "frameworks",
    "ai",
    "runs",
    "domains",
    "reports",
    "help",
]

SYSTEM_MODULES_BY_ROLE: dict[str, list[str]] = {
    "super_admin": [*SELLABLE_MODULES, "settings"],
    "admin": ["settings"],
}

MODULE_CATALOG = [
    {
        "key": "overview",
        "group": "strategy",
        "label": {"es": "Vision general", "en": "Overview"},
        "description": {
            "es": "Lectura ejecutiva inicial del estado de inteligencia.",
            "en": "Initial executive readout of the intelligence state.",
        },
    },
    {
        "key": "dashboards",
        "group": "strategy",
        "label": {"es": "Tablero estrategico", "en": "Strategic dashboard"},
        "description": {
            "es": "Riesgo, tendencias, calor geografico, Porter, PESTEL y priorizacion.",
            "en": "Risk, trends, geographic heat, Porter, PESTEL and prioritization.",
        },
    },
    {
        "key": "scenarios",
        "group": "strategy",
        "label": {"es": "Escenarios de decision", "en": "Decision scenarios"},
        "description": {
            "es": "Escenarios accionables mapeados contra MITRE, DISARM y marcos de gobierno.",
            "en": "Actionable scenarios mapped to MITRE, DISARM and governance frameworks.",
        },
    },
    {
        "key": "brand",
        "group": "strategy",
        "label": {"es": "Marca y fraude", "en": "Brand and fraud"},
        "description": {
            "es": "Riesgo reputacional, fraude, suplantacion y menciones externas.",
            "en": "Reputation risk, fraud, impersonation and external mentions.",
        },
    },
    {
        "key": "attackSurface",
        "group": "strategy",
        "label": {"es": "Superficie de ataque", "en": "Attack surface"},
        "description": {
            "es": "WHOIS/RDAP, certificados, exposicion pasiva y comparativos.",
            "en": "WHOIS/RDAP, certificates, passive exposure and comparisons.",
        },
    },
    {
        "key": "employeeRisk",
        "group": "intelligence",
        "label": {"es": "Riesgo virtual de empleados", "en": "Employee virtual risk"},
        "description": {
            "es": "Modulo independiente de exposicion personal autorizada y reporte propio.",
            "en": "Independent authorized personal-exposure module with its own report.",
        },
    },
    {
        "key": "disinformation",
        "group": "intelligence",
        "label": {"es": "Desinformacion", "en": "Disinformation"},
        "description": {
            "es": "Analisis DISARM para operaciones de influencia y narrativa adversaria.",
            "en": "DISARM analysis for influence operations and adversarial narratives.",
        },
    },
    {
        "key": "osint",
        "group": "intelligence",
        "label": {"es": "OSINT", "en": "OSINT"},
        "description": {
            "es": "Busquedas abiertas, dorks defensivos y evidencia publica accionable.",
            "en": "Open searches, defensive dorks and actionable public evidence.",
        },
    },
    {
        "key": "socmint",
        "group": "intelligence",
        "label": {"es": "SOCMINT", "en": "SOCMINT"},
        "description": {
            "es": "Menciones sociales, nodos, aristas, hashtags y comportamiento de tendencia.",
            "en": "Social mentions, nodes, edges, hashtags and trend behavior.",
        },
    },
    {
        "key": "relationshipGraph",
        "group": "intelligence",
        "label": {"es": "Grafo de relaciones", "en": "Relationship graph"},
        "description": {
            "es": "Analisis interactivo de entidades, vinculos, centralidad y evidencia trazable.",
            "en": "Interactive analysis of entities, links, centrality and traceable evidence.",
        },
    },
    {
        "key": "darkweb",
        "group": "intelligence",
        "label": {"es": "Dark Web", "en": "Dark Web"},
        "description": {
            "es": "Revision segura por indices/importaciones autorizadas y senales de exposicion.",
            "en": "Safe review through indexes/authorized imports and exposure signals.",
        },
    },
    {
        "key": "frameworks",
        "group": "governance",
        "label": {"es": "Mapeo de frameworks", "en": "Framework mapping"},
        "description": {
            "es": "NIST, ISO, PCI, SOC, GDPR, MITRE ATT&CK, DEFEND y ATLAS.",
            "en": "NIST, ISO, PCI, SOC, GDPR, MITRE ATT&CK, DEFEND and ATLAS.",
        },
    },
    {
        "key": "ai",
        "group": "strategy",
        "label": {"es": "IA estrategica", "en": "Strategic AI"},
        "description": {
            "es": "Orquestacion segura de prompts, contexto, payloads multi-IA y presupuestos de tokens.",
            "en": "Safe orchestration of prompts, context, multi-AI payloads and token budgets.",
        },
    },
    {
        "key": "runs",
        "group": "operations",
        "label": {"es": "Historial", "en": "Runs"},
        "description": {
            "es": "Ejecuciones, rangos de tiempo, estados y reprocesamiento.",
            "en": "Executions, time windows, status and reprocessing.",
        },
    },
    {
        "key": "domains",
        "group": "operations",
        "label": {"es": "Dominios", "en": "Domains"},
        "description": {
            "es": "Alcance autorizado de dominios y comparativos.",
            "en": "Authorized domain scope and comparisons.",
        },
    },
    {
        "key": "reports",
        "group": "operations",
        "label": {"es": "Informes", "en": "Reports"},
        "description": {
            "es": "Informes directivos y tecnicos descargables.",
            "en": "Downloadable executive and technical reports.",
        },
    },
    {
        "key": "help",
        "group": "operations",
        "label": {"es": "Uso y modelo", "en": "Usage and model"},
        "description": {
            "es": "Guia de uso, teoria, formulas y modelo de decision.",
            "en": "Usage guide, theory, formulas and decision model.",
        },
    },
]

MODULE_KEYS = {item["key"] for item in MODULE_CATALOG}
ALL_MODULES = [*SELLABLE_MODULES, "settings"]

DEFAULT_PLANS = [
    {
        "code": "starter",
        "name": "Starter",
        "description": {
            "es": "Entrada ejecutiva para lectura de riesgo, marca, superficie y reportes.",
            "en": "Executive entry plan for risk, brand, surface and reports.",
        },
        "max_users": 5,
        "modules": ["overview", "dashboards", "brand", "attackSurface", "frameworks", "reports", "help"],
    },
    {
        "code": "professional",
        "name": "Professional",
        "description": {
            "es": "Operacion de cyberinteligencia con OSINT, SOCMINT, DISARM y escenarios.",
            "en": "Cyber intelligence operations with OSINT, SOCMINT, DISARM and scenarios.",
        },
        "max_users": 25,
        "modules": [
            "overview",
            "dashboards",
            "scenarios",
            "brand",
            "attackSurface",
            "disinformation",
            "osint",
            "socmint",
            "relationshipGraph",
            "frameworks",
            "ai",
            "runs",
            "domains",
            "reports",
            "help",
        ],
    },
    {
        "code": "enterprise",
        "name": "Enterprise",
        "description": {
            "es": "Cobertura completa de inteligencia, fraude, dark web y riesgo de empleados.",
            "en": "Full intelligence, fraud, dark-web and employee-risk coverage.",
        },
        "max_users": 100,
        "modules": SELLABLE_MODULES,
    },
    {
        "code": "sovereign",
        "name": "Sovereign",
        "description": {
            "es": "Licencia ampliada para grupos empresariales, uso dedicado y despliegue privado.",
            "en": "Expanded license for business groups, dedicated use and private deployment.",
        },
        "max_users": 500,
        "modules": SELLABLE_MODULES,
    },
]


class ModuleCatalogItem(BaseModel):
    key: str
    group: str
    label: Dict[str, str]
    description: Dict[str, str]


class LicensePlan(BaseModel):
    code: str
    name: str
    description: Dict[str, str]
    max_users: int
    modules: List[str]
    status: Literal["active", "inactive"] = "active"
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)


class LicenseCompany(BaseModel):
    id: str
    name: str
    slug: str
    status: Literal["active", "inactive"] = "active"
    parent_id: Optional[str] = None
    country: str = ""
    sector: str = ""
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)


class CompanyLicense(BaseModel):
    id: str
    company_id: str
    plan_code: str
    status: LicenseStatus = "active"
    seats: int = Field(default=5, ge=1, le=5000)
    starts_at: str = Field(default_factory=lambda: date.today().isoformat())
    expires_at: Optional[str] = None
    modules_override: List[str] = Field(default_factory=list)
    effective_modules: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)


class LicenseControlUser(BaseModel):
    id: str
    company_id: str
    username: str
    full_name: str
    role: ControlRole
    plan_code: Optional[str] = None
    status: ControlUserStatus = "active"
    modules: List[str] = Field(default_factory=list)
    effective_modules: List[str] = Field(default_factory=list)
    created_by: Optional[str] = None
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)


class AuditLogEntry(BaseModel):
    id: str
    actor: str = "system"
    action: str
    target_type: str
    target_id: str
    company_id: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utcnow_iso)


class LicensingOverview(BaseModel):
    generated_at: str = Field(default_factory=utcnow_iso)
    module_catalog: List[ModuleCatalogItem]
    plans: List[LicensePlan]
    companies: List[LicenseCompany]
    licenses: List[CompanyLicense]
    users: List[LicenseControlUser]
    audit_log: List[AuditLogEntry] = Field(default_factory=list)


class CreateCompanyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    parent_id: Optional[str] = None
    country: str = ""
    sector: str = ""
    status: Literal["active", "inactive"] = "active"


class CreateLicenseRequest(BaseModel):
    company_id: str
    plan_code: str
    status: LicenseStatus = "active"
    seats: int = Field(default=5, ge=1, le=5000)
    expires_at: Optional[str] = None
    modules_override: List[str] = Field(default_factory=list)

    @field_validator("modules_override")
    @classmethod
    def modules_are_known(cls, value: List[str]) -> List[str]:
        return _clean_modules(value)


class UpdateLicenseRequest(BaseModel):
    status: Optional[LicenseStatus] = None
    seats: Optional[int] = Field(default=None, ge=1, le=5000)
    expires_at: Optional[str] = None
    modules_override: Optional[List[str]] = None

    @field_validator("modules_override")
    @classmethod
    def update_modules_are_known(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        return _clean_modules(value or []) if value is not None else value


class CreateLicenseUserRequest(BaseModel):
    company_id: str
    username: str = Field(min_length=3, max_length=80)
    full_name: str = Field(min_length=2, max_length=120)
    role: ControlRole = "analyst"
    plan_code: Optional[str] = None
    status: ControlUserStatus = "active"
    modules: List[str] = Field(default_factory=list)
    created_by: Optional[str] = None

    @field_validator("modules")
    @classmethod
    def user_modules_are_known(cls, value: List[str]) -> List[str]:
        return _clean_modules(value)


class UpdateLicenseUserRequest(BaseModel):
    status: Optional[ControlUserStatus] = None
    role: Optional[ControlRole] = None
    plan_code: Optional[str] = None
    modules: Optional[List[str]] = None

    @field_validator("modules")
    @classmethod
    def update_user_modules_are_known(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        return _clean_modules(value or []) if value is not None else value


class LicensingStore:
    def __init__(self, state_path: Optional[Path] = None) -> None:
        self.database_url = os.getenv("DATABASE_URL")
        self.state_path = state_path or PROJECT_ROOT / "data" / "licensing_state.json"
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Optional[asyncio.AbstractEventLoop] = None

    def _active_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    async def load(self) -> None:
        async with self._active_lock():
            await asyncio.to_thread(self._ensure_storage)

    async def overview(self) -> LicensingOverview:
        async with self._active_lock():
            return await asyncio.to_thread(self._overview)

    async def create_company(self, request: CreateCompanyRequest) -> LicensingOverview:
        async with self._active_lock():
            await asyncio.to_thread(self._create_company, request)
            return await asyncio.to_thread(self._overview)

    async def create_license(self, request: CreateLicenseRequest) -> LicensingOverview:
        async with self._active_lock():
            await asyncio.to_thread(self._create_license, request)
            return await asyncio.to_thread(self._overview)

    async def update_license(self, license_id: str, request: UpdateLicenseRequest) -> LicensingOverview:
        async with self._active_lock():
            await asyncio.to_thread(self._update_license, license_id, request)
            return await asyncio.to_thread(self._overview)

    async def create_user(self, request: CreateLicenseUserRequest) -> LicensingOverview:
        async with self._active_lock():
            await asyncio.to_thread(self._create_user, request)
            return await asyncio.to_thread(self._overview)

    async def update_user(self, user_id: str, request: UpdateLicenseUserRequest) -> LicensingOverview:
        async with self._active_lock():
            await asyncio.to_thread(self._update_user, user_id, request)
            return await asyncio.to_thread(self._overview)

    def _ensure_storage(self) -> None:
        if self.database_url:
            self._ensure_postgres()
            return
        self._ensure_json_state()

    def _overview(self) -> LicensingOverview:
        if self.database_url:
            return self._overview_postgres()
        return self._overview_json()

    def _create_company(self, request: CreateCompanyRequest) -> None:
        if self.database_url:
            self._create_company_postgres(request)
            return
        state = self._read_state()
        company = LicenseCompany(
            id=f"company-{uuid4().hex[:12]}",
            name=request.name.strip(),
            slug=_unique_slug(_slugify(request.name), [item["slug"] for item in state["companies"]]),
            parent_id=request.parent_id,
            country=request.country.strip(),
            sector=request.sector.strip(),
            status=request.status,
        )
        state["companies"].append(company.model_dump(mode="json"))
        _append_audit(state, "ui", "company.create", "company", company.id, company.id, {"name": company.name, "parent_id": company.parent_id})
        self._write_state(state)

    def _create_license(self, request: CreateLicenseRequest) -> None:
        if self.database_url:
            self._create_license_postgres(request)
            return
        state = self._read_state()
        _require_company(state, request.company_id)
        _require_plan(state, request.plan_code)
        license_item = CompanyLicense(
            id=f"license-{uuid4().hex[:12]}",
            company_id=request.company_id,
            plan_code=request.plan_code,
            status=request.status,
            seats=request.seats,
            expires_at=request.expires_at,
            modules_override=request.modules_override,
        )
        state["licenses"].append(license_item.model_dump(mode="json"))
        _append_audit(
            state,
            "ui",
            "license.create",
            "license",
            license_item.id,
            license_item.company_id,
            {"plan_code": license_item.plan_code, "status": license_item.status, "seats": license_item.seats},
        )
        self._write_state(state)

    def _update_license(self, license_id: str, request: UpdateLicenseRequest) -> None:
        if self.database_url:
            self._update_license_postgres(license_id, request)
            return
        state = self._read_state()
        for item in state["licenses"]:
            if item["id"] == license_id:
                if request.status is not None:
                    item["status"] = request.status
                if request.seats is not None:
                    item["seats"] = request.seats
                if request.expires_at is not None:
                    item["expires_at"] = request.expires_at
                if request.modules_override is not None:
                    item["modules_override"] = request.modules_override
                item["updated_at"] = utcnow_iso()
                _append_audit(state, "ui", "license.update", "license", license_id, item["company_id"], request.model_dump(exclude_none=True))
                self._write_state(state)
                return
        raise ValueError("License not found.")

    def _create_user(self, request: CreateLicenseUserRequest) -> None:
        if self.database_url:
            self._create_user_postgres(request)
            return
        state = self._read_state()
        _require_company(state, request.company_id)
        if request.plan_code:
            _require_plan(state, request.plan_code)
        if any(item["username"].lower() == request.username.lower().strip() for item in state["users"]):
            raise ValueError("User already exists.")
        user = LicenseControlUser(
            id=f"user-{uuid4().hex[:12]}",
            company_id=request.company_id,
            username=request.username.lower().strip(),
            full_name=request.full_name.strip(),
            role=request.role,
            plan_code=request.plan_code,
            status=request.status,
            modules=request.modules,
            created_by=request.created_by,
        )
        state["users"].append(user.model_dump(mode="json"))
        _append_audit(
            state,
            request.created_by or "ui",
            "user.create",
            "user",
            user.id,
            user.company_id,
            {"username": user.username, "role": user.role, "plan_code": user.plan_code},
        )
        self._write_state(state)

    def _update_user(self, user_id: str, request: UpdateLicenseUserRequest) -> None:
        if self.database_url:
            self._update_user_postgres(user_id, request)
            return
        state = self._read_state()
        for item in state["users"]:
            if item["id"] == user_id:
                if request.status is not None:
                    item["status"] = request.status
                if request.role is not None:
                    item["role"] = request.role
                if request.plan_code is not None:
                    if request.plan_code:
                        _require_plan(state, request.plan_code)
                    item["plan_code"] = request.plan_code or None
                if request.modules is not None:
                    item["modules"] = request.modules
                item["updated_at"] = utcnow_iso()
                _append_audit(state, "ui", "user.update", "user", user_id, item["company_id"], request.model_dump(exclude_none=True))
                self._write_state(state)
                return
        raise ValueError("User not found.")

    def _ensure_postgres(self) -> None:
        import psycopg

        with psycopg.connect(self.database_url) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_companies (
                    id TEXT PRIMARY KEY,
                    parent_id TEXT REFERENCES license_companies(id) ON DELETE SET NULL,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    country TEXT NOT NULL DEFAULT '',
                    sector TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_plans (
                    code TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description JSONB NOT NULL,
                    max_users INTEGER NOT NULL,
                    modules JSONB NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_assignments (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL REFERENCES license_companies(id) ON DELETE CASCADE,
                    plan_code TEXT NOT NULL REFERENCES license_plans(code),
                    status TEXT NOT NULL DEFAULT 'active',
                    seats INTEGER NOT NULL,
                    starts_at DATE NOT NULL DEFAULT CURRENT_DATE,
                    expires_at DATE,
                    modules_override JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_control_users (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL REFERENCES license_companies(id) ON DELETE CASCADE,
                    username TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    plan_code TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    modules JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute("ALTER TABLE license_control_users ADD COLUMN IF NOT EXISTS plan_code TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_audit_log (
                    id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL DEFAULT 'system',
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    company_id TEXT,
                    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_companies_parent ON license_companies(parent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_users_company ON license_control_users(company_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_assignments_company ON license_assignments(company_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_created ON license_audit_log(created_at DESC)")
            with conn.cursor() as cur:
                for plan in DEFAULT_PLANS:
                    cur.execute(
                        """
                        INSERT INTO license_plans (code, name, description, max_users, modules, status, updated_at)
                        VALUES (%s, %s, %s::jsonb, %s, %s::jsonb, 'active', now())
                        ON CONFLICT (code) DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            max_users = EXCLUDED.max_users,
                            modules = EXCLUDED.modules,
                            status = 'active',
                            updated_at = now()
                        """,
                        (plan["code"], plan["name"], json.dumps(plan["description"]), plan["max_users"], json.dumps(plan["modules"])),
                    )
                cur.execute(
                    """
                    INSERT INTO license_companies (id, name, slug, status, country, sector)
                    VALUES ('company-cde-root', 'CyberDecisionEngine Control Plane', 'cyberdecisionengine-root', 'active', '', 'Cyberintelligence')
                    ON CONFLICT (id) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO license_assignments (id, company_id, plan_code, status, seats, expires_at, modules_override)
                    VALUES ('license-cde-root-sovereign', 'company-cde-root', 'sovereign', 'active', 25, NULL, '[]'::jsonb)
                    ON CONFLICT (id) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO license_audit_log (id, actor, action, target_type, target_id, company_id, detail)
                    SELECT 'audit-bootstrap-control-plane', 'system', 'system.bootstrap', 'platform', 'cyberdecisionengine', 'company-cde-root', '{"scope":"licensing_control_plane"}'::jsonb
                    WHERE NOT EXISTS (SELECT 1 FROM license_audit_log WHERE id = 'audit-bootstrap-control-plane')
                    """
                )
            conn.commit()

    def _overview_postgres(self) -> LicensingOverview:
        import psycopg

        with psycopg.connect(self.database_url) as conn:
            self._ensure_postgres()
            plans = [
                LicensePlan(
                    code=row[0],
                    name=row[1],
                    description=_json_value(row[2]),
                    max_users=row[3],
                    modules=_json_value(row[4]),
                    status=row[5],
                    created_at=_iso(row[6]),
                    updated_at=_iso(row[7]),
                )
                for row in conn.execute(
                    "SELECT code, name, description, max_users, modules, status, created_at, updated_at FROM license_plans ORDER BY max_users"
                ).fetchall()
            ]
            companies = [
                LicenseCompany(
                    id=row[0],
                    parent_id=row[1],
                    name=row[2],
                    slug=row[3],
                    status=row[4],
                    country=row[5],
                    sector=row[6],
                    created_at=_iso(row[7]),
                    updated_at=_iso(row[8]),
                )
                for row in conn.execute(
                    """
                    SELECT id, parent_id, name, slug, status, country, sector, created_at, updated_at
                    FROM license_companies
                    ORDER BY parent_id NULLS FIRST, name
                    """
                ).fetchall()
            ]
            licenses = [
                CompanyLicense(
                    id=row[0],
                    company_id=row[1],
                    plan_code=row[2],
                    status=_effective_license_status(row[3], row[6]),
                    seats=row[4],
                    starts_at=_date_iso(row[5]),
                    expires_at=_date_iso(row[6]) if row[6] else None,
                    modules_override=_json_value(row[7]),
                    created_at=_iso(row[8]),
                    updated_at=_iso(row[9]),
                )
                for row in conn.execute(
                    """
                    SELECT id, company_id, plan_code, status, seats, starts_at, expires_at, modules_override, created_at, updated_at
                    FROM license_assignments
                    ORDER BY created_at DESC
                    """
                ).fetchall()
            ]
            users = [
                LicenseControlUser(
                    id=row[0],
                    company_id=row[1],
                    username=row[2],
                    full_name=row[3],
                    role=row[4],
                    plan_code=row[5],
                    status=row[6],
                    modules=_json_value(row[7]),
                    created_by=row[8],
                    created_at=_iso(row[9]),
                    updated_at=_iso(row[10]),
                )
                for row in conn.execute(
                    """
                    SELECT id, company_id, username, full_name, role, plan_code, status, modules, created_by, created_at, updated_at
                    FROM license_control_users
                    ORDER BY role, full_name
                    """
                ).fetchall()
            ]
            audit_log = [
                AuditLogEntry(
                    id=row[0],
                    actor=row[1],
                    action=row[2],
                    target_type=row[3],
                    target_id=row[4],
                    company_id=row[5],
                    detail=_json_value(row[6]),
                    created_at=_iso(row[7]),
                )
                for row in conn.execute(
                    """
                    SELECT id, actor, action, target_type, target_id, company_id, detail, created_at
                    FROM license_audit_log
                    ORDER BY created_at DESC
                    LIMIT 80
                    """
                ).fetchall()
            ]
        return _enrich_overview(plans, companies, licenses, users, audit_log)

    def _create_company_postgres(self, request: CreateCompanyRequest) -> None:
        import psycopg

        with psycopg.connect(self.database_url) as conn:
            slugs = [row[0] for row in conn.execute("SELECT slug FROM license_companies").fetchall()]
            company_id = f"company-{uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO license_companies (id, parent_id, name, slug, status, country, sector)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    company_id,
                    request.parent_id,
                    request.name.strip(),
                    _unique_slug(_slugify(request.name), slugs),
                    request.status,
                    request.country.strip(),
                    request.sector.strip(),
                ),
            )
            _audit_conn(conn, "ui", "company.create", "company", company_id, company_id, {"name": request.name.strip(), "parent_id": request.parent_id})
            conn.commit()

    def _create_license_postgres(self, request: CreateLicenseRequest) -> None:
        import psycopg

        with psycopg.connect(self.database_url) as conn:
            if not conn.execute("SELECT 1 FROM license_companies WHERE id = %s", (request.company_id,)).fetchone():
                raise ValueError("Company not found.")
            if not conn.execute("SELECT 1 FROM license_plans WHERE code = %s", (request.plan_code,)).fetchone():
                raise ValueError("Plan not found.")
            license_id = f"license-{uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO license_assignments (id, company_id, plan_code, status, seats, expires_at, modules_override)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    license_id,
                    request.company_id,
                    request.plan_code,
                    request.status,
                    request.seats,
                    request.expires_at,
                    json.dumps(request.modules_override),
                ),
            )
            _audit_conn(conn, "ui", "license.create", "license", license_id, request.company_id, {"plan_code": request.plan_code, "status": request.status, "seats": request.seats})
            conn.commit()

    def _update_license_postgres(self, license_id: str, request: UpdateLicenseRequest) -> None:
        import psycopg

        fields = []
        values: list[Any] = []
        if request.status is not None:
            fields.append("status = %s")
            values.append(request.status)
        if request.seats is not None:
            fields.append("seats = %s")
            values.append(request.seats)
        if request.expires_at is not None:
            fields.append("expires_at = %s")
            values.append(request.expires_at)
        if request.modules_override is not None:
            fields.append("modules_override = %s::jsonb")
            values.append(json.dumps(request.modules_override))
        if not fields:
            return
        values.append(license_id)
        with psycopg.connect(self.database_url) as conn:
            result = conn.execute(
                f"UPDATE license_assignments SET {', '.join(fields)}, updated_at = now() WHERE id = %s",
                values,
            )
            if result.rowcount == 0:
                raise ValueError("License not found.")
            company_row = conn.execute("SELECT company_id FROM license_assignments WHERE id = %s", (license_id,)).fetchone()
            _audit_conn(conn, "ui", "license.update", "license", license_id, company_row[0] if company_row else None, request.model_dump(exclude_none=True))
            conn.commit()

    def _create_user_postgres(self, request: CreateLicenseUserRequest) -> None:
        import psycopg

        with psycopg.connect(self.database_url) as conn:
            if not conn.execute("SELECT 1 FROM license_companies WHERE id = %s", (request.company_id,)).fetchone():
                raise ValueError("Company not found.")
            if request.plan_code and not conn.execute("SELECT 1 FROM license_plans WHERE code = %s", (request.plan_code,)).fetchone():
                raise ValueError("Plan not found.")
            if conn.execute("SELECT 1 FROM license_control_users WHERE lower(username) = lower(%s)", (request.username.strip(),)).fetchone():
                raise ValueError("User already exists.")
            user_id = f"user-{uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO license_control_users (id, company_id, username, full_name, role, plan_code, status, modules, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                """,
                (
                    user_id,
                    request.company_id,
                    request.username.lower().strip(),
                    request.full_name.strip(),
                    request.role,
                    request.plan_code,
                    request.status,
                    json.dumps(request.modules),
                    request.created_by,
                ),
            )
            _audit_conn(conn, request.created_by or "ui", "user.create", "user", user_id, request.company_id, {"username": request.username.lower().strip(), "role": request.role, "plan_code": request.plan_code})
            conn.commit()

    def _update_user_postgres(self, user_id: str, request: UpdateLicenseUserRequest) -> None:
        import psycopg

        fields = []
        values: list[Any] = []
        if request.status is not None:
            fields.append("status = %s")
            values.append(request.status)
        if request.role is not None:
            fields.append("role = %s")
            values.append(request.role)
        if request.plan_code is not None:
            fields.append("plan_code = %s")
            values.append(request.plan_code or None)
        if request.modules is not None:
            fields.append("modules = %s::jsonb")
            values.append(json.dumps(request.modules))
        if not fields:
            return
        values.append(user_id)
        with psycopg.connect(self.database_url) as conn:
            if request.plan_code and not conn.execute("SELECT 1 FROM license_plans WHERE code = %s", (request.plan_code,)).fetchone():
                raise ValueError("Plan not found.")
            result = conn.execute(
                f"UPDATE license_control_users SET {', '.join(fields)}, updated_at = now() WHERE id = %s",
                values,
            )
            if result.rowcount == 0:
                raise ValueError("User not found.")
            company_row = conn.execute("SELECT company_id FROM license_control_users WHERE id = %s", (user_id,)).fetchone()
            _audit_conn(conn, "ui", "user.update", "user", user_id, company_row[0] if company_row else None, request.model_dump(exclude_none=True))
            conn.commit()

    def _ensure_json_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            state = self._read_state()
        else:
            state = {"plans": [], "companies": [], "licenses": [], "users": [], "audit_log": []}
        state = _seed_state(state)
        self._write_state(state)

    def _overview_json(self) -> LicensingOverview:
        state = _seed_state(self._read_state())
        return _enrich_overview(
            [LicensePlan(**item) for item in state["plans"]],
            [LicenseCompany(**item) for item in state["companies"]],
            [CompanyLicense(**item) for item in state["licenses"]],
            [LicenseControlUser(**item) for item in state["users"]],
            [AuditLogEntry(**item) for item in state.get("audit_log", [])][-80:],
        )

    def _read_state(self) -> Dict[str, list[dict[str, Any]]]:
        if not self.state_path.exists():
            return {"plans": [], "companies": [], "licenses": [], "users": [], "audit_log": []}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_state(self, state: Dict[str, list[dict[str, Any]]]) -> None:
        tmp_path = self.state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.replace(self.state_path)


def _enrich_overview(
    plans: List[LicensePlan],
    companies: List[LicenseCompany],
    licenses: List[CompanyLicense],
    users: List[LicenseControlUser],
    audit_log: Optional[List[AuditLogEntry]] = None,
) -> LicensingOverview:
    plan_modules = {plan.code: plan.modules for plan in plans}
    company_modules: dict[str, set[str]] = {}
    for license_item in licenses:
        effective_modules = license_item.modules_override or plan_modules.get(license_item.plan_code, [])
        license_item.effective_modules = _clean_modules(effective_modules)
        if license_item.status in {"active", "trial"}:
            company_modules.setdefault(license_item.company_id, set()).update(license_item.effective_modules)

    for user in users:
        inherited = company_modules.get(user.company_id, set())
        specific = set(user.modules)
        user_plan_modules = set(plan_modules.get(user.plan_code or "", []))
        effective = set(ALL_MODULES if user.role == "super_admin" else (specific or user_plan_modules or inherited))
        effective.update(SYSTEM_MODULES_BY_ROLE.get(user.role, []))
        user.effective_modules = [module for module in ALL_MODULES if module in effective]

    return LicensingOverview(
        module_catalog=[ModuleCatalogItem(**item) for item in MODULE_CATALOG],
        plans=plans,
        companies=companies,
        licenses=licenses,
        users=users,
        audit_log=audit_log or [],
    )


def _seed_state(state: Dict[str, list[dict[str, Any]]]) -> Dict[str, list[dict[str, Any]]]:
    state.setdefault("plans", [])
    state.setdefault("companies", [])
    state.setdefault("licenses", [])
    state.setdefault("users", [])
    state.setdefault("audit_log", [])
    existing_plans = {item["code"] for item in state["plans"]}
    for plan in DEFAULT_PLANS:
        if plan["code"] not in existing_plans:
            state["plans"].append(LicensePlan(**plan).model_dump(mode="json"))
            continue
        for item in state["plans"]:
            if item["code"] == plan["code"]:
                item["name"] = plan["name"]
                item["description"] = plan["description"]
                item["max_users"] = plan["max_users"]
                item["modules"] = plan["modules"]
                item["status"] = "active"
                item["updated_at"] = utcnow_iso()
                break
    if not any(item["id"] == "company-cde-root" for item in state["companies"]):
        state["companies"].append(
            LicenseCompany(
                id="company-cde-root",
                name="CyberDecisionEngine Control Plane",
                slug="cyberdecisionengine-root",
                country="",
                sector="Cyberintelligence",
            ).model_dump(mode="json")
        )
    if not any(item["id"] == "license-cde-root-sovereign" for item in state["licenses"]):
        state["licenses"].append(
            CompanyLicense(
                id="license-cde-root-sovereign",
                company_id="company-cde-root",
                plan_code="sovereign",
                seats=25,
            ).model_dump(mode="json")
        )
    if not any(item["id"] == "audit-bootstrap-control-plane" for item in state["audit_log"]):
        state["audit_log"].append(
            AuditLogEntry(
                id="audit-bootstrap-control-plane",
                actor="system",
                action="system.bootstrap",
                target_type="platform",
                target_id="cyberdecisionengine",
                company_id="company-cde-root",
                detail={"scope": "licensing_control_plane"},
            ).model_dump(mode="json")
        )
    return state


def _clean_modules(value: List[str]) -> List[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for module in value:
        if module not in MODULE_KEYS or module in seen:
            continue
        seen.add(module)
        cleaned.append(module)
    return cleaned


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or f"company-{uuid4().hex[:8]}"


def _unique_slug(slug: str, existing: List[str]) -> str:
    if slug not in existing:
        return slug
    index = 2
    while f"{slug}-{index}" in existing:
        index += 1
    return f"{slug}-{index}"


def _require_company(state: Dict[str, list[dict[str, Any]]], company_id: str) -> None:
    if not any(item["id"] == company_id for item in state["companies"]):
        raise ValueError("Company not found.")


def _require_plan(state: Dict[str, list[dict[str, Any]]], plan_code: str) -> None:
    if not any(item["code"] == plan_code for item in state["plans"]):
        raise ValueError("Plan not found.")


def _append_audit(
    state: Dict[str, list[dict[str, Any]]],
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    company_id: Optional[str],
    detail: Dict[str, Any],
) -> None:
    state.setdefault("audit_log", [])
    state["audit_log"].append(
        AuditLogEntry(
            id=f"audit-{uuid4().hex[:12]}",
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            company_id=company_id,
            detail=detail,
        ).model_dump(mode="json")
    )
    state["audit_log"] = state["audit_log"][-200:]


def _audit_conn(conn: Any, actor: str, action: str, target_type: str, target_id: str, company_id: Optional[str], detail: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO license_audit_log (id, actor, action, target_type, target_id, company_id, detail)
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
        """,
        (f"audit-{uuid4().hex[:12]}", actor, action, target_type, target_id, company_id, json.dumps(detail, sort_keys=True)),
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _date_iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _effective_license_status(status: str, expires_at: Any) -> str:
    if expires_at and _date_iso(expires_at) < date.today().isoformat():
        return "expired"
    return status
