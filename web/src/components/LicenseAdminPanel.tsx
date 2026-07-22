import { BadgeCheck, Building2, KeyRound, Plus, RefreshCw, ShieldCheck, ShieldOff, UsersRound } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import {
  createCompanyLicense,
  createLicenseCompany,
  createLicenseUser,
  getLicensingOverview,
  updateCompanyLicense,
  updateLicenseUser
} from "../api";
import { ALL_SECTORS, economicSectors, localizedSectorLabel, selectedWithoutAll } from "../data/catalog";
import { createLocalUser, hashPassword, roleLabelsByLanguage } from "../data/auth";
import type { LanguageMode, LicenseCompany, LicensingOverview, LocalUser, UserRole, ViewKey } from "../types";

interface LicenseAdminPanelProps {
  currentUser: LocalUser;
  users: LocalUser[];
  language: LanguageMode;
  onUsersChange: (users: LocalUser[]) => void;
}

const copy = {
  es: {
    title: "Licenciamiento y empresas",
    text: "Gobierno comercial para operar por empresa, plan, usuarios y acceso modular a menús.",
    refresh: "Sincronizar acceso",
    companies: "Empresas",
    users: "Usuarios",
    activeLicenses: "Licencias activas",
    modules: "Módulos",
    planByUser: "Plan por usuario",
    accessLog: "Bitácora de cambios",
    tree: "Árbol empresarial",
    treeText: "Estructura padre-hijo para grupos, filiales o clientes finales.",
    plans: "Planes comerciales",
    createCompany: "Crear empresa",
    assignLicense: "Asignar licencia",
    createUser: "Crear usuario de empresa",
    name: "Nombre",
    country: "País",
    sector: "Sector(es)",
    allSectors: "Todos los sectores",
    sectorHint: "Selecciona uno o varios sectores",
    parent: "Empresa padre",
    noParent: "Sin padre",
    company: "Empresa",
    plan: "Plan",
    seats: "Usuarios incluidos",
    expiration: "Vence opcional",
    role: "Rol",
    username: "usuario",
    fullName: "nombre completo",
    password: "contraseña temporal",
    inherited: "Hereda plan",
    inheritCompany: "Heredar empresa",
    moduleOverride: "Ajuste modular",
    create: "Crear",
    assign: "Asignar",
    active: "Activa",
    trial: "Prueba",
    suspended: "Suspendida",
    expired: "Expirada",
    inactive: "Inactivo",
    activate: "Activar",
    suspend: "Suspender",
    deactivate: "Desactivar",
    reactivate: "Reactivar",
    adminOnly: "Un admin de empresa solo puede crear analistas, directivos o lectores de su empresa.",
    superOnly: "Solo el super admin puede crear empresas y asignar licencias.",
    empty: "Aún no hay datos de licenciamiento.",
    required: "Completa los campos requeridos.",
    weakPassword: "La contraseña temporal debe tener al menos 12 caracteres.",
    saved: "Cambio guardado.",
    error: "No se pudo actualizar licenciamiento.",
    roleOptions: {
      admin: "Administrador de empresa",
      analyst: "Analista",
      executive: "Directivo",
      viewer: "Lector"
    }
  },
  en: {
    title: "Licensing and companies",
    text: "Commercial governance to operate by company, plan, users and modular menu access.",
    refresh: "Sync access",
    companies: "Companies",
    users: "Users",
    activeLicenses: "Active licenses",
    modules: "Modules",
    planByUser: "User plan",
    accessLog: "Change log",
    tree: "Company tree",
    treeText: "Parent-child structure for groups, subsidiaries or end customers.",
    plans: "Commercial plans",
    createCompany: "Create company",
    assignLicense: "Assign license",
    createUser: "Create company user",
    name: "Name",
    country: "Country",
    sector: "Sector(s)",
    allSectors: "All sectors",
    sectorHint: "Select one or multiple sectors",
    parent: "Parent company",
    noParent: "No parent",
    company: "Company",
    plan: "Plan",
    seats: "Included users",
    expiration: "Optional expiration",
    role: "Role",
    username: "username",
    fullName: "full name",
    password: "temporary password",
    inherited: "Inherits plan",
    inheritCompany: "Inherit company",
    moduleOverride: "Module override",
    create: "Create",
    assign: "Assign",
    active: "Active",
    trial: "Trial",
    suspended: "Suspended",
    expired: "Expired",
    inactive: "Inactive",
    activate: "Activate",
    suspend: "Suspend",
    deactivate: "Deactivate",
    reactivate: "Reactivate",
    adminOnly: "A company admin can only create analysts, executives or readers for their company.",
    superOnly: "Only the super admin can create companies and assign licenses.",
    empty: "No licensing data yet.",
    required: "Complete the required fields.",
    weakPassword: "Temporary password must be at least 12 characters.",
    saved: "Change saved.",
    error: "Unable to update licensing.",
    roleOptions: {
      admin: "Company administrator",
      analyst: "Analyst",
      executive: "Executive",
      viewer: "Viewer"
    }
  }
};

export function LicenseAdminPanel({ currentUser, users, language, onUsersChange }: LicenseAdminPanelProps) {
  const labels = copy[language];
  const isSuperAdmin = currentUser.role === "super_admin";
  const [overview, setOverview] = useState<LicensingOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [companyDraft, setCompanyDraft] = useState({ name: "", parent_id: "", country: "", sectors: [] as string[] });
  const [licenseDraft, setLicenseDraft] = useState({ company_id: currentUser.companyId ?? "", plan_code: "professional", seats: 10, expires_at: "", modules_override: [] as ViewKey[] });
  const [userDraft, setUserDraft] = useState({
    company_id: currentUser.companyId ?? "",
    username: "",
    full_name: "",
    password: "",
    role: "analyst" as UserRole,
    plan_code: "",
    modules: [] as ViewKey[]
  });

  useEffect(() => {
    void refresh();
  }, []);

  const allowedCompanies = useMemo(() => {
    if (!overview) return [];
    if (isSuperAdmin) return overview.companies;
    return overview.companies.filter((company) => company.id === currentUser.companyId);
  }, [currentUser.companyId, isSuperAdmin, overview]);

  const companyById = useMemo(() => new Map((overview?.companies ?? []).map((company) => [company.id, company])), [overview]);
  const licensesByCompany = useMemo(() => groupBy(overview?.licenses ?? [], "company_id"), [overview]);
  const usersByCompany = useMemo(() => groupBy(overview?.users ?? [], "company_id"), [overview]);

  async function refresh() {
    setLoading(true);
    try {
      const next = await getLicensingOverview();
      setOverview(next);
      const firstCompany = currentUser.companyId ?? next.companies[0]?.id ?? "";
      setLicenseDraft((draft) => ({ ...draft, company_id: draft.company_id || firstCompany }));
      setUserDraft((draft) => ({ ...draft, company_id: draft.company_id || firstCompany }));
      setMessage(null);
    } catch (exc) {
      setMessage(exc instanceof Error ? exc.message : labels.error);
    } finally {
      setLoading(false);
    }
  }

  async function createCompany() {
    if (!isSuperAdmin) {
      setMessage(labels.superOnly);
      return;
    }
    if (!companyDraft.name.trim()) {
      setMessage(labels.required);
      return;
    }
    await runMutation(() =>
      createLicenseCompany({
        name: companyDraft.name.trim(),
        parent_id: companyDraft.parent_id || null,
        country: companyDraft.country.trim(),
        sector: selectedWithoutAll(companyDraft.sectors, ALL_SECTORS).join(", ") || ALL_SECTORS
      })
    );
    setCompanyDraft({ name: "", parent_id: "", country: "", sectors: [] });
  }

  async function assignLicense() {
    if (!isSuperAdmin) {
      setMessage(labels.superOnly);
      return;
    }
    if (!licenseDraft.company_id || !licenseDraft.plan_code) {
      setMessage(labels.required);
      return;
    }
    await runMutation(() =>
      createCompanyLicense({
        company_id: licenseDraft.company_id,
        plan_code: licenseDraft.plan_code,
        seats: Number(licenseDraft.seats) || 1,
        expires_at: licenseDraft.expires_at || null,
        modules_override: licenseDraft.modules_override
      })
    );
    setLicenseDraft((draft) => ({ ...draft, expires_at: "", modules_override: [] }));
  }

  async function createUser() {
    if (!userDraft.company_id || !userDraft.username.trim() || !userDraft.full_name.trim() || !userDraft.password.trim()) {
      setMessage(labels.required);
      return;
    }
    if (userDraft.password.length < 12) {
      setMessage(labels.weakPassword);
      return;
    }
    if (!isSuperAdmin && (userDraft.role === "super_admin" || userDraft.role === "admin")) {
      setMessage(labels.adminOnly);
      return;
    }
    if (!isSuperAdmin && userDraft.company_id !== currentUser.companyId) {
      setMessage(labels.adminOnly);
      return;
    }
    const nextOverview = await runMutation(() =>
      createLicenseUser({
        company_id: userDraft.company_id,
        username: userDraft.username.trim(),
        full_name: userDraft.full_name.trim(),
        role: userDraft.role,
        plan_code: userDraft.plan_code || null,
        modules: userDraft.modules,
        created_by: currentUser.username
      })
    );
    if (nextOverview && !users.some((user) => user.username.toLowerCase() === userDraft.username.trim().toLowerCase())) {
      const controlUser = nextOverview.users.find((user) => user.username.toLowerCase() === userDraft.username.trim().toLowerCase());
      const company = nextOverview.companies.find((item) => item.id === userDraft.company_id);
      const localUser = createLocalUser({
        username: userDraft.username.trim(),
        fullName: userDraft.full_name.trim(),
        passwordHash: await hashPassword(userDraft.password),
        role: userDraft.role,
        companyId: userDraft.company_id,
        companyName: company?.name,
        licenseModules: controlUser?.effective_modules
      });
      onUsersChange([...users, localUser]);
    }
    setUserDraft((draft) => ({ ...draft, username: "", full_name: "", password: "", role: "analyst", plan_code: "", modules: [] }));
  }

  async function toggleLicense(licenseId: string, currentStatus: string) {
    await runMutation(() => updateCompanyLicense(licenseId, { status: currentStatus === "active" || currentStatus === "trial" ? "suspended" : "active" }));
  }

  async function toggleUser(userId: string, currentStatus: string) {
    await runMutation(() => updateLicenseUser(userId, { status: currentStatus === "active" ? "inactive" : "active" }));
  }

  async function runMutation(action: () => Promise<LicensingOverview>): Promise<LicensingOverview | null> {
    setLoading(true);
    try {
      const next = await action();
      setOverview(next);
      setMessage(labels.saved);
      return next;
    } catch (exc) {
      setMessage(exc instanceof Error ? exc.message : labels.error);
      return null;
    } finally {
      setLoading(false);
    }
  }

  function toggleDraftModule(target: "license" | "user", module: ViewKey) {
    if (target === "license") {
      setLicenseDraft((draft) => ({ ...draft, modules_override: toggleValue(draft.modules_override, module) }));
      return;
    }
    setUserDraft((draft) => ({ ...draft, modules: toggleValue(draft.modules, module) }));
  }

  const activeLicenses = overview?.licenses.filter((license) => license.status === "active" || license.status === "trial").length ?? 0;

  return (
    <article className="panel chart-card license-control-card">
      <div className="panel-title-row compact">
        <div>
          <h2>{labels.title}</h2>
          <p>{labels.text}</p>
        </div>
        <button className="primary-button subtle" onClick={refresh} disabled={loading}>
          <RefreshCw size={17} />
          <span>{labels.refresh}</span>
        </button>
      </div>

      {overview ? (
        <>
          <div className="license-kpi-row">
            <LicenseKpi icon={<Building2 size={18} />} label={labels.companies} value={overview.companies.length} />
            <LicenseKpi icon={<UsersRound size={18} />} label={labels.users} value={overview.users.length} />
            <LicenseKpi icon={<BadgeCheck size={18} />} label={labels.activeLicenses} value={activeLicenses} />
            <LicenseKpi icon={<KeyRound size={18} />} label={labels.modules} value={overview.module_catalog.length} />
          </div>

          <div className="license-workspace">
            <section className="license-tree-panel">
              <div className="license-section-head">
                <div>
                  <strong>{labels.tree}</strong>
                  <span>{labels.treeText}</span>
                </div>
                <ShieldCheck size={18} />
              </div>
              <div className="license-company-list">
                {overview.companies.map((company) => (
                  <CompanyRow
                    key={company.id}
                    company={company}
                    companyById={companyById}
                    licenses={licensesByCompany.get(company.id) ?? []}
                    users={usersByCompany.get(company.id) ?? []}
                    language={language}
                    labels={labels}
                    canMutate={isSuperAdmin}
                    onToggleLicense={toggleLicense}
                    onToggleUser={toggleUser}
                  />
                ))}
              </div>
            </section>

            <section className="license-forms-panel">
              {isSuperAdmin ? (
                <div className="license-form-block">
                  <h3>{labels.createCompany}</h3>
                  <div className="settings-form license-inline-form">
                    <input value={companyDraft.name} onChange={(event) => setCompanyDraft({ ...companyDraft, name: event.target.value })} placeholder={labels.name} />
                    <select value={companyDraft.parent_id} onChange={(event) => setCompanyDraft({ ...companyDraft, parent_id: event.target.value })}>
                      <option value="">{labels.noParent}</option>
                      {overview.companies.map((company) => (
                        <option key={company.id} value={company.id}>{company.name}</option>
                      ))}
                    </select>
                    <input value={companyDraft.country} onChange={(event) => setCompanyDraft({ ...companyDraft, country: event.target.value })} placeholder={labels.country} />
                    <label className="license-sector-field">
                      <span>{labels.sectorHint}</span>
                      <select
                        className="license-sector-select"
                        multiple
                        value={companyDraft.sectors}
                        onChange={(event) => {
                          const values = Array.from(event.currentTarget.selectedOptions).map((option) => option.value);
                          setCompanyDraft({ ...companyDraft, sectors: values.includes(ALL_SECTORS) ? [ALL_SECTORS] : values });
                        }}
                      >
                        <option value={ALL_SECTORS}>{labels.allSectors}</option>
                        {economicSectors.filter((sector) => sector !== ALL_SECTORS).map((sector) => (
                          <option key={sector} value={sector}>{localizedSectorLabel(sector, language)}</option>
                        ))}
                      </select>
                    </label>
                    <button className="primary-button" onClick={createCompany} disabled={loading}>
                      <Plus size={17} />
                      <span>{labels.create}</span>
                    </button>
                  </div>
                </div>
              ) : null}

              {isSuperAdmin ? (
                <div className="license-form-block">
                  <h3>{labels.assignLicense}</h3>
                  <div className="settings-form license-inline-form">
                    <select value={licenseDraft.company_id} onChange={(event) => setLicenseDraft({ ...licenseDraft, company_id: event.target.value })}>
                      {overview.companies.map((company) => (
                        <option key={company.id} value={company.id}>{company.name}</option>
                      ))}
                    </select>
                    <select value={licenseDraft.plan_code} onChange={(event) => setLicenseDraft({ ...licenseDraft, plan_code: event.target.value })}>
                      {overview.plans.map((plan) => (
                        <option key={plan.code} value={plan.code}>{plan.name}</option>
                      ))}
                    </select>
                    <input
                      value={licenseDraft.seats}
                      onChange={(event) => setLicenseDraft({ ...licenseDraft, seats: Number(event.target.value) })}
                      min={1}
                      type="number"
                      placeholder={labels.seats}
                    />
                    <input value={licenseDraft.expires_at} onChange={(event) => setLicenseDraft({ ...licenseDraft, expires_at: event.target.value })} type="date" />
                  </div>
                  <ModulePicker
                    modules={overview.module_catalog.map((module) => module.key)}
                    selected={licenseDraft.modules_override}
                    language={language}
                    catalog={overview.module_catalog}
                    label={labels.moduleOverride}
                    inheritedLabel={labels.inherited}
                    onToggle={(module) => toggleDraftModule("license", module)}
                  />
                  <button className="primary-button license-submit" onClick={assignLicense} disabled={loading}>
                    <BadgeCheck size={17} />
                    <span>{labels.assign}</span>
                  </button>
                </div>
              ) : null}

              <div className="license-form-block">
                <h3>{labels.createUser}</h3>
                <div className="settings-form license-inline-form">
                  <select value={userDraft.company_id} onChange={(event) => setUserDraft({ ...userDraft, company_id: event.target.value })}>
                    {allowedCompanies.map((company) => (
                      <option key={company.id} value={company.id}>{company.name}</option>
                    ))}
                  </select>
                  <input value={userDraft.username} onChange={(event) => setUserDraft({ ...userDraft, username: event.target.value })} placeholder={labels.username} />
                  <input value={userDraft.full_name} onChange={(event) => setUserDraft({ ...userDraft, full_name: event.target.value })} placeholder={labels.fullName} />
                  <input
                    value={userDraft.password}
                    onChange={(event) => setUserDraft({ ...userDraft, password: event.target.value })}
                    placeholder={labels.password}
                    type="password"
                    autoComplete="new-password"
                  />
                  <select value={userDraft.role} onChange={(event) => setUserDraft({ ...userDraft, role: event.target.value as UserRole })}>
                    {isSuperAdmin ? <option value="admin">{labels.roleOptions.admin}</option> : null}
                    <option value="analyst">{labels.roleOptions.analyst}</option>
                    <option value="executive">{labels.roleOptions.executive}</option>
                    <option value="viewer">{labels.roleOptions.viewer}</option>
                  </select>
                  <select value={userDraft.plan_code} onChange={(event) => setUserDraft({ ...userDraft, plan_code: event.target.value })}>
                    <option value="">{labels.inheritCompany}</option>
                    {overview.plans.map((plan) => (
                      <option key={plan.code} value={plan.code}>{plan.name}</option>
                    ))}
                  </select>
                </div>
                <ModulePicker
                  modules={overview.module_catalog.map((module) => module.key)}
                  selected={userDraft.modules}
                  language={language}
                  catalog={overview.module_catalog}
                  label={labels.moduleOverride}
                  inheritedLabel={labels.inherited}
                  onToggle={(module) => toggleDraftModule("user", module)}
                />
                <button className="primary-button license-submit" onClick={createUser} disabled={loading}>
                  <UsersRound size={17} />
                  <span>{labels.create}</span>
                </button>
                {!isSuperAdmin ? <p className="license-hint">{labels.adminOnly}</p> : null}
              </div>
            </section>
          </div>

          <div className="license-plan-grid" aria-label={labels.plans}>
            {overview.plans.map((plan) => (
              <div className="license-plan-card" key={plan.code}>
                <div className="license-plan-head">
                  <div>
                    <strong>{plan.name}</strong>
                    <span>{plan.description[language]}</span>
                  </div>
                  <em>{plan.max_users}</em>
                </div>
                <div className="license-plan-modules">
                  <span>{labels.modules}</span>
                  <div className="license-chip-row">
                    {plan.modules.map((module) => (
                      <span key={module}>{moduleLabel(module, overview, language)}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>

          <section className="license-audit-panel">
            <div className="license-section-head">
              <div>
                <strong>{labels.accessLog}</strong>
                <span>{language === "es" ? "Registro de cambios de seguridad, acceso y licencias." : "Security, access and licensing change record."}</span>
              </div>
              <KeyRound size={18} />
            </div>
            <div className="license-audit-list">
              {overview.audit_log.length ? overview.audit_log.map((entry) => (
                <div className="license-audit-row" key={entry.id}>
                  <span>{entry.action}</span>
                  <strong>{entry.actor}</strong>
                  <em>{formatAuditDate(entry.created_at)}</em>
                  <code>{entry.target_type}:{entry.target_id}</code>
                </div>
              )) : <div className="chart-empty">{labels.empty}</div>}
            </div>
          </section>
        </>
      ) : (
        <div className="chart-empty">{labels.empty}</div>
      )}

      {message ? <p className="settings-message">{message}</p> : null}
    </article>
  );
}

function LicenseKpi({ icon, label, value }: { icon: ReactNode; label: string; value: number }) {
  return (
    <div className="license-kpi">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function CompanyRow({
  company,
  companyById,
  licenses,
  users,
  language,
  labels,
  canMutate,
  onToggleLicense,
  onToggleUser
}: {
  company: LicenseCompany;
  companyById: Map<string, LicenseCompany>;
  licenses: NonNullable<LicensingOverview["licenses"]>;
  users: NonNullable<LicensingOverview["users"]>;
  language: LanguageMode;
  labels: typeof copy.es;
  canMutate: boolean;
  onToggleLicense: (licenseId: string, status: string) => void;
  onToggleUser: (userId: string, status: string) => void;
}) {
  const depth = companyDepth(company, companyById);
  return (
    <div className="license-company-row" style={{ marginLeft: depth * 16 }}>
      <div className="license-company-head">
        <Building2 size={17} />
        <div>
          <strong>{company.name}</strong>
          <span>{company.sector || "Cyberintelligence"} | {company.country || "Global"} | {company.status}</span>
        </div>
      </div>
      <div className="license-company-detail">
        {licenses.map((license) => (
          <button
            className={`license-status-chip ${license.status}`}
            key={license.id}
            onClick={() => canMutate && onToggleLicense(license.id, license.status)}
            disabled={!canMutate}
          >
            {license.status === "active" || license.status === "trial" ? <ShieldCheck size={14} /> : <ShieldOff size={14} />}
            <span>{license.plan_code} | {statusLabel(license.status, labels)} | {license.seats}</span>
          </button>
        ))}
        {users.map((user) => (
          <button className={`license-user-chip ${user.status}`} key={user.id} onClick={() => onToggleUser(user.id, user.status)}>
            <UsersRound size={14} />
            <span>{user.full_name} | {roleLabelsByLanguage[language][user.role]} | {user.plan_code || labels.inheritCompany} | {user.effective_modules.length}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function ModulePicker({
  modules,
  selected,
  language,
  catalog,
  label,
  inheritedLabel,
  onToggle
}: {
  modules: ViewKey[];
  selected: ViewKey[];
  language: LanguageMode;
  catalog: LicensingOverview["module_catalog"];
  label: string;
  inheritedLabel: string;
  onToggle: (module: ViewKey) => void;
}) {
  return (
    <div className="license-module-picker">
      <span>{label} <em>{selected.length ? selected.length : inheritedLabel}</em></span>
      <div>
        {modules.map((module) => (
          <button className={selected.includes(module) ? "selected" : ""} key={module} onClick={() => onToggle(module)} type="button">
            {moduleLabel(module, { module_catalog: catalog } as LicensingOverview, language)}
          </button>
        ))}
      </div>
    </div>
  );
}

function groupBy<T, K extends keyof T>(items: T[], key: K): Map<string, T[]> {
  const grouped = new Map<string, T[]>();
  items.forEach((item) => {
    const value = String(item[key]);
    grouped.set(value, [...(grouped.get(value) ?? []), item]);
  });
  return grouped;
}

function toggleValue<T>(items: T[], item: T): T[] {
  return items.includes(item) ? items.filter((current) => current !== item) : [...items, item];
}

function companyDepth(company: LicenseCompany, companyById: Map<string, LicenseCompany>): number {
  let depth = 0;
  let parent = company.parent_id ? companyById.get(company.parent_id) : undefined;
  while (parent && depth < 6) {
    depth += 1;
    parent = parent.parent_id ? companyById.get(parent.parent_id) : undefined;
  }
  return depth;
}

function moduleLabel(module: ViewKey, overview: LicensingOverview, language: LanguageMode): string {
  return overview.module_catalog.find((item) => item.key === module)?.label[language] ?? module;
}

function statusLabel(status: string, labels: typeof copy.es): string {
  if (status === "active") return labels.active;
  if (status === "trial") return labels.trial;
  if (status === "suspended") return labels.suspended;
  if (status === "expired") return labels.expired;
  return labels.inactive;
}

function formatAuditDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
