import { AlertTriangle, BadgeCheck, KeyRound, Languages, LockKeyhole, Moon, Plus, Save, ShieldAlert, ShieldCheck, Sun, ToggleLeft, UserCog, UsersRound, Wrench } from "lucide-react";
import { useEffect, useState } from "react";
import {
  attachTemporaryMfaCode,
  createLocalUser,
  generateTemporaryPassword,
  hashPassword,
  isUserLocked,
  lockoutMinutes,
  roleLabelsByLanguage,
  unlockUser
} from "../data/auth";
import { LicenseAdminPanel } from "./LicenseAdminPanel";
import { KnowledgeCatalogAdminPanel } from "./KnowledgeCatalogAdminPanel";
import { SourceHealth } from "./SourceHealth";
import type { LanguageMode, LocalUser, SourceStatus, ThemeMode, UserRole } from "../types";
import { cleanEvidenceText } from "../utils/sourceLabels";

interface SourceConfig {
  name: string;
  type: string;
  status: string;
  keyRef: string;
}

interface SettingsViewProps {
  currentUser: LocalUser;
  users: LocalUser[];
  theme: ThemeMode;
  language: LanguageMode;
  sourceStatuses: SourceStatus[];
  sourceRunId?: string;
  sourceUpdatedAt?: string;
  onUsersChange: (users: LocalUser[]) => void;
  onThemeChange: (theme: ThemeMode) => void;
  onLanguageChange: (language: LanguageMode) => void;
}

const defaultSources: SourceConfig[] = [
  { name: "public_web", type: "Brand Risk", status: "Enabled", keyRef: "" },
  { name: "external_surface", type: "Attack Surface", status: "Enabled", keyRef: "" },
  { name: "vulnerability_intelligence", type: "Vulnerability", status: "Enabled", keyRef: "" },
  { name: "threat_intelligence", type: "CTI", status: "Optional", keyRef: "" },
  { name: "cyberphysical_intelligence", type: "Exposure", status: "Optional", keyRef: "" },
  { name: "fraud_intelligence", type: "Fraud", status: "Optional", keyRef: "" },
  { name: "historical_intelligence", type: "SOCMINT", status: "Optional", keyRef: "" },
  { name: "deep_intelligence", type: "Dark Web", status: "Guarded", keyRef: "" }
];

const copy = {
  es: {
    profile: "Gobierno local de acceso",
    profileText: "Administra usuarios, idioma, tema y fuentes API para CyberDecisionEngine.",
    language: "Idioma",
    theme: "Apariencia",
    users: "Usuarios y roles",
    usersText: "El admin puede crear usuarios con permisos para generar, validar o solo consultar información.",
    addUser: "Crear usuario",
    sources: "Configuración de fuentes y API",
    sourcesText: "Registra referencias locales. Los secretos productivos deben vivir como variables de entorno.",
    addSource: "Agregar fuente",
    sourceName: "Nombre de fuente",
    keyRef: "Referencia ENV/API key",
    create: "Crear",
    username: "usuario",
    fullName: "nombre completo",
    password: "contraseña",
    noKeyRef: "Sin referencia de key",
    addSourceText: "Conectores SOCMINT, CTI, exposición, fraude, dark web o riesgo de marca.",
    roleOptions: {
      analyst: "Analista",
      executive: "Directivo",
      viewer: "Lector",
      admin: "Administrador"
    },
    adminOnly: "Solo administradores pueden crear usuarios.",
    adminRoleDenied: "Solo super admin puede crear administradores de empresa.",
    duplicate: "Ese usuario ya existe.",
    incomplete: "Completa usuario, nombre y contraseña.",
    weakPassword: "La contraseña debe tener al menos 12 caracteres.",
    sourceRequired: "Agrega nombre de fuente para registrar la configuración.",
    selectedConnector: "Conector seleccionado",
    observedStatus: "Estado observado",
    executionMode: "Modo de ejecución",
    connectorDiagnostic: "Diagnóstico de la corrida",
    editCapability: "Editar capacidad",
    registerCapability: "Registrar capacidad",
    saveSource: "Guardar configuración",
    cancelEdit: "Cancelar edición",
    accessSecurity: "Seguridad de acceso",
    accessSecurityText: "Gobierna doble factor, bloqueos por intentos y restablecimiento de contraseñas locales.",
    mfaOn: "MFA activo",
    mfaOff: "MFA inactivo",
    locked: "Bloqueado",
    attempts: "Intentos",
    mustChange: "Debe cambiar clave",
    ok: "Operativo",
    requireMfa: "Generar MFA",
    disableMfa: "Desactivar MFA",
    resetPassword: "Restablecer clave",
    unlock: "Desbloquear",
    mfaIssued: "Código MFA temporal para {user}: {code}. Expira en 10 minutos.",
    mfaDisabled: "MFA desactivado para {user}.",
    tempPassword: "Contraseña temporal para {user}: {password}. El usuario deberá cambiarla al ingresar.",
    unlocked: "Cuenta desbloqueada: {user}.",
    noPermission: "Tu rol no permite modificar ese usuario.",
    ownPassword: "Cambiar mi contraseña",
    ownPasswordText: "Si recibiste una clave temporal, cámbiala antes de operar la plataforma.",
    currentPassword: "contraseña actual",
    newPassword: "nueva contraseña",
    confirmPassword: "confirmar contraseña",
    changePassword: "Actualizar contraseña",
    wrongCurrent: "La contraseña actual no coincide.",
    mismatch: "La nueva contraseña y su confirmación no coinciden.",
    passwordChanged: "Contraseña actualizada correctamente.",
    localAuth: "Autenticación local de laboratorio con hash SHA-256 en navegador, MFA temporal, bloqueo por intentos y expiración de sesión. Para producción conecta backend auth/IAM, salting, hashing fuerte, auditoría central y control de sesiones."
  },
  en: {
    profile: "Local access governance",
    profileText: "Manage users, language, theme and API sources for CyberDecisionEngine.",
    language: "Language",
    theme: "Theme",
    users: "Users and roles",
    usersText: "Admin can create users with permissions to generate, validate or only read intelligence.",
    addUser: "Create user",
    sources: "Source and API configuration",
    sourcesText: "Register local references. Production secrets should live as environment variables.",
    addSource: "Add source",
    sourceName: "Source name",
    keyRef: "ENV/API key reference",
    create: "Create",
    username: "username",
    fullName: "full name",
    password: "password",
    noKeyRef: "No key reference",
    addSourceText: "SOCMINT, CTI, exposure, fraud, dark web or brand-risk connectors.",
    roleOptions: {
      analyst: "Analyst",
      executive: "Executive",
      viewer: "Viewer",
      admin: "Admin"
    },
    adminOnly: "Only administrators can create users.",
    adminRoleDenied: "Only super admin can create company administrators.",
    duplicate: "That username already exists.",
    incomplete: "Complete username, name and password.",
    weakPassword: "Password must be at least 12 characters.",
    sourceRequired: "Add a source name to register the configuration.",
    selectedConnector: "Selected connector",
    observedStatus: "Observed status",
    executionMode: "Execution mode",
    connectorDiagnostic: "Run diagnostic",
    editCapability: "Edit capability",
    registerCapability: "Register capability",
    saveSource: "Save configuration",
    cancelEdit: "Cancel edit",
    accessSecurity: "Access security",
    accessSecurityText: "Govern two-factor verification, failed-attempt lockout and local password reset.",
    mfaOn: "MFA enabled",
    mfaOff: "MFA disabled",
    locked: "Locked",
    attempts: "Attempts",
    mustChange: "Must change password",
    ok: "Operational",
    requireMfa: "Generate MFA",
    disableMfa: "Disable MFA",
    resetPassword: "Reset password",
    unlock: "Unlock",
    mfaIssued: "Temporary MFA code for {user}: {code}. Expires in 10 minutes.",
    mfaDisabled: "MFA disabled for {user}.",
    tempPassword: "Temporary password for {user}: {password}. The user must change it after login.",
    unlocked: "Account unlocked: {user}.",
    noPermission: "Your role cannot modify that user.",
    ownPassword: "Change my password",
    ownPasswordText: "If you received a temporary password, change it before operating the platform.",
    currentPassword: "current password",
    newPassword: "new password",
    confirmPassword: "confirm password",
    changePassword: "Update password",
    wrongCurrent: "Current password does not match.",
    mismatch: "New password and confirmation do not match.",
    passwordChanged: "Password updated successfully.",
    localAuth: "Local lab authentication with browser SHA-256 hashing, temporary MFA, failed-attempt lockout and session expiration. For production connect backend auth/IAM, salting, strong hashing, central audit and session control."
  }
};

const sourceDisplay: Record<LanguageMode, Record<string, string>> = {
  es: {
    Vulnerability: "Vulnerabilidades",
    CTI: "CTI",
    Exposure: "Exposicion",
    "Attack Surface": "Superficie de ataque",
    "Brand Risk": "Riesgo de marca",
    Fraud: "Fraude",
    SOCMINT: "SOCMINT",
    "Dark Web": "Dark Web",
    Enabled: "Habilitada",
    Optional: "Opcional",
    "Safe index": "Indice seguro",
    Guarded: "Controlado",
    "Needs key": "Requiere key",
    public_web: "Inteligencia web publica",
    external_surface: "Exposicion tecnologica publica",
    vulnerability_intelligence: "Inteligencia de vulnerabilidades",
    threat_intelligence: "Inteligencia de amenazas",
    cyberphysical_intelligence: "Inteligencia ciberfisica",
    fraud_intelligence: "Inteligencia de fraude",
    historical_intelligence: "Inteligencia historica",
    deep_intelligence: "Evidencia publica corroborada"
  },
  en: {
    Vulnerability: "Vulnerability",
    CTI: "CTI",
    Exposure: "Exposure",
    "Attack Surface": "Attack Surface",
    "Brand Risk": "Brand Risk",
    Fraud: "Fraud",
    SOCMINT: "SOCMINT",
    "Dark Web": "Dark Web",
    Enabled: "Enabled",
    Optional: "Optional",
    "Safe index": "Safe index",
    Guarded: "Guarded",
    "Needs key": "Needs key",
    public_web: "Public web intelligence",
    external_surface: "Public technology exposure",
    vulnerability_intelligence: "Vulnerability intelligence",
    threat_intelligence: "Threat intelligence",
    cyberphysical_intelligence: "Cyber-physical intelligence",
    fraud_intelligence: "Fraud intelligence",
    historical_intelligence: "Historical intelligence",
    deep_intelligence: "Corroborated public evidence"
  }
};

const sourceCapabilityByType: Record<string, string> = {
  Vulnerability: "vulnerability_intelligence",
  CTI: "threat_intelligence",
  Exposure: "cyberphysical_intelligence",
  "Attack Surface": "external_surface",
  "Brand Risk": "public_web",
  Fraud: "fraud_intelligence",
  SOCMINT: "historical_intelligence",
  "Dark Web": "deep_intelligence"
};

function sourceTypeForStatus(source: SourceStatus): string {
  const value = `${source.name} ${source.mode}`.toLowerCase();
  if (/vulnerab|\bcve\b|\bkev\b/.test(value)) return "Vulnerability";
  if (/dark|\btor\b|ransom/.test(value)) return "Dark Web";
  if (/fraud|brand|phish|typo|squat/.test(value)) return "Fraud";
  if (/threat|\bcti\b|actor|campaign|ttp/.test(value)) return "CTI";
  if (/cyberphysical|\bics\b|\bot\b|\biot\b/.test(value)) return "Exposure";
  if (/surface|attack|dns|tls|whois|domain|exposure/.test(value)) return "Attack Surface";
  if (/socmint|social|histor/.test(value)) return "SOCMINT";
  return "Brand Risk";
}

function sourceLabel(value: string, language: LanguageMode) {
  return sourceDisplay[language][value] ?? value;
}

function normalizeSourceConfig(source: SourceConfig): SourceConfig {
  return {
    name: sourceCapabilityByType[source.type] ?? "public_web",
    type: source.type,
    status: source.status,
    keyRef: source.keyRef ? "configured" : ""
  };
}

export function SettingsView({
  currentUser,
  users,
  theme,
  language,
  sourceStatuses,
  sourceRunId,
  sourceUpdatedAt,
  onUsersChange,
  onThemeChange,
  onLanguageChange
}: SettingsViewProps) {
  const labels = copy[language];
  const [sources, setSources] = useState<SourceConfig[]>(() => {
    const saved = window.localStorage.getItem("cyberdecision.sources");
    if (!saved) return defaultSources;
    try {
      const parsed = JSON.parse(saved);
      return Array.isArray(parsed) ? parsed.map(normalizeSourceConfig) : defaultSources;
    } catch {
      return defaultSources;
    }
  });
  const [draft, setDraft] = useState<SourceConfig>({ name: "", type: "SOCMINT", status: "Needs key", keyRef: "" });
  const [userDraft, setUserDraft] = useState({ username: "", fullName: "", password: "", role: "analyst" as UserRole });
  const [userMessage, setUserMessage] = useState<string | null>(null);
  const [sourceMessage, setSourceMessage] = useState<string | null>(null);
  const [selectedSource, setSelectedSource] = useState<SourceStatus | null>(null);
  const [editingSourceIndex, setEditingSourceIndex] = useState<number | null>(null);
  const [accessMessage, setAccessMessage] = useState<string | null>(null);
  const [passwordDraft, setPasswordDraft] = useState({ current: "", next: "", confirm: "" });

  useEffect(() => {
    window.localStorage.setItem("cyberdecision.sources", JSON.stringify(sources));
  }, [sources]);

  function saveSource() {
    if (!draft.name.trim()) {
      setSourceMessage(labels.sourceRequired);
      return;
    }
    const normalized = normalizeSourceConfig(draft);
    setSources((current) => editingSourceIndex === null
      ? [...current, normalized]
      : current.map((source, index) => (index === editingSourceIndex ? normalized : source)));
    setDraft({ name: "", type: "SOCMINT", status: "Needs key", keyRef: "" });
    setEditingSourceIndex(null);
    setSourceMessage(null);
  }

  function openSourceConfiguration(source?: SourceStatus) {
    setSelectedSource(source ?? null);
    document.getElementById("settings-source-configuration")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function editSourceConfiguration(source: SourceStatus) {
    const type = sourceTypeForStatus(source);
    const capability = sourceCapabilityByType[type];
    const index = sources.findIndex((configuredSource) => configuredSource.name === capability || configuredSource.type === type);
    setSelectedSource(source);
    setEditingSourceIndex(index >= 0 ? index : null);
    setDraft(index >= 0 ? sources[index] : {
      name: source.name,
      type,
      status: source.configured === false || source.unconfigured ? "Needs key" : "Optional",
      keyRef: ""
    });
    requestAnimationFrame(() => document.getElementById("settings-source-form")?.scrollIntoView({ behavior: "smooth", block: "center" }));
  }

  function cancelSourceEdit() {
    setEditingSourceIndex(null);
    setDraft({ name: "", type: "SOCMINT", status: "Needs key", keyRef: "" });
    setSourceMessage(null);
  }

  async function addUser() {
    if (!["super_admin", "admin"].includes(currentUser.role)) {
      setUserMessage(labels.adminOnly);
      return;
    }
    if (currentUser.role !== "super_admin" && userDraft.role === "admin") {
      setUserMessage(labels.adminRoleDenied);
      return;
    }
    if (!userDraft.username.trim() || !userDraft.fullName.trim() || !userDraft.password.trim()) {
      setUserMessage(labels.incomplete);
      return;
    }
    if (userDraft.password.length < 12) {
      setUserMessage(labels.weakPassword);
      return;
    }
    if (users.some((user) => user.username.toLowerCase() === userDraft.username.trim().toLowerCase())) {
      setUserMessage(labels.duplicate);
      return;
    }
    const nextUser = createLocalUser({
      username: userDraft.username.trim(),
      fullName: userDraft.fullName.trim(),
      passwordHash: await hashPassword(userDraft.password),
      role: userDraft.role,
      companyId: currentUser.companyId,
      companyName: currentUser.companyName,
      licenseModules: currentUser.licenseModules
    });
    onUsersChange([...users, nextUser]);
    setUserDraft({ username: "", fullName: "", password: "", role: "analyst" });
    setUserMessage(null);
  }

  function canManageUser(target: LocalUser): boolean {
    if (!["super_admin", "admin"].includes(currentUser.role)) return false;
    if (currentUser.role === "super_admin") return true;
    return target.role !== "super_admin" && target.role !== "admin" && target.companyId === currentUser.companyId;
  }

  function updateUser(userId: string, updater: (user: LocalUser) => LocalUser) {
    onUsersChange(users.map((user) => (user.id === userId ? updater(user) : user)));
  }

  async function generateMfa(user: LocalUser) {
    if (!canManageUser(user)) {
      setAccessMessage(labels.noPermission);
      return;
    }
    const result = await attachTemporaryMfaCode(user);
    updateUser(user.id, () => result.user);
    setAccessMessage(labels.mfaIssued.replace("{user}", user.username).replace("{code}", result.code));
  }

  function disableMfa(user: LocalUser) {
    if (!canManageUser(user)) {
      setAccessMessage(labels.noPermission);
      return;
    }
    updateUser(user.id, (current) => ({
      ...current,
      mfaEnabled: false,
      mfaCodeHash: undefined,
      mfaCodeIssuedAt: undefined,
      mfaCodeExpiresAt: undefined
    }));
    setAccessMessage(labels.mfaDisabled.replace("{user}", user.username));
  }

  async function resetPassword(user: LocalUser) {
    if (!canManageUser(user)) {
      setAccessMessage(labels.noPermission);
      return;
    }
    const password = generateTemporaryPassword();
    const passwordHash = await hashPassword(password);
    updateUser(user.id, (current) => ({
      ...unlockUser(current),
      passwordHash,
      mustChangePassword: true,
      passwordUpdatedAt: new Date().toISOString()
    }));
    setAccessMessage(labels.tempPassword.replace("{user}", user.username).replace("{password}", password));
  }

  function unlockLocalUser(user: LocalUser) {
    if (!canManageUser(user)) {
      setAccessMessage(labels.noPermission);
      return;
    }
    updateUser(user.id, unlockUser);
    setAccessMessage(labels.unlocked.replace("{user}", user.username));
  }

  async function changeOwnPassword() {
    if (!passwordDraft.current || !passwordDraft.next || !passwordDraft.confirm) {
      setAccessMessage(labels.incomplete);
      return;
    }
    if (passwordDraft.next.length < 12) {
      setAccessMessage(labels.weakPassword);
      return;
    }
    if (passwordDraft.next !== passwordDraft.confirm) {
      setAccessMessage(labels.mismatch);
      return;
    }
    if ((await hashPassword(passwordDraft.current)) !== currentUser.passwordHash) {
      setAccessMessage(labels.wrongCurrent);
      return;
    }
    const passwordHash = await hashPassword(passwordDraft.next);
    updateUser(currentUser.id, (user) => ({
      ...user,
      passwordHash,
      mustChangePassword: false,
      passwordUpdatedAt: new Date().toISOString()
    }));
    setPasswordDraft({ current: "", next: "", confirm: "" });
    setAccessMessage(labels.passwordChanged);
  }

  return (
    <section className="settings-layout">
      <LicenseAdminPanel currentUser={currentUser} users={users} language={language} onUsersChange={onUsersChange} />

      <SourceHealth
        sources={sourceStatuses}
        language={language}
        runId={sourceRunId}
        updatedAt={sourceUpdatedAt}
        className="settings-source-coverage"
        administrative
        onOpenConfiguration={openSourceConfiguration}
      />

      <KnowledgeCatalogAdminPanel
        language={language}
        canAdminister={["super_admin", "admin"].includes(currentUser.role)}
      />

      <article className="panel chart-card settings-card settings-card-profile">
        <div className="panel-title-row compact">
          <div>
            <h2>{labels.profile}</h2>
            <p>{labels.profileText}</p>
          </div>
          <UserCog size={18} />
        </div>
        <div className="settings-form settings-stack">
          <label className="field-control">
            <span>{labels.language}</span>
            <select value={language} onChange={(event) => onLanguageChange(event.target.value as LanguageMode)}>
              <option value="es">Español</option>
              <option value="en">English</option>
            </select>
          </label>
          <button className="primary-button" onClick={() => onThemeChange(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            <span>{theme === "dark" ? (language === "es" ? "Modo claro" : "Light mode") : language === "es" ? "Modo oscuro" : "Dark mode"}</span>
          </button>
          <div className="security-note">
            <ShieldCheck size={18} />
            <p>{labels.localAuth}</p>
          </div>
          {currentUser.mustChangePassword ? (
            <div className="guided-alert compact">
              <AlertTriangle size={17} />
              <div>
                <strong>{labels.mustChange}</strong>
                <p>{labels.ownPasswordText}</p>
              </div>
            </div>
          ) : null}
          <div className="password-change-box">
            <div className="security-section-title">
              <LockKeyhole size={17} />
              <div>
                <strong>{labels.ownPassword}</strong>
                <span>{labels.ownPasswordText}</span>
              </div>
            </div>
            <input
              value={passwordDraft.current}
              onChange={(event) => setPasswordDraft({ ...passwordDraft, current: event.target.value })}
              placeholder={labels.currentPassword}
              type="password"
              autoComplete="current-password"
            />
            <input
              value={passwordDraft.next}
              onChange={(event) => setPasswordDraft({ ...passwordDraft, next: event.target.value })}
              placeholder={labels.newPassword}
              type="password"
              autoComplete="new-password"
            />
            <input
              value={passwordDraft.confirm}
              onChange={(event) => setPasswordDraft({ ...passwordDraft, confirm: event.target.value })}
              placeholder={labels.confirmPassword}
              type="password"
              autoComplete="new-password"
            />
            <button className="primary-button subtle" onClick={changeOwnPassword}>
              <BadgeCheck size={17} />
              <span>{labels.changePassword}</span>
            </button>
          </div>
        </div>
      </article>

      <article className="panel chart-card settings-card settings-card-users">
        <div className="panel-title-row compact">
          <div>
            <h2>{labels.accessSecurity}</h2>
            <p>{labels.accessSecurityText}</p>
          </div>
          <ShieldAlert size={18} />
        </div>
        <div className="user-admin-grid access-user-grid">
          {users.map((user) => (
            <div className="user-admin-row" key={user.id}>
              <UserCog size={17} />
              <div>
                <strong>{user.fullName}</strong>
                <span>{user.username} | {roleLabelsByLanguage[language][user.role]} | {user.companyName ?? "CyberDecisionEngine"}</span>
                <div className="access-chip-row">
                  <em className={user.mfaEnabled ? "ok" : "muted"}>{user.mfaEnabled ? labels.mfaOn : labels.mfaOff}</em>
                  <em className={isUserLocked(user) ? "danger" : "ok"}>
                    {isUserLocked(user) ? `${labels.locked} ${lockoutMinutes(user)} min` : labels.ok}
                  </em>
                  <em className={(user.failedLoginCount ?? 0) > 0 ? "warn" : "muted"}>{labels.attempts}: {user.failedLoginCount ?? 0}/5</em>
                  {user.mustChangePassword ? <em className="warn">{labels.mustChange}</em> : null}
                </div>
                <div className="user-action-row">
                  <button className="secondary-button compact" type="button" onClick={() => generateMfa(user)} disabled={!canManageUser(user)}>
                    <KeyRound size={15} />
                    <span>{labels.requireMfa}</span>
                  </button>
                  <button className="secondary-button compact" type="button" onClick={() => disableMfa(user)} disabled={!canManageUser(user) || !user.mfaEnabled}>
                    <ShieldCheck size={15} />
                    <span>{labels.disableMfa}</span>
                  </button>
                  <button className="secondary-button compact" type="button" onClick={() => resetPassword(user)} disabled={!canManageUser(user)}>
                    <LockKeyhole size={15} />
                    <span>{labels.resetPassword}</span>
                  </button>
                  <button className="secondary-button compact" type="button" onClick={() => unlockLocalUser(user)} disabled={!canManageUser(user) || !isUserLocked(user)}>
                    <BadgeCheck size={15} />
                    <span>{labels.unlock}</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
        {accessMessage ? <div className="guided-alert compact access-message"><AlertTriangle size={17} /><p>{accessMessage}</p></div> : null}
      </article>

      <article className="panel chart-card settings-card settings-card-local-users">
        <div className="panel-title-row compact">
          <div>
            <h2>{labels.users}</h2>
            <p>{labels.usersText}</p>
          </div>
          <UsersRound size={18} />
        </div>
        <div className="settings-form user-create-form">
          <input value={userDraft.username} onChange={(event) => setUserDraft({ ...userDraft, username: event.target.value })} placeholder={labels.username} />
          <input value={userDraft.fullName} onChange={(event) => setUserDraft({ ...userDraft, fullName: event.target.value })} placeholder={labels.fullName} />
          <input
            value={userDraft.password}
            onChange={(event) => setUserDraft({ ...userDraft, password: event.target.value })}
            placeholder={labels.password}
            type="password"
            autoComplete="new-password"
          />
          <select value={userDraft.role} onChange={(event) => setUserDraft({ ...userDraft, role: event.target.value as UserRole })}>
            <option value="analyst">{labels.roleOptions.analyst}</option>
            <option value="executive">{labels.roleOptions.executive}</option>
            <option value="viewer">{labels.roleOptions.viewer}</option>
            {currentUser.role === "super_admin" ? <option value="admin">{labels.roleOptions.admin}</option> : null}
          </select>
          <button className="primary-button" onClick={addUser}>
            <Plus size={17} />
            <span>{labels.create}</span>
          </button>
          {userMessage ? <div className="guided-alert compact"><AlertTriangle size={17} /><p>{userMessage}</p></div> : null}
        </div>
      </article>

      <article id="settings-source-configuration" className="panel chart-card settings-card settings-card-sources">
        <div className="panel-title-row compact">
          <div>
            <h2>{labels.sources}</h2>
            <p>{labels.sourcesText}</p>
          </div>
          <Save size={18} />
        </div>
        {selectedSource ? (
          <div className="source-diagnostic" role="status">
            <div>
              <span>{labels.selectedConnector}</span>
              <strong>{selectedSource.name}</strong>
            </div>
            <div>
              <span>{labels.observedStatus}</span>
              <strong>{selectedSource.status}</strong>
            </div>
            <div>
              <span>{labels.executionMode}</span>
              <strong>{selectedSource.mode || "N/D"}</strong>
            </div>
            <p><strong>{labels.connectorDiagnostic}:</strong> {selectedSource.warning ? cleanEvidenceText(selectedSource.warning) : (language === "es" ? "Sin advertencias reportadas en la corrida seleccionada." : "No warnings reported for the selected run.")}</p>
            <button type="button" className="secondary-button compact" onClick={() => editSourceConfiguration(selectedSource)}>
              <Wrench size={15} />
              <span>{sources.some((source) => source.name === sourceCapabilityByType[sourceTypeForStatus(selectedSource)]) ? labels.editCapability : labels.registerCapability}</span>
            </button>
          </div>
        ) : null}
        <div className="settings-grid">
          {sources.map((source, index) => (
            <div className={`source-config-row ${selectedSource && source.name === sourceCapabilityByType[sourceTypeForStatus(selectedSource)] ? "selected" : ""}`.trim()} key={`${source.name}-${source.keyRef}-${index}`}>
              <KeyRound size={18} />
              <div>
                <strong>{sourceLabel(source.name, language)}</strong>
                <span>{sourceLabel(source.type, language)} - {source.keyRef ? (language === "es" ? "Referencia interna configurada" : "Internal reference configured") : labels.noKeyRef}</span>
              </div>
              <em>{sourceLabel(source.status, language)}</em>
              <button type="button" className="source-config-action" onClick={() => {
                setEditingSourceIndex(index);
                setDraft(source);
                document.getElementById("settings-source-form")?.scrollIntoView({ behavior: "smooth", block: "center" });
              }} aria-label={`${labels.editCapability}: ${sourceLabel(source.name, language)}`}>
                <Wrench size={14} />
              </button>
            </div>
          ))}
        </div>
      </article>

      <article id="settings-source-form" className="panel chart-card settings-card settings-card-source-form">
        <div className="panel-title-row compact">
          <div>
            <h2>{labels.addSource}</h2>
            <p>{labels.addSourceText}</p>
          </div>
          <Languages size={18} />
        </div>
        <div className="settings-form">
          <input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder={labels.sourceName} />
          <select value={draft.type} onChange={(event) => setDraft({ ...draft, type: event.target.value })}>
            {["SOCMINT", "CTI", "Exposure", "Attack Surface", "Vulnerability", "Fraud", "Dark Web", "Brand Risk"].map((value) => (
              <option key={value} value={value}>{sourceLabel(value, language)}</option>
            ))}
          </select>
          <input value={draft.keyRef} onChange={(event) => setDraft({ ...draft, keyRef: event.target.value })} placeholder={labels.keyRef} />
          <button className="primary-button" onClick={saveSource}>
            <ToggleLeft size={17} />
            <span>{editingSourceIndex === null ? labels.addSource : labels.saveSource}</span>
          </button>
          {editingSourceIndex !== null ? <button className="secondary-button" type="button" onClick={cancelSourceEdit}><span>{labels.cancelEdit}</span></button> : null}
          {sourceMessage ? <div className="guided-alert compact"><AlertTriangle size={17} /><p>{sourceMessage}</p></div> : null}
        </div>
      </article>
    </section>
  );
}
