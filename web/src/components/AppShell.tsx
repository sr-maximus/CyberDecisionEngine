import {
  BookOpenCheck,
  BrainCircuit,
  ChartNoAxesCombined,
  DatabaseZap,
  FileChartColumn,
  Fingerprint,
  Gauge,
  GitBranch,
  GlobeLock,
  LogOut,
  MessageSquareWarning,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  SearchCode,
  Settings2,
  ShieldCheck,
  Sun,
  UserCog,
  UserRoundSearch,
  Waypoints
} from "lucide-react";
import type { ReactNode } from "react";
import { roleLabelsByLanguage } from "../data/auth";
import type { LanguageMode, LocalUser, ThemeMode, UserRole, ViewKey } from "../types";

interface AppShellProps {
  children: ReactNode;
  isOnline: boolean;
  activeView: ViewKey;
  onViewChange: (view: ViewKey) => void;
  currentUser: LocalUser;
  theme: ThemeMode;
  language: LanguageMode;
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  onThemeChange: (theme: ThemeMode) => void;
  onLanguageChange: (language: LanguageMode) => void;
  onLogout: () => void;
}

const adminRoles: UserRole[] = ["super_admin", "admin"];
const analystRoles: UserRole[] = ["super_admin", "admin", "analyst"];
const executiveRoles: UserRole[] = ["super_admin", "admin", "analyst", "executive"];
const allRoles: UserRole[] = ["super_admin", "admin", "analyst", "executive", "viewer"];

const nav: Array<{ key: ViewKey; group: "strategy" | "intel" | "ops"; label: Record<LanguageMode, string>; icon: typeof ShieldCheck; roles: UserRole[] }> = [
  { key: "overview", group: "strategy", label: { es: "Visión general", en: "Overview" }, icon: Gauge, roles: allRoles },
  { key: "dashboards", group: "strategy", label: { es: "Tablero estratégico", en: "Strategic Dashboard" }, icon: ChartNoAxesCombined, roles: allRoles },
  { key: "scenarios", group: "strategy", label: { es: "Escenarios de decisión", en: "Decision Scenarios" }, icon: Waypoints, roles: executiveRoles },
  { key: "ai", group: "strategy", label: { es: "Asistente estratégico", en: "Strategic Assistant" }, icon: BrainCircuit, roles: executiveRoles },
  { key: "attackSurface", group: "strategy", label: { es: "Superficie de ataque", en: "Attack Surface" }, icon: ScanSearch, roles: executiveRoles },
  { key: "brand", group: "strategy", label: { es: "Marca y Fraude", en: "Brand & Fraud" }, icon: Fingerprint, roles: executiveRoles },
  { key: "employeeRisk", group: "intel", label: { es: "Riesgo Empleados", en: "Employee Risk" }, icon: UserRoundSearch, roles: analystRoles },
  { key: "disinformation", group: "intel", label: { es: "Desinformación", en: "Disinformation" }, icon: MessageSquareWarning, roles: executiveRoles },
  { key: "osint", group: "intel", label: { es: "OSINT y SOCMINT", en: "OSINT & SOCMINT" }, icon: SearchCode, roles: analystRoles },
  { key: "relationshipGraph", group: "intel", label: { es: "Grafo de relaciones", en: "Relationship Graph" }, icon: Network, roles: analystRoles },
  { key: "darkweb", group: "intel", label: { es: "Dark Web", en: "Dark Web" }, icon: GlobeLock, roles: analystRoles },
  { key: "frameworks", group: "intel", label: { es: "Mapeo de Frameworks", en: "Framework Mapping" }, icon: GitBranch, roles: executiveRoles },
  { key: "runs", group: "ops", label: { es: "Historial", en: "Runs" }, icon: DatabaseZap, roles: analystRoles },
  { key: "reports", group: "ops", label: { es: "Informes", en: "Reports" }, icon: FileChartColumn, roles: allRoles },
  { key: "help", group: "ops", label: { es: "Uso y modelo", en: "Usage & model" }, icon: BookOpenCheck, roles: allRoles },
  { key: "settings", group: "ops", label: { es: "Configuración", en: "Settings" }, icon: Settings2, roles: adminRoles }
];

const navGroups: Array<{ key: "strategy" | "intel" | "ops"; label: Record<LanguageMode, string> }> = [
  { key: "strategy", label: { es: "Estrategia", en: "Strategy" } },
  { key: "intel", label: { es: "Inteligencia", en: "Intelligence" } },
  { key: "ops", label: { es: "Operación", en: "Operations" } }
];

export function AppShell({
  children,
  isOnline,
  activeView,
  onViewChange,
  currentUser,
  theme,
  language,
  collapsed,
  onCollapsedChange,
  onThemeChange,
  onLanguageChange,
  onLogout
}: AppShellProps) {
  const visibleNav = nav.filter((item) => {
    if (!item.roles.includes(currentUser.role)) return false;
    if (currentUser.role === "super_admin") return true;
    if (!currentUser.licenseModules?.length) return true;
    if (item.key === "osint") {
      return currentUser.licenseModules.includes("osint") || currentUser.licenseModules.includes("socmint");
    }
    return currentUser.licenseModules.includes(item.key);
  });
  const shellCopy = {
    es: {
      expand: "Expandir menú",
      collapse: "Contraer menú",
      profile: "Perfil de usuario local",
      primary: "Navegación principal",
      controls: "Controles locales",
      language: "Idioma",
      lightMode: "Modo claro",
      darkMode: "Modo oscuro",
      signOut: "Salir"
    },
    en: {
      expand: "Expand menu",
      collapse: "Collapse menu",
      profile: "Local user profile",
      primary: "Primary navigation",
      controls: "Local controls",
      language: "Language",
      lightMode: "Light mode",
      darkMode: "Dark mode",
      signOut: "Sign out"
    }
  }[language];
  return (
    <div className={collapsed ? "app-shell collapsed" : "app-shell"}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </div>
          <div>
            <span>CyberDecision</span>
            <strong>Engine</strong>
          </div>
          <button type="button" className="collapse-button" onClick={() => onCollapsedChange(!collapsed)} title={collapsed ? shellCopy.expand : shellCopy.collapse}>
            {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
          </button>
        </div>

        <div className="profile-switch" aria-label={shellCopy.profile}>
          <UserCog size={16} />
          <div>
            <span>{roleLabelsByLanguage[language][currentUser.role]}</span>
            <strong>{currentUser.fullName}</strong>
          </div>
        </div>

        <nav className="nav-list" aria-label={shellCopy.primary}>
          {navGroups.map((group) => {
            const items = visibleNav.filter((item) => item.group === group.key);
            if (!items.length) return null;
            return (
              <div className="nav-section" key={group.key}>
                <span>{group.label[language]}</span>
                {items.map((item) => (
                  <button
                    className={activeView === item.key || (item.key === "osint" && activeView === "socmint") ? "nav-item active" : "nav-item"}
                    key={item.key}
                    onClick={() => onViewChange(item.key)}
                    title={item.label[language]}
                    type="button"
                  >
                    <item.icon size={18} aria-hidden="true" />
                    <span>{item.label[language]}</span>
                  </button>
                ))}
              </div>
            );
          })}
        </nav>

        <div className="shell-controls" aria-label={shellCopy.controls}>
          <span className="shell-controls-label">{shellCopy.controls}</span>
          <div className="mini-segmented" aria-label={shellCopy.language}>
            <button type="button" className={language === "es" ? "selected" : ""} onClick={() => onLanguageChange("es")} title="Español">
              ES
            </button>
            <button type="button" className={language === "en" ? "selected" : ""} onClick={() => onLanguageChange("en")} title="English">
              EN
            </button>
          </div>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => onThemeChange(theme === "dark" ? "light" : "dark")}
            title={theme === "dark" ? shellCopy.lightMode : shellCopy.darkMode}
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            <span>{theme === "dark" ? shellCopy.lightMode : shellCopy.darkMode}</span>
          </button>
          <button type="button" className="theme-toggle danger" onClick={onLogout}>
            <LogOut size={16} />
            <span>{shellCopy.signOut}</span>
          </button>
        </div>

        <div className="sidebar-status">
          <span className={isOnline ? "status-dot online" : "status-dot offline"} />
          <span>{isOnline ? (language === "es" ? "API local lista" : "Local API ready") : language === "es" ? "API no disponible" : "API unavailable"}</span>
        </div>
      </aside>
      {children}
    </div>
  );
}
