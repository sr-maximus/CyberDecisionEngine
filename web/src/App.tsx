import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { createAnalysis, deleteReport, generateRunReport, getLicensingOverview, listReports, listRuns, rerunAnalysis } from "./api";
import { ALL_CONTINENTS, ALL_COUNTRIES, ALL_SECTORS, countriesFor, economicSectors, selectedWithoutAll } from "./data/catalog";
import { DEFAULT_ANALYSIS_WINDOW, analysisWindowConfig } from "./data/analysisWindows";
import { clearSession, loadUsers, readSession, saveUsers, sessionPolicyForUser, touchSession, writeSession } from "./data/auth";
import { AppShell } from "./components/AppShell";
import { EvidenceLedger } from "./components/EvidenceLedger";
import { FindingsTable } from "./components/FindingsTable";
import { KpiStrip } from "./components/KpiStrip";
import { LoginView } from "./components/LoginView";
import { PlatformBrief } from "./components/PlatformBrief";
import { RiskTrend } from "./components/RiskTrend";
import { RunTimeline } from "./components/RunTimeline";
import { AnalysisContextBar } from "./components/AnalysisContextBar";
import type {
  AnalysisMode,
  AnalysisWindow,
  LanguageMode,
  LocalUser,
  ReportCatalogItem,
  RunRecord,
  ThemeMode,
  UserRole,
  ViewKey
} from "./types";
import { formatDateTime } from "./utils/format";

const AttackSurfaceView = lazy(() => import("./components/AttackSurfaceView").then((module) => ({ default: module.AttackSurfaceView })));
const BrandRiskView = lazy(() => import("./components/BrandRiskView").then((module) => ({ default: module.BrandRiskView })));
const DisinformationView = lazy(() => import("./components/DisinformationView").then((module) => ({ default: module.DisinformationView })));
const EmployeeRiskView = lazy(() => import("./components/EmployeeRiskView").then((module) => ({ default: module.EmployeeRiskView })));
const FrameworksView = lazy(() => import("./components/FrameworksView").then((module) => ({ default: module.FrameworksView })));
const DomainsView = lazy(() => import("./components/ManagementViews").then((module) => ({ default: module.DomainsView })));
const RunsView = lazy(() => import("./components/ManagementViews").then((module) => ({ default: module.RunsView })));
const ReportsView = lazy(() => import("./components/ReportsView").then((module) => ({ default: module.ReportsView })));
const ScenarioDecisionView = lazy(() => import("./components/ScenarioDecisionView").then((module) => ({ default: module.ScenarioDecisionView })));
const SettingsView = lazy(() => import("./components/SettingsView").then((module) => ({ default: module.SettingsView })));
const SocmintView = lazy(() => import("./components/SocmintView").then((module) => ({ default: module.SocmintView })));
const SourceIntelligenceView = lazy(() => import("./components/SourceIntelligenceView").then((module) => ({ default: module.SourceIntelligenceView })));
const StrategicDashboard = lazy(() => import("./components/StrategicDashboard").then((module) => ({ default: module.StrategicDashboard })));
const UsageGuideView = lazy(() => import("./components/UsageGuideView").then((module) => ({ default: module.UsageGuideView })));
const AIAssistantView = lazy(() => import("./components/AIAssistantView").then((module) => ({ default: module.AIAssistantView })));

const seedDomains = "";
const seedOrganizationName = "";
const scopeDefaultsPrefix = "cyberdecision.defaultScope.";

const viewTitles: Record<LanguageMode, Record<ViewKey, string>> = {
  es: {
    overview: "CyberDecisionEngine",
    dashboards: "Tablero estratégico",
    scenarios: "Escenarios de decisión",
    brand: "Marca y Fraude",
    attackSurface: "Superficie de ataque",
    employeeRisk: "Riesgo virtual de empleados",
    disinformation: "Desinformación",
    osint: "Inteligencia OSINT",
    socmint: "Inteligencia SOCMINT",
    darkweb: "Inteligencia Dark Web",
    frameworks: "Mapeo de Frameworks",
    ai: "IA estratégica",
    runs: "Historial de análisis",
    reports: "Informes CyberDecisionEngine",
    help: "Uso de la plataforma",
    settings: "Configuración"
  },
  en: {
    overview: "CyberDecisionEngine Overview",
    dashboards: "Strategic Dashboard",
    scenarios: "Decision Scenarios",
    brand: "Brand & Fraud Risk",
    attackSurface: "Attack Surface",
    employeeRisk: "Employee Virtual Risk",
    disinformation: "Disinformation",
    osint: "OSINT Intelligence",
    socmint: "SOCMINT Intelligence",
    darkweb: "Dark Web Intelligence",
    frameworks: "Framework Mapping",
    ai: "Strategic AI",
    runs: "Analysis Runs",
    reports: "CyberDecisionEngine Reports",
    help: "Platform Usage",
    settings: "Settings"
  }
};

const allViews: ViewKey[] = [
  "overview",
  "dashboards",
  "scenarios",
  "attackSurface",
  "brand",
  "employeeRisk",
  "disinformation",
  "osint",
  "socmint",
  "darkweb",
  "frameworks",
  "ai",
  "runs",
  "reports",
  "help",
  "settings"
];

function initialViewFromUrl(): ViewKey {
  const candidate = new URLSearchParams(window.location.search).get("view");
  if (candidate === "domains") return "overview";
  return candidate && allViews.includes(candidate as ViewKey) ? (candidate as ViewKey) : "dashboards";
}

const viewAccess: Record<UserRole, ViewKey[]> = {
  super_admin: allViews,
  admin: allViews,
  analyst: ["overview", "dashboards", "scenarios", "attackSurface", "brand", "employeeRisk", "disinformation", "osint", "socmint", "darkweb", "frameworks", "ai", "runs", "reports", "help"],
  executive: ["overview", "dashboards", "scenarios", "attackSurface", "brand", "disinformation", "frameworks", "ai", "reports", "help"],
  viewer: ["overview", "dashboards", "reports", "help"]
};

const evidenceViews: ViewKey[] = ["dashboards", "scenarios", "brand", "attackSurface", "disinformation", "osint", "socmint", "darkweb", "frameworks"];

const appCopy = {
  es: {
    apiError: "No se puede conectar con la API",
    startError: "No se pudo iniciar el analisis",
    refreshError: "No se pudieron actualizar los datos"
  },
  en: {
    apiError: "Unable to reach API",
    startError: "Unable to start analysis",
    refreshError: "Unable to refresh data"
  }
};

function parseDomains(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\s,;]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .filter((item) => {
      if (seen.has(item)) return false;
      seen.add(item);
      return true;
    });
}

function hasViewAccess(user: LocalUser, view: ViewKey): boolean {
  if (!viewAccess[user.role].includes(view)) return false;
  if (user.role === "super_admin") return true;
  if (!user.licenseModules?.length) return true;
  if (view === "settings") return user.role === "admin" && user.licenseModules.includes("settings");
  return user.licenseModules.includes(view);
}

function selectDashboardRun(selectedRun: RunRecord | undefined, runs: RunRecord[]): RunRecord | undefined {
  if (!selectedRun) return latestCompletedWithData(runs);
  const selectedHasEvidence =
    selectedRun.status === "completed" ||
    Boolean(selectedRun.report) ||
    selectedRun.summary.kpis.new_events > 0 ||
    selectedRun.summary.findings.length > 0;
  if (selectedHasEvidence) return selectedRun;
  return latestCompletedWithData(runs, selectedRun.domains) ?? selectedRun;
}

function latestCompletedWithData(runs: RunRecord[], domains?: string[]): RunRecord | undefined {
  const domainSet = new Set((domains ?? []).map((domain) => domain.toLowerCase()));
  const candidates = runs.filter((run) => {
    if (run.status !== "completed") return false;
    if (!run.report && run.summary.kpis.new_events === 0 && run.summary.findings.length === 0) return false;
    if (!domainSet.size) return true;
    return run.domains.some((domain) => domainSet.has(domain.toLowerCase()));
  });
  return candidates[0];
}

export function App() {
  const [activeView, setActiveView] = useState<ViewKey>(initialViewFromUrl);
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [reports, setReports] = useState<ReportCatalogItem[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [rawDomains, setRawDomains] = useState(seedDomains);
  const [rawCompetitorDomains, setRawCompetitorDomains] = useState("");
  const [organizationName, setOrganizationName] = useState(seedOrganizationName);
  const [mode, setMode] = useState<AnalysisMode>("deep");
  const [analysisWindow, setAnalysisWindow] = useState<AnalysisWindow>(DEFAULT_ANALYSIS_WINDOW);
  const [scanTimeBudgetMinutes, setScanTimeBudgetMinutes] = useState(30);
  const [reportDisplayAt, setReportDisplayAt] = useState("");
  const [selectedSectors, setSelectedSectors] = useState<string[]>([ALL_SECTORS]);
  const [selectedCountries, setSelectedCountries] = useState<string[]>([ALL_COUNTRIES]);
  const [realOnly, setRealOnly] = useState(true);
  const [authorizedScope, setAuthorizedScope] = useState(true);
  const [allowTor, setAllowTor] = useState(true);
  const [hasTouchedDomains, setHasTouchedDomains] = useState(false);
  const [scopeDefaultMessage, setScopeDefaultMessage] = useState<string | null>(null);
  const [users, setUsers] = useState<LocalUser[]>(() => loadUsers());
  const [sessionUserId, setSessionUserId] = useState<string | null>(() => readSession()?.userId ?? null);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeMode>(() => (window.localStorage.getItem("cyberdecision.theme") as ThemeMode | null) ?? "light");
  const [language, setLanguage] = useState<LanguageMode>(() => (window.localStorage.getItem("cyberdecision.language") as LanguageMode | null) ?? "es");
  const [collapsed, setCollapsed] = useState(() => window.localStorage.getItem("cyberdecision.sidebar.collapsed") === "true");
  const [isOnline, setIsOnline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const labels = appCopy[language];

  const currentUser = useMemo(() => users.find((user) => user.id === sessionUserId) ?? null, [sessionUserId, users]);
  const domains = useMemo(() => parseDomains(rawDomains), [rawDomains]);
  const competitorDomains = useMemo(() => parseDomains(rawCompetitorDomains), [rawCompetitorDomains]);
  const reusableScopeProfile = useMemo(() => {
    if (domains.length < 2 || organizationName.trim()) return null;
    const key = [...domains].sort().join("|");
    return runs.find((run) =>
      run.status === "completed" &&
      Boolean(run.request.organization_name?.trim()) &&
      [...run.domains].sort().join("|") === key
    ) ?? null;
  }, [domains, organizationName, runs]);
  const selectedRun = selectedRunId ? runs.find((run) => run.id === selectedRunId) : undefined;
  const dashboardRun = useMemo(() => selectDashboardRun(selectedRun, runs), [runs, selectedRun]);
  const evidenceRun = activeView === "dashboards" ? dashboardRun : selectedRun;
  const isRunning = runs.some((run) => run.status === "queued" || run.status === "running");
  const countryOptions = useMemo(() => countriesFor([ALL_CONTINENTS]), []);

  function handleLogin(user: LocalUser) {
    writeSession(user.id);
    setSessionUserId(user.id);
    if (user.mustChangePassword) setActiveView("settings");
    setSessionNotice(null);
  }

  function handleLogout(reason?: "expired" | "manual") {
    clearSession();
    setSessionUserId(null);
    setSelectedRunId(null);
    setActiveView("dashboards");
    setSessionNotice(
      reason === "expired"
        ? language === "es"
          ? "Sesion cerrada por inactividad o vencimiento de seguridad."
          : "Session closed because it expired or was inactive."
        : null
    );
  }

  const refreshReports = useCallback(async () => {
    const nextReports = await listReports();
    setReports(nextReports);
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      const [nextRuns, nextReports] = await Promise.all([listRuns(), listReports()]);
      setRuns(nextRuns);
      setReports(nextReports);
      setIsOnline(true);
      setError(null);
      setSelectedRunId((current) => (current && nextRuns.some((run) => run.id === current) ? current : latestCompletedWithData(nextRuns)?.id ?? null));
    } catch (exc) {
      setIsOnline(false);
      setError(exc instanceof Error ? exc.message : labels.apiError);
    }
  }, [labels.apiError]);

  useEffect(() => {
    if (!currentUser) return;
    refreshRuns();
    const timer = window.setInterval(refreshRuns, 2500);
    return () => window.clearInterval(timer);
  }, [currentUser, refreshRuns]);

  useEffect(() => {
    if (sessionUserId && !currentUser) {
      clearSession();
      setSessionUserId(null);
    }
  }, [currentUser, sessionUserId]);

  useEffect(() => {
    if (!currentUser) return;
    let lastTouch = 0;
    const expire = () => handleLogout("expired");
    const checkSession = () => {
      const session = readSession(Date.now(), sessionPolicyForUser(currentUser));
      if (!session || session.userId !== currentUser.id) expire();
    };
    const refreshActivity = () => {
      const now = Date.now();
      if (now - lastTouch < 30_000) return;
      lastTouch = now;
      if (!touchSession(currentUser.id, now, sessionPolicyForUser(currentUser))) expire();
    };
    const activityEvents = ["pointerdown", "keydown", "mousemove", "scroll"];
    activityEvents.forEach((eventName) => window.addEventListener(eventName, refreshActivity, { passive: true }));
    window.addEventListener("focus", checkSession);
    document.addEventListener("visibilitychange", checkSession);
    const timer = window.setInterval(checkSession, 60_000);
    return () => {
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, refreshActivity));
      window.removeEventListener("focus", checkSession);
      document.removeEventListener("visibilitychange", checkSession);
      window.clearInterval(timer);
    };
  }, [currentUser?.id, language]);

  useEffect(() => {
    if (!currentUser) return;
    let disposed = false;
    getLicensingOverview()
      .then((overview) => {
        if (disposed) return;
        setUsers((currentUsers) => {
          let changed = false;
          const nextUsers = currentUsers.map((user) => {
            const controlUser = overview.users.find((item) => item.username.toLowerCase() === user.username.toLowerCase());
            if (!controlUser) return user;
            const company = overview.companies.find((item) => item.id === controlUser.company_id);
            const nextUser = {
              ...user,
              role: controlUser.role,
              companyId: controlUser.company_id,
              companyName: company?.name ?? user.companyName,
              licenseModules: controlUser.effective_modules
            };
            changed ||= JSON.stringify({
              role: user.role,
              companyId: user.companyId,
              companyName: user.companyName,
              licenseModules: user.licenseModules ?? []
            }) !== JSON.stringify({
              role: nextUser.role,
              companyId: nextUser.companyId,
              companyName: nextUser.companyName,
              licenseModules: nextUser.licenseModules ?? []
            });
            return nextUser;
          });
          if (changed) saveUsers(nextUsers);
          return changed ? nextUsers : currentUsers;
        });
      })
      .catch(() => {
        // Licensing is a control-plane enhancement; keep the local lab login usable if the API is offline.
      });
    return () => {
      disposed = true;
    };
  }, [currentUser?.username]);

  useEffect(() => {
    if (!currentUser) return;
    window.localStorage.removeItem(`${scopeDefaultsPrefix}${currentUser.id}`);
  }, [currentUser?.id]);

  useEffect(() => {
    window.localStorage.setItem("cyberdecision.theme", theme);
    window.localStorage.setItem("cyberdecision.language", language);
    window.localStorage.setItem("cyberdecision.sidebar.collapsed", String(collapsed));
    document.documentElement.dataset.theme = theme;
  }, [collapsed, language, theme]);

  useEffect(() => {
    if (!currentUser) return;
    if (!hasViewAccess(currentUser, activeView)) {
      setActiveView(allViews.find((view) => hasViewAccess(currentUser, view)) ?? "dashboards");
    }
  }, [activeView, currentUser]);

  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("view", activeView);
    window.history.replaceState({ view: activeView }, "", `${url.pathname}${url.search}${url.hash}`);
  }, [activeView]);

  useEffect(() => {
    const handleNavigation = () => setActiveView(initialViewFromUrl());
    window.addEventListener("popstate", handleNavigation);
    return () => window.removeEventListener("popstate", handleNavigation);
  }, []);

  function handleUsersChange(nextUsers: LocalUser[]) {
    setUsers(nextUsers);
    saveUsers(nextUsers);
  }

  async function handleRun() {
    await createAnalysisRun();
  }

  async function createAnalysisRun(overrides: Partial<Parameters<typeof createAnalysis>[0]> = {}) {
    setError(null);
    try {
      const windowConfig = analysisWindowConfig(analysisWindow);
      const targetSectors = selectedWithoutAll(selectedSectors, ALL_SECTORS);
      const targetCountries = selectedWithoutAll(selectedCountries, ALL_COUNTRIES);
      const run = await createAnalysis({
        domains,
        competitor_domains: competitorDomains,
        subject_type: "organization",
        organization_name: organizationName.trim() || undefined,
        person_name: undefined,
        sector: targetSectors.join(", "),
        country: targetCountries.join(", "),
        language,
        mode,
        analysis_window: windowConfig.value,
        lookback_hours: windowConfig.hours,
        lookback_days: windowConfig.days,
        real_only: realOnly,
        authorized_scope: authorizedScope,
        allow_tor: authorizedScope && allowTor,
        scan_time_budget_minutes: scanTimeBudgetMinutes,
        report_display_at: currentUser?.role === "super_admin" && reportDisplayAt.trim() ? reportDisplayAt.trim() : undefined,
        ...overrides
      });
      setSelectedRunId(run.id);
      setRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      if (!organizationName.trim() && run.request.organization_name) {
        setOrganizationName(run.request.organization_name);
      }
      setActiveView("dashboards");
      await refreshRuns();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : labels.startError);
    }
  }

  async function handleAssistedRun() {
    await createAnalysisRun({
      mode: "deep",
      real_only: true,
      authorized_scope: true,
      allow_tor: true
    });
  }

  async function handleRerun() {
    if (!selectedRun) return;
    await handleRerunRun(selectedRun.id);
  }

  async function handleRerunRun(runId: string) {
    setError(null);
    try {
      const run = await rerunAnalysis(runId);
      setSelectedRunId(run.id);
      setActiveView("dashboards");
      await refreshRuns();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : labels.refreshError);
    }
  }

  async function handleGenerateReport(runId: string) {
    setError(null);
    try {
      const run = await generateRunReport(runId);
      setSelectedRunId(run.id);
      setRuns((current) => current.map((item) => (item.id === run.id ? run : item)));
      await refreshReports();
      await refreshRuns();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : labels.refreshError);
    }
  }

  async function handleDeleteReport(report: ReportCatalogItem) {
    if (!["super_admin", "admin"].includes(currentUser?.role ?? "viewer")) return;
    const confirmed = window.confirm(language === "es" ? `Eliminar informe ${report.name}?` : `Delete report ${report.name}?`);
    if (!confirmed) return;
    setError(null);
    try {
      await deleteReport(report.url.replace(/^\/reports\//, ""));
      await refreshReports();
      await refreshRuns();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : labels.refreshError);
    }
  }

  function removeDomain(domain: string) {
    markScopeTouched();
    setRawDomains((current) =>
      parseDomains(current)
        .filter((item) => item !== domain)
        .join("\n")
    );
  }

  function handleRawDomainsChange(value: string) {
    markScopeTouched();
    setRawDomains(value);
  }

  function handleRawCompetitorDomainsChange(value: string) {
    markScopeTouched();
    setRawCompetitorDomains(value);
  }

  function handleOrganizationNameChange(value: string) {
    markScopeTouched();
    setOrganizationName(value);
  }

  function handleSectorsChange(values: string[]) {
    markScopeTouched();
    setSelectedSectors(values.length ? values : [ALL_SECTORS]);
  }

  function handleCountriesChange(values: string[]) {
    markScopeTouched();
    setSelectedCountries(values.length ? values : [ALL_COUNTRIES]);
  }

  function handleModeChange(value: AnalysisMode) {
    markScopeTouched();
    setMode(value);
  }

  function handleAnalysisWindowChange(value: AnalysisWindow) {
    markScopeTouched();
    setAnalysisWindow(value);
  }

  function handleScanTimeBudgetChange(value: number) {
    markScopeTouched();
    setScanTimeBudgetMinutes(value);
  }

  function handleReportDisplayAtChange(value: string) {
    markScopeTouched();
    setReportDisplayAt(value);
  }

  function handleRealOnlyChange(value: boolean) {
    markScopeTouched();
    setRealOnly(value);
  }

  function handleAuthorizedScopeChange(value: boolean) {
    markScopeTouched();
    setAuthorizedScope(value);
  }

  function handleAllowTorChange(value: boolean) {
    markScopeTouched();
    setAllowTor(value);
  }

  function markScopeTouched() {
    setHasTouchedDomains(true);
    setSelectedRunId(null);
    setScopeDefaultMessage(null);
  }

  function saveDefaultScope() {
    if (!currentUser || !["super_admin", "admin"].includes(currentUser.role)) return;
    window.localStorage.removeItem(`${scopeDefaultsPrefix}${currentUser.id}`);
    setScopeDefaultMessage(
      language === "es"
        ? "Sin alcance por default: las busquedas solo usan datos ingresados manualmente."
        : "No default scope: searches only use manually entered data."
    );
  }

  const domainComposerProps = {
    rawDomains,
    rawCompetitorDomains,
    organizationName,
    domains,
    competitorDomains,
    selectedSectors,
    selectedCountries,
    sectorOptions: economicSectors,
    countryOptions,
    language,
    mode,
    analysisWindow,
    scanTimeBudgetMinutes,
    reportDisplayAt,
    canOverrideReportDate: currentUser?.role === "super_admin",
    realOnly,
    authorizedScope,
    allowTor,
    isRunning,
    onRawDomainsChange: handleRawDomainsChange,
    onRawCompetitorDomainsChange: handleRawCompetitorDomainsChange,
    onOrganizationNameChange: handleOrganizationNameChange,
    onSectorsChange: handleSectorsChange,
    onCountriesChange: handleCountriesChange,
    onModeChange: handleModeChange,
    onAnalysisWindowChange: handleAnalysisWindowChange,
    onScanTimeBudgetChange: handleScanTimeBudgetChange,
    onReportDisplayAtChange: handleReportDisplayAtChange,
    onRealOnlyChange: handleRealOnlyChange,
    onAuthorizedScopeChange: handleAuthorizedScopeChange,
    onAllowTorChange: handleAllowTorChange,
    onRemoveDomain: removeDomain,
    onRun: handleRun,
    onAssistedRun: handleAssistedRun,
    canSaveDefaults: false,
    onSaveDefaults: saveDefaultScope,
    defaultScopeMessage: scopeDefaultMessage,
    reusableScopeName: reusableScopeProfile?.request.organization_name ?? null
  };

  function renderView() {
    if (activeView === "dashboards") return <StrategicDashboard run={dashboardRun} language={language} />;
    if (activeView === "scenarios") return <ScenarioDecisionView run={selectedRun} language={language} />;
    if (activeView === "attackSurface") return <AttackSurfaceView run={selectedRun} competitorDomains={competitorDomains} language={language} />;
    if (activeView === "brand") return <BrandRiskView run={selectedRun} language={language} />;
    if (activeView === "employeeRisk") return <EmployeeRiskView language={language} onReportReady={refreshReports} />;
    if (activeView === "disinformation") return <DisinformationView run={selectedRun} language={language} />;
    if (activeView === "osint") return <SourceIntelligenceView run={selectedRun} channel="osint" language={language} />;
    if (activeView === "socmint") return <SocmintView run={selectedRun} language={language} />;
    if (activeView === "darkweb") return <SourceIntelligenceView run={selectedRun} channel="darkweb" language={language} />;
    if (activeView === "frameworks") return <FrameworksView run={selectedRun} language={language} />;
    if (activeView === "ai") return <AIAssistantView run={selectedRun} language={language} />;
    if (activeView === "runs") return <RunsView runs={runs} language={language} onOpenRun={(runId) => { setSelectedRunId(runId); setActiveView("dashboards"); }} onGenerateReport={handleGenerateReport} />;
    if (activeView === "reports") {
      return (
        <ReportsView
          reports={reports}
          runs={runs}
          language={language}
          canDelete={["super_admin", "admin"].includes(currentUser?.role ?? "viewer")}
          onDelete={handleDeleteReport}
          onOpenRun={(runId) => { setSelectedRunId(runId); setActiveView("dashboards"); }}
          onRerunRun={handleRerunRun}
          onGenerateReport={handleGenerateReport}
        />
      );
    }
    if (activeView === "help" && currentUser) return <UsageGuideView language={language} role={currentUser.role} />;
    if (activeView === "settings" && currentUser) {
      return (
        <SettingsView
          currentUser={currentUser}
          users={users}
          theme={theme}
          language={language}
          sourceStatuses={selectedRun?.summary.source_statuses ?? []}
          sourceRunId={selectedRun?.id}
          sourceUpdatedAt={selectedRun?.updated_at}
          onUsersChange={handleUsersChange}
          onThemeChange={setTheme}
          onLanguageChange={setLanguage}
        />
      );
    }
    return (
      <>
        <PlatformBrief language={language} />
        <section className="overview-scope-workspace" aria-label={language === "es" ? "Configuración y monitoreo del análisis" : "Analysis setup and monitoring"}>
          <DomainsView {...domainComposerProps} />
        </section>
        {selectedRun ? (
          <section className="overview-board">
            <div className="overview-column overview-intelligence-column">
            <KpiStrip
              language={language}
              kpis={selectedRun.summary.kpis}
              findingCount={selectedRun.summary.findings.length}
            />
              <RiskTrend signals={selectedRun.summary.domain_signals} language={language} />
              <FindingsTable findings={selectedRun.summary.findings} language={language} />
            </div>
            <div className="overview-column overview-operation-column">
              <RunTimeline run={selectedRun} onRerun={handleRerun} onGenerateReport={handleGenerateReport} language={language} />
            </div>
          </section>
        ) : (
          <section className="panel overview-empty-state">
            <strong>{language === "es" ? "Sin análisis seleccionado" : "No analysis selected"}</strong>
            <span>{language === "es" ? "Define el alcance arriba para iniciar una corrida trazable." : "Define the scope above to start a traceable run."}</span>
          </section>
        )}
      </>
    );
  }

  if (!currentUser) {
    return (
      <LoginView
        users={users}
        language={language}
        theme={theme}
        onLanguageChange={setLanguage}
        onThemeChange={setTheme}
        onLogin={handleLogin}
        onUsersChange={handleUsersChange}
        sessionMessage={sessionNotice}
      />
    );
  }

  return (
    <AppShell
      isOnline={isOnline}
      activeView={activeView}
      currentUser={currentUser}
      theme={theme}
      language={language}
      collapsed={collapsed}
      onCollapsedChange={setCollapsed}
      onViewChange={(view) => {
        if (hasViewAccess(currentUser, view)) setActiveView(view);
      }}
      onThemeChange={setTheme}
      onLanguageChange={setLanguage}
      onLogout={handleLogout}
    >
      <main className="workspace">
        <header className="topbar">
          <div>
            <h1>{viewTitles[language][activeView]}</h1>
            <p>
              CyberDecisionEngine -{" "}
              {selectedRun
                ? `${language === "es" ? "Última actualización" : "Last update"} ${formatDateTime(selectedRun.updated_at)}`
                : language === "es"
                  ? "sin análisis seleccionado"
                  : "no analysis selected"}
            </p>
          </div>
        </header>

        {error ? <div className="error-banner">{error}</div> : null}
        <AnalysisContextBar
          run={selectedRun}
          language={language}
          draftOrganizationName={organizationName}
          draftSubjectType="organization"
          draftDomains={domains}
          draftAnalysisWindow={analysisWindow}
        />
        <Suspense fallback={<div className="module-loading" role="status">{language === "es" ? "Cargando módulo..." : "Loading module..."}</div>}>
          {renderView()}
        </Suspense>
        {evidenceRun && evidenceViews.includes(activeView) ? <EvidenceLedger run={evidenceRun} language={language} view={activeView} /> : null}
      </main>
    </AppShell>
  );
}
