import { Activity, AlertCircle, BellRing, CalendarClock, CheckCircle2, ChevronDown, FileWarning, LifeBuoy, Pause, PlayCircle, RefreshCw, ScrollText, Send, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { createMonitoringProfile, createSupportTicket, getMonitoringOverview, updateMonitoringAlert, updateMonitoringProfile, updateSupportTicket } from "../api";
import type { DomainAnalysisRequest, MonitoringCadence, MonitoringOverview, RunRecord } from "../types";
import { formatDateTime } from "../utils/format";
import { DomainComposer } from "./DomainComposer";
import type { DomainComposerProps } from "./DomainComposer";
import type { AnalysisMode, AnalysisWindow, LanguageMode } from "../types";
import { analysisWindowConfig } from "../data/analysisWindows";

const runLabels = {
  es: {
    title: "Historial de analisis",
    subtitle: "Revision por solicitud: alcance, ventana, senales, riesgo, fuentes e informe generado",
    run: "Corrida",
    subject: "Objetivo principal",
    status: "Estado",
    stage: "Etapa",
    domains: "Dominios",
    window: "Rango",
    signals: "Senales",
    risk: "Riesgo",
    sources: "Fuentes",
    report: "Informe",
    updated: "Actualizado",
    open: "Abrir",
    openDashboard: "Abrir tablero",
    generate: "Generar informe",
    noReport: "Pendiente",
    noSubject: "Dominio único o grupo de dominios"
  },
  en: {
    title: "Analysis runs",
    subtitle: "Request-level review: scope, window, signals, risk, sources and generated report",
    run: "Run",
    subject: "Primary target",
    status: "Status",
    stage: "Stage",
    domains: "Domains",
    window: "Range",
    signals: "Signals",
    risk: "Risk",
    sources: "Sources",
    report: "Report",
    updated: "Updated",
    open: "Open",
    openDashboard: "Open dashboard",
    generate: "Generate report",
    noReport: "Pending",
    noSubject: "Single domain or domain group"
  }
};

const schedulerCopy = {
  es: {
    title: "Programar revisiones",
    subtitle: "Agenda local para relanzar el analisis con el alcance actual mientras la plataforma este abierta.",
    enabled: "Activar programacion",
    frequency: "Frecuencia",
    next: "Proxima ejecucion",
    last: "Ultima ejecucion",
    runNow: "Ejecutar ahora",
    disabled: "No programado",
    noRun: "Sin ejecucion registrada",
    options: {
      "1h": "Cada hora",
      "24h": "Diario",
      "7d": "Semanal",
      "30d": "Mensual"
    },
    note: "Para produccion se recomienda mover esta agenda a un worker/cron del backend."
  },
  en: {
    title: "Schedule reviews",
    subtitle: "Local schedule to rerun the analysis with the current scope while the platform is open.",
    enabled: "Enable schedule",
    frequency: "Frequency",
    next: "Next run",
    last: "Last run",
    runNow: "Run now",
    disabled: "Not scheduled",
    noRun: "No recorded run",
    options: {
      "1h": "Hourly",
      "24h": "Daily",
      "7d": "Weekly",
      "30d": "Monthly"
    },
    note: "For production, move this schedule to a backend worker/cron."
  }
};

export function RunsView({
  runs,
  language,
  onOpenRun,
  onGenerateReport
}: {
  runs: RunRecord[];
  language: LanguageMode;
  onOpenRun: (runId: string) => void;
  onGenerateReport: (runId: string) => void;
}) {
  const copy = runLabels[language];
  return (
    <section className="panel table-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{copy.run}</th>
              <th>{copy.subject}</th>
              <th>{copy.status}</th>
              <th>{copy.domains}</th>
              <th>{copy.window}</th>
              <th>{copy.signals}</th>
              <th>{copy.risk}</th>
              <th>{copy.sources}</th>
              <th>{copy.report}</th>
              <th>{copy.updated}</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>#{run.id}</td>
                <td>{run.request.person_name || run.request.organization_name || copy.noSubject}</td>
                <td><span className={`run-status-pill ${run.status}`}>{run.status}</span><small>{run.stage}</small></td>
                <td>{run.domains.join(", ")}</td>
                <td>{run.request.analysis_window}</td>
                <td>{run.summary.kpis.new_events}</td>
                <td>{run.summary.kpis.max_residual_risk == null ? "N/D" : run.summary.kpis.max_residual_risk.toFixed(1)}</td>
                <td>{run.summary.kpis.queried_sources ? `${run.summary.kpis.productive_sources ?? run.summary.kpis.healthy_sources}/${run.summary.kpis.queried_sources}` : "N/D"}</td>
                <td>
                  <span className="table-actions">
                    <button className="table-link button-link" type="button" onClick={() => onOpenRun(run.id)}>{copy.openDashboard}</button>
                    {run.report?.url ? (
                      <a href={run.report.url} target="_blank" rel="noreferrer">{copy.open}</a>
                    ) : run.status === "completed" ? (
                      <button className="table-link button-link" type="button" onClick={() => onGenerateReport(run.id)}>{copy.generate}</button>
                    ) : <span>{copy.noReport}</span>}
                  </span>
                </td>
                <td>{formatDateTime(run.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function DomainsView(props: DomainComposerProps) {
  return (
    <div className="view-stack">
      <DomainComposer {...props} />
      <ContinuousMonitoringPanel {...props} />
    </div>
  );
}

const monitoringCopy = {
  es: {
    title: "Monitoreo 24/7 y alertas",
    subtitle: "Perfiles persistentes de backend: recolectan, deduplican y generan alertas internas. Los informes HTML se generan solo cuando el usuario los solicita.",
    name: "Nombre del perfil",
    namePlaceholder: "Monitoreo ejecutivo del grupo",
    cadence: "Frecuencia",
    duration: "Tiempo maximo por ciclo",
    create: "Activar monitoreo",
    refresh: "Sincronizar estado",
    setup: "Configurar nuevo seguimiento",
    noScope: "Ingresa marca/grupo o dominio autorizado antes de activar monitoreo.",
    profiles: "Perfiles activos",
    alerts: "Alertas nuevas",
    logs: "Bitacora operativa",
    support: "Registro de falla o soporte",
    subject: "Asunto",
    description: "Describe que ocurre y donde lo viste",
    send: "Enviar a soporte",
    pause: "Pausar",
    resume: "Reanudar",
    emptyProfiles: "Sin perfiles de monitoreo.",
    emptyAlerts: "Sin alertas deduplicadas.",
    emptyLogs: "Sin eventos operativos.",
    alertsWord: "alertas",
    created: "Perfil creado. El backend lanzara la primera recoleccion y generara alertas, no informes automaticos.",
    ticketCreated: "Ticket enviado al centro de soporte.",
    profileMetric: "Perfiles",
    alertMetric: "Alertas abiertas",
    logMetric: "Registros de log",
    ticketMetric: "Tickets",
    acknowledge: "Reconocer",
    close: "Cerrar",
    falsePositive: "Falso positivo",
    review: "En revision",
    resolve: "Resolver",
    noTickets: "Sin tickets de soporte.",
    lastRun: "Ultima corrida",
    nextRun: "Siguiente",
    indefinite: "Indefinido por perfil activo",
    durationHint: "Cada ciclo recolecta hasta el tiempo seleccionado; el perfil queda activo hasta pausarlo.",
    cadences: {
      "1h": "Cada hora",
      "6h": "Cada 6 horas",
      "24h": "Diario",
      "7d": "Semanal",
      continuous: "Continuo 24/7",
      manual: "Manual"
    }
  },
  en: {
    title: "24/7 monitoring and alerts",
    subtitle: "Persistent backend profiles collect, deduplicate and create internal alerts. HTML reports are generated only when requested by the user.",
    name: "Profile name",
    namePlaceholder: "Executive group monitoring",
    cadence: "Cadence",
    duration: "Max time per cycle",
    create: "Enable monitoring",
    refresh: "Sync status",
    setup: "Configure new monitoring",
    noScope: "Enter an authorized brand/group or domain before enabling monitoring.",
    profiles: "Active profiles",
    alerts: "New alerts",
    logs: "Operational log",
    support: "Failure or support report",
    subject: "Subject",
    description: "Describe what happened and where you saw it",
    send: "Send to support",
    pause: "Pause",
    resume: "Resume",
    emptyProfiles: "No monitoring profiles.",
    emptyAlerts: "No deduplicated alerts.",
    emptyLogs: "No operational records.",
    alertsWord: "alerts",
    created: "Profile created. The backend will launch the first collection and create alerts, not automatic reports.",
    ticketCreated: "Ticket sent to support center.",
    profileMetric: "Profiles",
    alertMetric: "Open alerts",
    logMetric: "Log records",
    ticketMetric: "Tickets",
    acknowledge: "Acknowledge",
    close: "Close",
    falsePositive: "False positive",
    review: "In review",
    resolve: "Resolve",
    noTickets: "No support tickets.",
    lastRun: "Last run",
    nextRun: "Next",
    indefinite: "Indefinite while profile is active",
    durationHint: "Each cycle collects up to the selected duration; the profile stays active until paused.",
    cadences: {
      "1h": "Hourly",
      "6h": "Every 6 hours",
      "24h": "Daily",
      "7d": "Weekly",
      continuous: "Continuous 24/7",
      manual: "Manual"
    }
  }
};

type DomainViewProps = Parameters<typeof DomainsView>[0];

function ContinuousMonitoringPanel(props: DomainViewProps) {
  const copy = monitoringCopy[props.language];
  const [overview, setOverview] = useState<MonitoringOverview | null>(null);
  const [cadence, setCadence] = useState<MonitoringCadence>("24h");
  const [duration, setDuration] = useState(30);
  const [profileName, setProfileName] = useState("");
  const [supportSubject, setSupportSubject] = useState("");
  const [supportDescription, setSupportDescription] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeSection, setActiveSection] = useState<"profiles" | "alerts" | "logs" | "support">("profiles");
  const [setupOpen, setSetupOpen] = useState(false);
  const hasScope = props.domains.length > 0 || props.organizationName.trim().length > 0;

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 10_000);
    return () => window.clearInterval(timer);
  }, []);

  async function refresh() {
    try {
      setOverview(await getMonitoringOverview());
    } catch {
      // The panel remains usable when the monitoring API is temporarily unavailable.
    }
  }

  function buildRequest(): DomainAnalysisRequest {
    const windowConfig = analysisWindowConfig(props.analysisWindow);
    return {
      domains: props.domains,
      competitor_domains: props.competitorDomains,
      subject_type: "organization",
      organization_name: props.organizationName.trim() || undefined,
      person_name: undefined,
      sector: cleanScopeValues(props.selectedSectors).join(", "),
      country: cleanScopeValues(props.selectedCountries).join(", "),
      language: props.language,
      mode: props.mode,
      analysis_window: windowConfig.value,
      lookback_hours: windowConfig.hours,
      lookback_days: windowConfig.days,
      real_only: props.realOnly,
      authorized_scope: props.authorizedScope,
      allow_tor: props.authorizedScope && props.allowTor,
      scan_time_budget_minutes: duration,
      report_display_at: null
    };
  }

  async function createProfile() {
    if (!hasScope) {
      setMessage(copy.noScope);
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      await createMonitoringProfile({
        name: profileName.trim() || props.organizationName.trim() || props.domains.join(", "),
        request: buildRequest(),
        cadence,
        collection_duration_minutes: duration,
        enabled: cadence !== "manual",
        created_by: "web"
      });
      setProfileName("");
      setMessage(copy.created);
      await refresh();
    } catch (exc) {
      setMessage(exc instanceof Error ? exc.message : copy.noScope);
    } finally {
      setLoading(false);
    }
  }

  async function toggleProfile(profileId: string, enabled: boolean) {
    setLoading(true);
    try {
      await updateMonitoringProfile(profileId, { enabled });
      await refresh();
    } finally {
      setLoading(false);
    }
  }

  async function sendTicket() {
    if (!supportSubject.trim() || !supportDescription.trim()) return;
    setLoading(true);
    try {
      await createSupportTicket({
        subject: supportSubject.trim(),
        description: supportDescription.trim(),
        user: "web",
        severity: "medium"
      });
      setSupportSubject("");
      setSupportDescription("");
      setMessage(copy.ticketCreated);
      await refresh();
    } finally {
      setLoading(false);
    }
  }

  async function setAlertStatus(alertId: string, status: "acknowledged" | "closed" | "false_positive") {
    setLoading(true);
    try {
      await updateMonitoringAlert(alertId, { status, user: "web" });
      await refresh();
    } finally {
      setLoading(false);
    }
  }

  async function setTicketStatus(ticketId: string, status: "in_review" | "resolved") {
    setLoading(true);
    try {
      await updateSupportTicket(ticketId, { status, user: "web" });
      await refresh();
    } finally {
      setLoading(false);
    }
  }

  const profiles = overview?.profiles ?? [];
  const alerts = overview?.alerts ?? [];
  const logs = overview?.logs ?? [];
  const tickets = overview?.support_tickets ?? [];
  const openAlerts = alerts.filter((alert) => alert.status === "open").length;

  return (
    <section className="panel monitoring-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
        <BellRing size={20} />
      </div>
      <details className="monitoring-setup" open={setupOpen} onToggle={(event) => setSetupOpen(event.currentTarget.open)}>
        <summary>
          <span><Activity size={17} /> {copy.setup}</span>
          <ChevronDown size={17} />
        </summary>
        <div className="monitoring-control-grid">
          <label className="field-control">
            <span>{copy.name}</span>
            <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder={copy.namePlaceholder} />
          </label>
          <label className="field-control">
            <span>{copy.cadence}</span>
            <select value={cadence} onChange={(event) => setCadence(event.target.value as MonitoringCadence)}>
              {(["1h", "6h", "24h", "7d", "continuous", "manual"] as MonitoringCadence[]).map((item) => (
                <option key={item} value={item}>{copy.cadences[item]}</option>
              ))}
            </select>
          </label>
          <label className="field-control">
            <span>{copy.duration}</span>
            <select value={duration} onChange={(event) => setDuration(Number(event.target.value))}>
              {[10, 30, 60, 120, 240, 480, 1440].map((minutes) => (
                <option key={minutes} value={minutes}>{minutes < 60 ? `${minutes} min` : `${minutes / 60} h`}</option>
              ))}
            </select>
          </label>
          <button className="primary-button" type="button" disabled={loading || !hasScope} onClick={createProfile} title={copy.create}>
            <PlayCircle size={17} />
            <span>{copy.create}</span>
          </button>
        </div>
      </details>
      {message ? <div className="guided-alert compact"><AlertCircle size={17} /><p>{message}</p></div> : null}
      <div className="monitoring-kpi-row" role="tablist" aria-label={copy.title}>
        <button className={activeSection === "profiles" ? "active" : ""} type="button" role="tab" aria-selected={activeSection === "profiles"} onClick={() => setActiveSection("profiles")}>
          <ShieldCheck size={17} />
          <span>{copy.profileMetric}</span>
          <strong>{profiles.length}</strong>
        </button>
        <button className={activeSection === "alerts" ? "active" : ""} type="button" role="tab" aria-selected={activeSection === "alerts"} onClick={() => setActiveSection("alerts")}>
          <BellRing size={17} />
          <span>{copy.alertMetric}</span>
          <strong>{openAlerts}</strong>
        </button>
        <button className={activeSection === "logs" ? "active" : ""} type="button" role="tab" aria-selected={activeSection === "logs"} onClick={() => setActiveSection("logs")}>
          <ScrollText size={17} />
          <span>{copy.logMetric}</span>
          <strong>{logs.length}</strong>
        </button>
        <button className={activeSection === "support" ? "active" : ""} type="button" role="tab" aria-selected={activeSection === "support"} onClick={() => setActiveSection("support")}>
          <LifeBuoy size={17} />
          <span>{copy.ticketMetric}</span>
          <strong>{tickets.length}</strong>
        </button>
      </div>
      <div className="monitoring-toolbar">
        <strong>{activeSection === "profiles" ? copy.profiles : activeSection === "alerts" ? copy.alerts : activeSection === "logs" ? copy.logs : copy.support}</strong>
        <button className="secondary-button compact" type="button" onClick={refresh} disabled={loading} title={copy.refresh}>
          <RefreshCw className={loading ? "spin" : ""} size={16} />
          <span>{copy.refresh}</span>
        </button>
      </div>
      <div className="monitoring-workspace" role="tabpanel">
        {activeSection === "profiles" ? <article className="monitoring-card">
          <h3>{copy.profiles}</h3>
          {profiles.slice(0, 6).map((profile) => (
            <div className="monitoring-row" key={profile.id}>
              <div>
                <strong>{profile.name}</strong>
                <span>{copy.cadences[profile.cadence]} · {profile.alert_count} {copy.alertsWord}</span>
                <span>{copy.lastRun}: {profile.last_completed_at ? formatDateTime(profile.last_completed_at) : "N/A"} · {copy.nextRun}: {profile.next_run_at ? formatDateTime(profile.next_run_at) : copy.indefinite}</span>
                {profile.last_error ? <em>{profile.last_error}</em> : null}
              </div>
              <button className="table-link button-link" type="button" disabled={loading} onClick={() => toggleProfile(profile.id, profile.status !== "active")}>
                {profile.status === "active" ? <Pause size={14} /> : <PlayCircle size={14} />}
                {profile.status === "active" ? copy.pause : copy.resume}
              </button>
            </div>
          ))}
          {!profiles.length ? <p className="empty-state compact">{copy.emptyProfiles}</p> : null}
        </article> : null}
        {activeSection === "alerts" ? <article className="monitoring-card">
          <h3>{copy.alerts}</h3>
          {alerts.slice(0, 8).map((alert) => (
            <div className={`monitoring-row severity-${alert.severity}`} key={alert.id}>
              <div>
                <strong>{alert.title}</strong>
                <span>{alert.category} · {alert.severity} · {alert.status} · {formatDateTime(alert.created_at)}</span>
                <span>{alert.validation}</span>
                {alert.evidence_url ? <a href={alert.evidence_url} target="_blank" rel="noreferrer">{alert.evidence_url}</a> : null}
              </div>
              {alert.status === "open" ? (
                <div className="monitoring-actions">
                  <button className="icon-button" type="button" disabled={loading} title={copy.acknowledge} onClick={() => setAlertStatus(alert.id, "acknowledged")}><CheckCircle2 size={16} /></button>
                  <button className="icon-button" type="button" disabled={loading} title={copy.falsePositive} onClick={() => setAlertStatus(alert.id, "false_positive")}><XCircle size={16} /></button>
                </div>
              ) : (
                <button className="table-link button-link" type="button" disabled={loading} onClick={() => setAlertStatus(alert.id, "closed")}><CheckCircle2 size={14} />{copy.close}</button>
              )}
            </div>
          ))}
          {!alerts.length ? <p className="empty-state compact">{copy.emptyAlerts}</p> : null}
        </article> : null}
        {activeSection === "logs" ? <article className="monitoring-card">
          <h3>{copy.logs}</h3>
          {logs.slice(0, 8).map((log) => (
            <div className={`monitoring-row log-${log.level}`} key={log.id}>
              <FileWarning size={15} />
              <div>
                <strong>{log.component}</strong>
                <span>{log.message} · {formatDateTime(log.created_at)}</span>
              </div>
            </div>
          ))}
          {!logs.length ? <p className="empty-state compact">{copy.emptyLogs}</p> : null}
        </article> : null}
        {activeSection === "support" ? <article className="monitoring-card support-card">
          <h3>{copy.support}</h3>
          <input value={supportSubject} onChange={(event) => setSupportSubject(event.target.value)} placeholder={copy.subject} />
          <textarea value={supportDescription} onChange={(event) => setSupportDescription(event.target.value)} rows={4} placeholder={copy.description} />
          <button className="secondary-button" type="button" disabled={loading || !supportSubject.trim() || !supportDescription.trim()} onClick={sendTicket}>
            <Send size={16} />
            <span>{copy.send}</span>
          </button>
          <div className="ticket-list">
            {tickets.slice(0, 5).map((ticket) => (
              <div className={`monitoring-row log-${ticket.severity === "high" ? "error" : ticket.severity === "medium" ? "warning" : "info"}`} key={ticket.id}>
                <div>
                  <strong>{ticket.subject}</strong>
                  <span>{ticket.status} · {ticket.severity} · {formatDateTime(ticket.created_at)}</span>
                </div>
                {ticket.status !== "resolved" ? (
                  <button className="table-link button-link" type="button" disabled={loading} onClick={() => setTicketStatus(ticket.id, ticket.status === "open" ? "in_review" : "resolved")}>
                    {ticket.status === "open" ? copy.review : copy.resolve}
                  </button>
                ) : null}
              </div>
            ))}
            {!tickets.length ? <p className="empty-state compact">{copy.noTickets}</p> : null}
          </div>
        </article> : null}
      </div>
      <p className="scheduler-note">{copy.durationHint}</p>
    </section>
  );
}

function ScanScheduler({ language, domains, isRunning, onRun }: { language: LanguageMode; domains: string[]; isRunning: boolean; onRun: () => void }) {
  const copy = schedulerCopy[language];
  const storageKey = "cyberdecision.scanSchedule";
  const [enabled, setEnabled] = useState(false);
  const [frequency, setFrequency] = useState<"1h" | "24h" | "7d" | "30d">("24h");
  const [nextRunAt, setNextRunAt] = useState("");
  const [lastRunAt, setLastRunAt] = useState("");

  useEffect(() => {
    try {
      const saved = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
      setEnabled(Boolean(saved.enabled));
      if (["1h", "24h", "7d", "30d"].includes(saved.frequency)) setFrequency(saved.frequency);
      setNextRunAt(saved.nextRunAt || "");
      setLastRunAt(saved.lastRunAt || "");
    } catch {
      // Keep defaults if local storage has an old shape.
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(storageKey, JSON.stringify({ enabled, frequency, nextRunAt, lastRunAt }));
  }, [enabled, frequency, lastRunAt, nextRunAt]);

  useEffect(() => {
    if (!enabled && nextRunAt) setNextRunAt("");
    if (enabled && !nextRunAt) setNextRunAt(nextScheduleDate(frequency).toISOString());
  }, [enabled, frequency, nextRunAt]);

  useEffect(() => {
    if (!enabled || !nextRunAt) return;
    const timer = window.setInterval(() => {
      if (isRunning || !domains.length) return;
      if (Date.now() < Date.parse(nextRunAt)) return;
      setLastRunAt(new Date().toISOString());
      setNextRunAt(nextScheduleDate(frequency).toISOString());
      onRun();
    }, 30_000);
    return () => window.clearInterval(timer);
  }, [domains.length, enabled, frequency, isRunning, nextRunAt, onRun]);

  function updateFrequency(value: "1h" | "24h" | "7d" | "30d") {
    setFrequency(value);
    if (enabled) setNextRunAt(nextScheduleDate(value).toISOString());
  }

  function runNow() {
    if (isRunning || !domains.length) return;
    setLastRunAt(new Date().toISOString());
    setNextRunAt(enabled ? nextScheduleDate(frequency).toISOString() : "");
    onRun();
  }

  return (
    <section className="panel chart-card scan-scheduler-card">
      <div className="panel-title-row compact">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
        <CalendarClock size={18} />
      </div>
      <div className="scan-scheduler-grid">
        <label className="toggle-row">
          <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
          <span>{copy.enabled}</span>
        </label>
        <label>
          <span>{copy.frequency}</span>
          <select value={frequency} onChange={(event) => updateFrequency(event.target.value as typeof frequency)}>
            {Object.entries(copy.options).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
          </select>
        </label>
        <div>
          <span>{copy.next}</span>
          <strong>{enabled && nextRunAt ? formatDateTime(nextRunAt) : copy.disabled}</strong>
        </div>
        <div>
          <span>{copy.last}</span>
          <strong>{lastRunAt ? formatDateTime(lastRunAt) : copy.noRun}</strong>
        </div>
        <button className="primary-button" type="button" onClick={runNow} disabled={isRunning || !domains.length}>
          <PlayCircle size={17} />
          <span>{copy.runNow}</span>
        </button>
      </div>
      <p className="scheduler-note">{copy.note}</p>
    </section>
  );
}

function nextScheduleDate(frequency: "1h" | "24h" | "7d" | "30d"): Date {
  const msByFrequency = {
    "1h": 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000
  };
  return new Date(Date.now() + msByFrequency[frequency]);
}

function cleanScopeValues(values: string[]): string[] {
  return values.filter((value) => value && !/^all /i.test(value));
}
