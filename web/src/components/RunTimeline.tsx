import { Brain, CheckCircle2, CircleDashed, Clock3, FileCheck2, FileText, Globe2, Network, RadioTower, RotateCcw, Search, ShieldCheck, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { LanguageMode, RunRecord } from "../types";
import { formatDateTime } from "../utils/format";

interface RunTimelineProps {
  run?: RunRecord;
  onRerun: () => void;
  onGenerateReport: (runId: string) => void;
  language: LanguageMode;
}

const labels = {
  es: {
    title: "Estado de corrida",
    noRun: "Sin corrida activa",
    progress: "Progreso de corrida",
    queued: "En cola",
    waiting: "Esperando",
    failed: "Fallida",
    completed: "Completada",
    reportGenerated: "Informe generado",
    analysisReady: "Análisis listo",
    generateReport: "Generar informe",
    pending: "Pendiente",
    openReport: "Abrir informe",
    refreshData: "Reejecutar análisis",
    percent: "avance",
    etaReady: "Finalizando",
    eta: "estimado restante",
    process: "Proceso de análisis",
    currentStage: "Etapa actual",
    completedStep: "Completo",
    currentStep: "En proceso",
    pendingStep: "Pendiente",
    issueStep: "Revisar",
    records: "registros",
    backgroundSafe: "La corrida sigue en backend aunque cierre sesión por inactividad; vuelve a entrar y verás el avance/historial."
  },
  en: {
    title: "Run status",
    noRun: "No active run",
    progress: "Run progress",
    queued: "Queued",
    waiting: "Waiting",
    failed: "Failed",
    completed: "Completed",
    reportGenerated: "Report generated",
    analysisReady: "Analysis ready",
    generateReport: "Generate report",
    pending: "Pending",
    openReport: "Open report",
    refreshData: "Run analysis again",
    percent: "complete",
    etaReady: "Finishing",
    eta: "estimated remaining",
    process: "Analysis process",
    currentStage: "Current stage",
    completedStep: "Complete",
    currentStep: "In progress",
    pendingStep: "Pending",
    issueStep: "Review",
    records: "records",
    backgroundSafe: "The run continues in the backend even if the session expires; sign back in to see progress/history."
  }
};

export function RunTimeline({ run, onRerun, onGenerateReport, language }: RunTimelineProps) {
  const copy = labels[language];
  const status = run?.status ?? "queued";
  const isDone = status === "completed";
  const isFailed = status === "failed";
  const visibleProgress = estimatedProgress(run);
  const progressTone = progressToneFor(run, visibleProgress);
  const eta = estimatedRemaining(run, visibleProgress, language);
  const processSteps = buildProcessSteps(run, language, visibleProgress);
  const processSummary = summarizeProcess(processSteps);
  const currentStage = isDone ? (run?.report ? copy.reportGenerated : copy.analysisReady) : isFailed ? copy.failed : run?.stage || copy.waiting;

  return (
    <aside className="panel timeline-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{run ? `#${run.id}` : copy.noRun}</p>
        </div>
        <span className={`run-pill ${status}`}>{runStatusText(status, language)}</span>
      </div>

      <div className="run-progress-head">
        <strong>{visibleProgress}% {copy.percent}</strong>
        <span>{isDone ? currentStage : eta || copy.etaReady}</span>
      </div>
      <div className={`progress-shell ${progressTone}`} aria-label={copy.progress}>
        <span style={{ width: `${visibleProgress}%` }} />
      </div>
      <div className={`run-stage-current ${status}`}>
        <span>{copy.currentStage}</span>
        <strong>{currentStage}</strong>
      </div>
      {run?.status === "running" || run?.status === "queued" ? <p className="run-background-note">{copy.backgroundSafe}</p> : null}

      <div className="run-process-panel">
        <div className="run-checklist-head">
          <FileCheck2 size={15} />
          <strong>{copy.process}</strong>
        </div>
        <div className="run-process-summary">
          <span className="done"><b>{processSummary.done}</b>{copy.completedStep}</span>
          <span className="current"><b>{processSummary.current}</b>{copy.currentStep}</span>
          <span className="pending"><b>{processSummary.pending}</b>{copy.pendingStep}</span>
        </div>
        <div className="run-process-list">
          {processSteps.map((step) => (
            <div className={`run-process-step ${step.status}`} key={step.id}>
              <span className="run-process-icon">{step.icon}</span>
              <div className="run-process-copy">
                <strong>{step.label}</strong>
                <span>{step.detail}</span>
              </div>
              <div className="run-process-step-status">
                <i />
                <em>{statusText(step.status, language)}</em>
              </div>
            </div>
          ))}
        </div>
      </div>

      <ol className="timeline">
        <li className={run ? "done" : ""}>
          <Clock3 size={17} />
          <div>
            <strong>{copy.queued}</strong>
            <span>{formatDateTime(run?.created_at)}</span>
          </div>
        </li>
        <li className={status === "running" || isDone ? "done" : ""}>
          <RotateCcw size={17} />
          <div>
            <strong>{run?.stage ?? copy.waiting}</strong>
            <span>{formatDateTime(run?.updated_at)}</span>
          </div>
        </li>
        <li className={isDone ? "done" : isFailed ? "failed" : ""}>
          {isFailed ? <XCircle size={17} /> : <CheckCircle2 size={17} />}
          <div>
            <strong>{isFailed ? copy.failed : copy.completed}</strong>
            <span>{run?.error ?? (isDone ? (run?.report ? copy.reportGenerated : copy.analysisReady) : copy.pending)}</span>
          </div>
        </li>
      </ol>

      <div className="run-action-row">
        {run?.report ? (
          <a className="report-button" href={run.report.url} target="_blank" rel="noreferrer">
            <FileText size={18} />
            <span>{copy.openReport}</span>
          </a>
        ) : run?.status === "completed" ? (
          <button className="report-button" type="button" onClick={() => onGenerateReport(run.id)}>
            <FileText size={18} />
            <span>{copy.generateReport}</span>
          </button>
        ) : null}
        {run && (isDone || isFailed) ? (
          <button className="secondary-button" type="button" onClick={onRerun}>
            <RotateCcw size={17} />
            <span>{copy.refreshData}</span>
          </button>
        ) : null}
      </div>
    </aside>
  );
}

interface ProcessStep {
  id: string;
  label: string;
  detail: string;
  status: "done" | "current" | "pending" | "issue";
  icon: ReactNode;
}

function buildProcessSteps(run: RunRecord | undefined, language: LanguageMode, progress: number): ProcessStep[] {
  const copy = {
    es: {
      scope: ["Alcance y parámetros", "Dominios, marca/conglomerado, ventana de tiempo y país objetivo."],
      dorks: ["Búsquedas públicas y dorks", "Consultas públicas por dominio, marca, fraude, archivos expuestos y menciones."],
      sources: ["Noticias, vulnerabilidades y fuentes abiertas", "Señales de noticias, Hacker News, vulnerabilidades y fuentes públicas configuradas."],
      surface: ["Superficie externa", "DNS, certificados, WHOIS, subdominios, tecnologías y exposición externa."],
      socmint: ["SOCMINT, marca y fraude", "Menciones públicas, redes sociales indexadas, similitud de dominio y narrativa de fraude."],
      darkweb: ["Dark web autorizada", "Revisión segura de índices, filtraciones y señales públicas sin interacción riesgosa."],
      scenarios: ["Escenarios y frameworks", "MITRE ATT&CK, DEFEND, ATLAS, DISARM, PESTEL, Porter y controles aplicables."],
      report: ["Riesgo e informes HTML", "Cálculo de riesgo, predicción, recomendaciones y generación de informes HTML."]
    },
    en: {
      scope: ["Scope and parameters", "Domains, brand/group, time window and target country."],
      dorks: ["Public searches and dorks", "Public queries by domain, brand, fraud, exposed files and mentions."],
      sources: ["News, vulnerabilities and open sources", "Signals from news, Hacker News, vulnerabilities and configured public sources."],
      surface: ["External surface", "DNS, certificates, WHOIS, subdomains, technologies and external exposure."],
      socmint: ["SOCMINT, brand and fraud", "Public mentions, indexed social networks, domain similarity and fraud narratives."],
      darkweb: ["Authorized dark web", "Safe review of indexes, leaks and public signals without risky interaction."],
      scenarios: ["Scenarios and frameworks", "MITRE ATT&CK, DEFEND, ATLAS, DISARM, PESTEL, Porter and applicable controls."],
      report: ["Risk and HTML reports", "Risk scoring, prediction, recommendations and HTML report generation."]
    }
  }[language];
  const sources = run?.summary.source_statuses ?? [];
  const events = run?.summary.events ?? [];
  const findings = run?.summary.findings ?? [];
  const doneAll = run?.status === "completed";
  const failed = run?.status === "failed";
  const hasSource = (patterns: RegExp[]) => sources.some((source) => patterns.some((pattern) => pattern.test(`${source.name} ${source.warning ?? ""}`)));
  const hasEvent = (patterns: RegExp[]) => events.some((event) => patterns.some((pattern) => pattern.test(`${event.source} ${event.category} ${event.title} ${(event.tags ?? []).join(" ")}`)));
  const records = (patterns: RegExp[]) =>
    sources
      .filter((source) => patterns.some((pattern) => pattern.test(`${source.name} ${source.warning ?? ""}`)))
      .reduce((sum, source) => sum + (source.records ?? 0), 0);
  const step = (
    id: string,
    label: string,
    detail: string,
    threshold: number,
    icon: ReactNode,
    active: boolean,
    recordPatterns: RegExp[] = []
  ): ProcessStep => {
    const count = records(recordPatterns);
    const suffix = count > 0 ? ` · ${count} ${language === "es" ? "registros" : "records"}` : "";
    const status: ProcessStep["status"] =
      id === "report"
        ? run?.report
          ? "done"
          : doneAll
            ? "current"
            : progress >= Math.max(0, threshold - 12) || active
              ? "current"
              : "pending"
        : failed && progress >= threshold
          ? "issue"
          : doneAll || progress >= threshold
            ? "done"
            : progress >= Math.max(0, threshold - 12) || active
              ? "current"
              : "pending";
    return { id, label, detail: `${detail}${suffix}`, status, icon };
  };
  return [
    step("scope", copy.scope[0], copy.scope[1], 8, <Globe2 size={16} />, Boolean(run), []),
    step("dorks", copy.dorks[0], copy.dorks[1], 30, <Search size={16} />, hasSource([/internet|search|osint|google|duckduckgo/i]) || hasEvent([/query|dork|filetype|site:/i]), [/internet|search|osint|google|duckduckgo/i]),
    step("sources", copy.sources[0], copy.sources[1], 44, <RadioTower size={16} />, hasSource([/hacker|news|gdelt|rss|cisa|nvd|kev|epss|github/i]) || hasEvent([/hacker|news|gdelt|rss|cve|kev|epss|vulnerab/i]), [/hacker|news|gdelt|rss|cisa|nvd|kev|epss|github/i]),
    step("surface", copy.surface[0], copy.surface[1], 56, <ShieldCheck size={16} />, hasSource([/surface|dns|whois|ssl|certificate|subdomain|port|http|technology|kali/i]) || hasEvent([/dns|whois|ssl|certificate|subdomain|port|surface/i]), [/surface|dns|whois|ssl|certificate|subdomain|port|http|technology|kali/i]),
    step("socmint", copy.socmint[0], copy.socmint[1], 66, <Network size={16} />, hasSource([/socmint|social|brand|fraud|facebook|instagram|tiktok|linkedin|twitter|\bx\b/i]) || hasEvent([/socmint|social|brand|fraud|facebook|instagram|tiktok|linkedin|twitter|\bx\b/i]), [/socmint|social|brand|fraud|facebook|instagram|tiktok|linkedin|twitter|\bx\b/i]),
    step("darkweb", copy.darkweb[0], copy.darkweb[1], 74, <ShieldCheck size={16} />, hasSource([/dark|tor|onion|leak|ransom/i]) || hasEvent([/dark|tor|onion|leak|ransom/i]), [/dark|tor|onion|leak|ransom/i]),
    step("scenarios", copy.scenarios[0], copy.scenarios[1], 86, <Brain size={16} />, findings.length > 0 || hasEvent([/mitre|ttp|attack|defend|atlas|disarm|pestel|porter|framework/i]), []),
    step("report", copy.report[0], copy.report[1], 96, <FileText size={16} />, Boolean(run?.report), [])
  ];
}

function statusText(status: ProcessStep["status"], language: LanguageMode): string {
  const copy = labels[language];
  if (status === "done") return copy.completedStep;
  if (status === "current") return copy.currentStep;
  if (status === "issue") return copy.issueStep;
  return copy.pendingStep;
}

function summarizeProcess(steps: ProcessStep[]) {
  return steps.reduce(
    (summary, step) => {
      summary[step.status] += 1;
      return summary;
    },
    { done: 0, current: 0, pending: 0, issue: 0 }
  );
}

function runStatusText(status: RunRecord["status"], language: LanguageMode): string {
  const localized = {
    es: { queued: "En cola", running: "En proceso", completed: "Completada", failed: "Fallida" },
    en: { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed" }
  }[language];
  return localized[status] ?? status;
}

function estimatedProgress(run?: RunRecord): number {
  if (!run) return 0;
  if (run.status === "completed" || run.status === "failed") return 100;
  const base = run.progress ?? 0;
  if (run.status !== "running") return base;
  const created = Date.parse(run.created_at);
  if (!Number.isFinite(created)) return base;
  const elapsedSeconds = Math.max(0, (Date.now() - created) / 1000);
  const expectedSeconds = expectedDuration(run);
  const estimated = Math.min(92, Math.round(8 + (elapsedSeconds / expectedSeconds) * 84));
  return Math.max(base, estimated);
}

function progressToneFor(run: RunRecord | undefined, progress: number): string {
  if (!run) return "idle";
  if (run.status === "failed") return "failed";
  if (run.status === "completed") return run.report ? "completed" : "analysis-ready";
  if (progress >= 85) return "finalizing";
  if (progress >= 35) return "running";
  return "queued";
}

function expectedDuration(run: RunRecord): number {
  if (run.estimated_seconds && run.estimated_seconds > 0) return run.estimated_seconds;
  if (run.request.scan_time_budget_minutes > 0) return Math.min(14400, Math.max(120, run.request.scan_time_budget_minutes * 60));
  const domainCount = Math.max(1, run.domains.length || 1);
  const brandFactor = run.request.person_name?.trim() || run.request.organization_name?.trim() ? 1 : 0;
  const windowFactor = run.request.analysis_window === "180d" || run.request.analysis_window === "365d" ? 1.25 : run.request.analysis_window === "1h" || run.request.analysis_window === "24h" ? 0.85 : 1;
  return run.request.mode === "deep"
    ? Math.min(780, Math.round((150 + domainCount * 48 + brandFactor * 35) * windowFactor))
    : Math.min(420, Math.round((75 + domainCount * 26 + brandFactor * 20) * windowFactor));
}

function estimatedRemaining(run: RunRecord | undefined, progress: number, language: LanguageMode): string {
  if (!run || run.status !== "running") return "";
  const created = Date.parse(run.created_at);
  if (!Number.isFinite(created)) return "";
  const elapsedSeconds = Math.max(0, (Date.now() - created) / 1000);
  const total = expectedDuration(run);
  const remaining = Math.max(0, Math.round(total - elapsedSeconds));
  if (progress >= 92 || remaining <= 8) return language === "es" ? "Finalizando" : "Finishing";
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  const suffix = language === "es" ? "estimado restante" : "estimated remaining";
  return minutes > 0 ? `${minutes}m ${seconds}s ${suffix}` : `${seconds}s ${suffix}`;
}
