import { Archive, BriefcaseBusiness, ExternalLink, FileDown, FileText, Trash2, Wrench } from "lucide-react";
import type { ReactNode } from "react";
import { apiUrl } from "../api";
import { analysisWindowLabel } from "../data/analysisWindows";
import type { LanguageMode, ReportCatalogItem, RunRecord } from "../types";
import { formatDateTime } from "../utils/format";
import { hasReadyReport } from "../utils/reportLifecycle";
import { preferredRunIdsBySubject } from "../utils/runSelection";

export function ReportsView({
  reports,
  runs,
  language,
  canDelete,
  onDelete,
  onOpenRun,
  onRerunRun,
  onGenerateReport
}: {
  reports: ReportCatalogItem[];
  runs: RunRecord[];
  language: LanguageMode;
  canDelete: boolean;
  onDelete: (report: ReportCatalogItem) => void;
  onOpenRun: (runId: string) => void;
  onRerunRun: (runId: string) => void;
  onGenerateReport: (runId: string) => void;
}) {
  const technicalReports = reports.filter(isTechnicalReport);
  const executiveReports = reports.filter((report) => !isTechnicalReport(report));
  const subjectsByRun = new Map(
    runs.map((run) => [
      run.id,
      run.request.organization_name?.trim()
        || run.request.person_name?.trim()
        || run.domains[0]
        || run.id
    ])
  );
  const copy = labels[language];
  const preferredRunIds = preferredRunIdsBySubject(runs);

  return (
    <section className="panel table-panel reports-workspace">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
        <div className="panel-action-row">
          <a className={`icon-text-button ${reports.length ? "" : "disabled-link"}`} href={apiUrl("/api/reports/archive")} download title={copy.downloadAllTitle}>
            <Archive size={17} />
            <span>{copy.downloadAll}</span>
          </a>
        </div>
      </div>

      <div className="report-columns">
        <ReportColumn
          icon={<BriefcaseBusiness size={18} />}
          title={copy.executive}
          subtitle={copy.executiveSubtitle}
          empty={copy.emptyExecutive}
          reports={executiveReports}
          typeLabel={copy.executiveType}
          openLabel={copy.open}
          downloadLabel={copy.download}
          deleteLabel={copy.delete}
          language={language}
          subjectsByRun={subjectsByRun}
          canDelete={canDelete}
          onDelete={onDelete}
        />
        <ReportColumn
          icon={<Wrench size={18} />}
          title={copy.technical}
          subtitle={copy.technicalSubtitle}
          empty={copy.emptyTechnical}
          reports={technicalReports}
          typeLabel={copy.technicalType}
          openLabel={copy.open}
          downloadLabel={copy.download}
          deleteLabel={copy.delete}
          language={language}
          subjectsByRun={subjectsByRun}
          canDelete={canDelete}
          onDelete={onDelete}
        />
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{copy.run}</th>
              <th>{copy.status}</th>
              <th>{copy.range}</th>
              <th>{copy.domains}</th>
              <th>{copy.updated}</th>
              <th>{copy.report}</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>
                  <span className="report-run-id">#{run.id}</span>
                  {preferredRunIds.has(run.id) ? (
                    <span className="status-chip status-chip-success">
                      {language === "es" ? "Más completa" : "Most complete"}
                    </span>
                  ) : null}
                </td>
                <td>{runStatusLabel(run, language)}</td>
                <td>{analysisWindowLabel(run.request, language)}</td>
                <td>{run.domains.join(", ")}</td>
                <td>{formatDateTime(run.updated_at, language)}</td>
                <td>
                  <span className="table-actions">
                    <button className="table-link button-link" type="button" onClick={() => onOpenRun(run.id)}>{copy.openDashboard}</button>
                    {hasReadyReport(run) && run.report ? (
                      <>
                      <a className="table-link" href={apiUrl(run.report.url)} target="_blank" rel="noreferrer">
                        {copy.openExecutive}
                      </a>
                      {run.report.technical_url ? (
                        <a className="table-link" href={apiUrl(run.report.technical_url)} target="_blank" rel="noreferrer">
                          {copy.openTechnical}
                        </a>
                      ) : null}
                      </>
                    ) : run.status === "completed" ? (
                      <button
                        className="table-link button-link"
                        type="button"
                        disabled={run.report_status === "queued" || run.report_status === "generating"}
                        onClick={() => onGenerateReport(run.id)}
                      >
                        {run.report_status === "queued"
                          ? copy.reportQueued
                          : run.report_status === "generating"
                            ? copy.reportGenerating
                            : run.report_status === "failed"
                              ? copy.retryReport
                              : copy.generate}
                      </button>
                    ) : (
                      <button className="table-link button-link" type="button" onClick={() => onRerunRun(run.id)}>{copy.rerun}</button>
                    )}
                  </span>
                </td>
              </tr>
            ))}
            {!runs.length ? (
              <tr>
                <td className="empty-cell" colSpan={6}>{copy.emptyHistory}</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ReportColumn({
  icon,
  title,
  subtitle,
  empty,
  reports,
  typeLabel,
  openLabel,
  downloadLabel,
  deleteLabel,
  language,
  subjectsByRun,
  canDelete,
  onDelete
}: {
  icon: ReactNode;
  title: string;
  subtitle: string;
  empty: string;
  reports: ReportCatalogItem[];
  typeLabel: string;
  openLabel: string;
  downloadLabel: string;
  deleteLabel: string;
  language: LanguageMode;
  subjectsByRun: ReadonlyMap<string, string>;
  canDelete: boolean;
  onDelete: (report: ReportCatalogItem) => void;
}) {
  return (
    <article className="report-column">
      <div className="report-column-head">
        {icon}
        <div>
          <strong>{title}</strong>
          <span>{subtitle}</span>
        </div>
        <em>{reports.length}</em>
      </div>
      <div className="report-list">
        {reports.map((report) => (
          <div className="report-row" key={report.path}>
            <FileText size={20} />
            <div>
              <strong title={report.name}>{reportDisplayName(report, subjectsByRun, language)}</strong>
              <span>
                {typeLabel} | {formatDateTime(report.modified_at, language)} | {Math.round(report.size_bytes / 1024)} KB
              </span>
            </div>
            <div className="report-actions">
              <a href={apiUrl(report.url)} target="_blank" rel="noreferrer" title={openLabel}>
                <ExternalLink size={15} />
                <span>{openLabel}</span>
              </a>
              <a href={apiUrl(report.download_url)} download title={downloadLabel}>
                <FileDown size={15} />
                <span>{downloadLabel}</span>
              </a>
              {canDelete ? (
                <button type="button" onClick={() => onDelete(report)} title={deleteLabel}>
                  <Trash2 size={15} />
                  <span>{deleteLabel}</span>
                </button>
              ) : null}
            </div>
          </div>
        ))}
        {!reports.length ? <div className="muted-empty">{empty}</div> : null}
      </div>
    </article>
  );
}

function isTechnicalReport(report: ReportCatalogItem): boolean {
  return report.report_type === "technical";
}

function reportDisplayName(
  report: ReportCatalogItem,
  subjectsByRun: ReadonlyMap<string, string>,
  language: LanguageMode
): string {
  const inferredRunId = report.name.match(/^([a-f0-9]{12})-/i)?.[1] ?? null;
  const runId = report.run_id || inferredRunId;
  const subject = runId ? subjectsByRun.get(runId) : null;
  if (subject && runId) {
    return `${subject} | ${language === "es" ? "corrida" : "run"} #${runId}`;
  }
  return report.name.replace(/cyberdeck/gi, "CyberDecisionEngine");
}

const labels = {
  es: {
    title: "Informes CyberDecisionEngine",
    subtitle: "Informes directivos y tecnicos separados para lectura ejecutiva, auditoria y trazabilidad.",
    downloadAll: "Descargar todos",
    downloadAllTitle: "Descarga todos los informes HTML generados en un archivo ZIP.",
    executive: "Informes directivos",
    executiveSubtitle: "Resumen ejecutivo, decision, riesgo y estrategia",
    technical: "Informes tecnicos",
    technicalSubtitle: "Evidencia, fuentes, metodologia y trazabilidad",
    executiveType: "Informe directivo",
    technicalType: "Informe tecnico",
    emptyExecutive: "Aun no hay informes directivos.",
    emptyTechnical: "Aun no hay informes tecnicos.",
    emptyHistory: "No hay corridas registradas.",
    run: "Corrida",
    status: "Estado",
    range: "Rango",
    domains: "Dominios",
    updated: "Actualizado",
    report: "Informe",
    open: "Abrir",
    openExecutive: "Abrir directivo",
    openTechnical: "Abrir técnico",
    download: "Descargar",
    delete: "Eliminar",
    pending: "Pendiente",
    openDashboard: "Ver tablero",
    generate: "Generar informe",
    reportQueued: "Informe en cola",
    reportGenerating: "Generando informe",
    retryReport: "Reintentar informe",
    rerun: "Reejecutar"
  },
  en: {
    title: "CyberDecisionEngine reports",
    subtitle: "Executive and technical reports separated for decision, audit and traceability.",
    downloadAll: "Download all",
    downloadAllTitle: "Downloads all generated HTML reports as a ZIP archive.",
    executive: "Executive reports",
    executiveSubtitle: "Executive summary, decision, risk and strategy",
    technical: "Technical reports",
    technicalSubtitle: "Evidence, sources, methodology and traceability",
    executiveType: "Executive report",
    technicalType: "Technical report",
    emptyExecutive: "No executive reports yet.",
    emptyTechnical: "No technical reports yet.",
    emptyHistory: "No runs recorded.",
    run: "Run",
    status: "Status",
    range: "Range",
    domains: "Domains",
    updated: "Updated",
    report: "Report",
    open: "Open",
    openExecutive: "Open executive",
    openTechnical: "Open technical",
    download: "Download",
    delete: "Delete",
    pending: "Pending",
    openDashboard: "Open dashboard",
    generate: "Generate report",
    reportQueued: "Report queued",
    reportGenerating: "Generating report",
    retryReport: "Retry report",
    rerun: "Rerun"
  }
};

function runStatusLabel(run: RunRecord, language: LanguageMode): string {
  const statuses = {
    es: { queued: "En cola", running: "Ejecutando", completed: "Completada", failed: "Fallida" },
    en: { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed" }
  }[language];
  if (run.status === "completed" && run.report_status === "queued") return labels[language].reportQueued;
  if (run.status === "completed" && run.report_status === "generating") return labels[language].reportGenerating;
  if (run.status === "completed" && run.report_status === "failed") return labels[language].retryReport;
  return statuses[run.status];
}
