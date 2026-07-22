import { Building2, CalendarClock, Globe2, RadioTower, ShieldCheck, UserRound } from "lucide-react";
import type { AnalysisWindow, LanguageMode, RunRecord, SubjectType } from "../types";
import { ANALYSIS_WINDOWS } from "../data/analysisWindows";
import { formatDateTime, formatNumber } from "../utils/format";

interface AnalysisContextBarProps {
  run?: RunRecord;
  language: LanguageMode;
  draftOrganizationName: string;
  draftSubjectType: SubjectType;
  draftDomains: string[];
  draftAnalysisWindow: AnalysisWindow;
}

const labels = {
  es: {
    subject: "Objetivo principal",
    person: "Persona autorizada",
    organization: "Organización / grupo",
    singleDomain: "Dominio único",
    domains: "Dominios de búsqueda",
    window: "Rango",
    run: "Corrida",
    signals: "Señales",
    noRun: "Sin corrida seleccionada",
    pending: "Pendiente de ejecutar",
    updated: "Actualizado"
  },
  en: {
    subject: "Primary target",
    person: "Authorized person",
    organization: "Organization / group",
    singleDomain: "Single domain",
    domains: "Search domains",
    window: "Range",
    run: "Run",
    signals: "Signals",
    noRun: "No selected run",
    pending: "Pending execution",
    updated: "Updated"
  }
};

export function AnalysisContextBar({
  run,
  language,
  draftOrganizationName,
  draftSubjectType,
  draftDomains,
  draftAnalysisWindow
}: AnalysisContextBarProps) {
  const copy = labels[language];
  const domains = run?.domains?.length ? run.domains : draftDomains;
  const subject = resolveSubject(run, draftOrganizationName, domains, language);
  const subjectType = run?.request.subject_type ?? draftSubjectType;
  const windowLabel = windowDisplay(run?.request.analysis_window ?? draftAnalysisWindow, language);
  const updated = run ? `${copy.updated} ${formatDateTime(run.updated_at)}` : copy.pending;
  const runStatus = run ? localizedRunStatus(run.status, language) : copy.noRun;
  const explicitSubject = run?.request.person_name || run?.request.organization_name || draftOrganizationName.trim();
  const subjectLabel = explicitSubject ? (subjectType === "person" ? copy.person : copy.organization) : domains.length === 1 ? copy.singleDomain : copy.subject;

  return (
    <section className="analysis-context-bar" aria-label={copy.subject}>
      <div className="analysis-context-main">
        {subjectType === "person" ? <UserRound size={18} /> : <Building2 size={18} />}
        <div>
          <span>{subjectLabel}</span>
          <strong title={subject}>{subject}</strong>
        </div>
      </div>
      <div className="analysis-context-item">
        <Globe2 size={16} />
        <div>
          <span>{copy.domains}</span>
          <strong title={domains.length ? domains.join(", ") : copy.noRun}>{domains.length ? domains.join(", ") : copy.noRun}</strong>
        </div>
      </div>
      <div className="analysis-context-item">
        <CalendarClock size={16} />
        <div>
          <span>{copy.window}</span>
          <strong title={windowLabel}>{windowLabel}</strong>
        </div>
      </div>
      <div className="analysis-context-item analysis-context-run">
        <ShieldCheck size={16} />
        <div>
          <span>{copy.run}</span>
          {run ? (
            <strong title={`#${run.id} · ${runStatus}`}>
              <b>#{run.id}</b>
              <em>{runStatus}</em>
            </strong>
          ) : (
            <strong title={copy.noRun}>{copy.noRun}</strong>
          )}
        </div>
      </div>
      <div className="analysis-context-item">
        <RadioTower size={16} />
        <div>
          <span>{copy.signals}</span>
          <strong title={`${formatNumber(run?.summary.kpis.new_events ?? 0)} · ${updated}`}>{formatNumber(run?.summary.kpis.new_events ?? 0)} · {updated}</strong>
        </div>
      </div>
    </section>
  );
}

function localizedRunStatus(status: RunRecord["status"], language: LanguageMode): string {
  const statuses: Record<RunRecord["status"], Record<LanguageMode, string>> = {
    queued: { es: "en cola", en: "queued" },
    running: { es: "en ejecución", en: "running" },
    completed: { es: "completa", en: "complete" },
    failed: { es: "fallida", en: "failed" }
  };
  return statuses[status]?.[language] ?? status;
}

function resolveSubject(run: RunRecord | undefined, draftOrganizationName: string, domains: string[], language: LanguageMode): string {
  const explicit = run?.request.person_name?.trim() || run?.request.organization_name?.trim() || draftOrganizationName.trim();
  if (explicit) return explicit;
  if (domains.length === 1) return domains[0];
  if (domains.length > 1) return language === "es" ? "Dominios de búsqueda ingresados" : "Submitted search domains";
  return language === "es" ? "Define una organización, persona o dominio" : "Define an organization, person or domain";
}

function windowDisplay(value: AnalysisWindow, language: LanguageMode): string {
  return ANALYSIS_WINDOWS.find((item) => item.value === value)?.label[language] ?? value;
}
