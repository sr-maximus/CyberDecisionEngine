import { CheckCircle2, CircleDashed, TriangleAlert } from "lucide-react";
import type { LanguageMode, SourceStatus } from "../types";
import { cleanEvidenceText, displaySourceName } from "../utils/sourceLabels";
import { semanticLabel } from "../data/semanticTerms.generated";

interface SourceHealthProps {
  sources: SourceStatus[];
  language: LanguageMode;
  runId?: string;
  updatedAt?: string;
  className?: string;
}

const labels = {
  es: {
    title: semanticLabel("connector_operational_coverage", "es"),
    collectors: "colectores",
    records: "registros",
    attempted: "consultadas",
    productive: "productivas",
    eligible: "elegibles",
    review: "por revisar",
    emptyTitle: "Sin colectores aun",
    emptyText: "Ejecuta o selecciona una corrida para ver el estado real de los conectores.",
    runContext: "Corrida",
    updated: "actualizada"
  },
  en: {
    title: semanticLabel("connector_operational_coverage", "en"),
    collectors: "collectors",
    records: "records",
    attempted: "attempted",
    productive: "productive",
    eligible: "eligible",
    review: "review",
    emptyTitle: "No collectors yet",
    emptyText: "Run or select an analysis to see the real connector status.",
    runContext: "Run",
    updated: "updated"
  }
};

export function SourceHealth({ sources, language, runId, updatedAt, className = "" }: SourceHealthProps) {
  const copy = labels[language];
  const eligible = sources.filter((source) => source.eligible ?? (!source.disabled && source.configured !== false)).length;
  const attempted = sources.filter((source) => source.attempted ?? source.queried).length;
  const productive = sources.filter((source) => source.productive ?? Boolean(source.queried && source.records > 0)).length;
  const review = sources.filter((source) => source.degraded || source.failed).length;
  const totalRecords = sources.reduce((sum, source) => sum + (source.records ?? 0), 0);
  return (
    <section className={`panel source-panel ${className}`.trim()}>
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>
            {sources.length} {copy.collectors}
            {runId ? ` · ${copy.runContext} #${runId}` : ""}
            {updatedAt ? ` · ${copy.updated} ${new Date(updatedAt).toLocaleString(language === "es" ? "es-CO" : "en-US")}` : ""}
          </p>
        </div>
      </div>
      <div className="source-health-summary">
        <span><strong>{productive}</strong>{copy.productive}</span>
        <span><strong>{attempted}</strong>{copy.attempted}</span>
        <span><strong>{eligible}</strong>{copy.eligible}</span>
        <span><strong>{review}</strong>{copy.review}</span>
        <span><strong>{totalRecords}</strong>{copy.records}</span>
      </div>

      <div className="source-grid">
        {sources.length ? (
          sources.map((source) => {
            const status = normalizeStatus(source.status);
            const Icon = status === "ok" ? CheckCircle2 : status === "skipped" ? CircleDashed : TriangleAlert;
            const detail = `${source.records} ${copy.records}${source.warning ? ` · ${cleanEvidenceText(source.warning)}` : ""}`;
            return (
              <div className={`source-row ${status}`} key={source.name}>
                <Icon size={18} />
                <div>
                  <strong>{displaySourceName(source.name, language)}</strong>
                  <span title={detail}>{detail}</span>
                </div>
              </div>
            );
          })
        ) : (
          <div className="source-row skipped">
            <CircleDashed size={18} />
            <div>
              <strong>{copy.emptyTitle}</strong>
              <span>{copy.emptyText}</span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function normalizeStatus(status: string): string {
  if (status === "healthy") return "ok";
  if (status === "searched" || status === "configured") return "ok";
  if (["pending", "warning", "partial", "timeout"].includes(status)) return "partial";
  if (status === "skipped") return "skipped";
  return status || "partial";
}
