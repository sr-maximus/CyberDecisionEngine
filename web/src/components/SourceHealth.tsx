import { useMemo, useState } from "react";
import { CheckCircle2, CircleDashed, SlidersHorizontal, TriangleAlert, Wrench } from "lucide-react";
import type { LanguageMode, SourceStatus } from "../types";
import { cleanEvidenceText, displaySourceName } from "../utils/sourceLabels";
import { semanticLabel } from "../data/semanticTerms.generated";

interface SourceHealthProps {
  sources: SourceStatus[];
  language: LanguageMode;
  runId?: string;
  updatedAt?: string;
  className?: string;
  administrative?: boolean;
  onOpenConfiguration?: (source?: SourceStatus) => void;
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
    all: "Todos",
    productiveOnly: "Productivos",
    attentionOnly: "Requieren atención",
    configure: "Revisar configuración",
    reviewConnector: "Revisar",
    viewConnector: "Ver detalle",
    explanation: "Productivo significa que el conector devolvió registros en esta corrida. Requiere atención agrupa estados parciales, fallidos o degradados; no implica ausencia de información.",
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
    all: "All",
    productiveOnly: "Productive",
    attentionOnly: "Needs attention",
    configure: "Review configuration",
    reviewConnector: "Review",
    viewConnector: "View details",
    explanation: "Productive means the connector returned records in this run. Needs attention groups partial, failed or degraded states; it does not imply absence of information.",
    emptyTitle: "No collectors yet",
    emptyText: "Run or select an analysis to see the real connector status.",
    runContext: "Run",
    updated: "updated"
  }
};

export function SourceHealth({ sources, language, runId, updatedAt, className = "", administrative = false, onOpenConfiguration }: SourceHealthProps) {
  const copy = labels[language];
  const [filter, setFilter] = useState<"all" | "productive" | "attention">("all");
  const eligible = sources.filter((source) => source.eligible ?? (!source.disabled && source.configured !== false)).length;
  const attempted = sources.filter((source) => source.attempted ?? source.queried).length;
  const productive = sources.filter((source) => source.productive ?? Boolean(source.queried && source.records > 0)).length;
  const review = sources.filter((source) => source.degraded || source.failed).length;
  const totalRecords = sources.reduce((sum, source) => sum + (source.records ?? 0), 0);
  const visibleSources = useMemo(() => sources
    .map((source, index) => ({ source, index, status: normalizeStatus(source.status) }))
    .filter(({ source, status }) => {
      if (filter === "productive") return source.productive ?? Boolean(source.queried && source.records > 0);
      if (filter === "attention") return Boolean(source.degraded || source.failed || status === "partial");
      return true;
    })
    .sort((left, right) => {
      const leftAttention = left.source.degraded || left.source.failed || left.status === "partial" ? 1 : 0;
      const rightAttention = right.source.degraded || right.source.failed || right.status === "partial" ? 1 : 0;
      return rightAttention - leftAttention || (right.source.records ?? 0) - (left.source.records ?? 0);
    }), [filter, sources]);
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

      {administrative ? (
        <div className="source-health-admin">
          <div className="source-health-filter" aria-label={language === "es" ? "Filtrar conectores" : "Filter connectors"}>
            <SlidersHorizontal size={15} />
            {(["all", "productive", "attention"] as const).map((item) => (
              <button type="button" key={item} className={filter === item ? "selected" : ""} aria-pressed={filter === item} onClick={() => setFilter(item)}>
                {item === "all" ? copy.all : item === "productive" ? copy.productiveOnly : copy.attentionOnly}
              </button>
            ))}
          </div>
          {onOpenConfiguration ? <button type="button" className="secondary-button compact" onClick={() => onOpenConfiguration()}><Wrench size={15} /><span>{copy.configure}</span></button> : null}
          <p>{copy.explanation}</p>
        </div>
      ) : null}

      <div className="source-grid">
        {visibleSources.length ? (
          visibleSources.map(({ source, status, index }) => {
            const Icon = status === "ok" ? CheckCircle2 : status === "skipped" ? CircleDashed : TriangleAlert;
            const detail = `${source.records} ${copy.records}${source.warning ? ` · ${cleanEvidenceText(source.warning)}` : ""}`;
            return (
              <div className={`source-row ${status}`} key={`${source.name}-${index}`}>
                <Icon size={18} />
                <div>
                  <strong>{displaySourceName(source.name, language)}</strong>
                  <small title={source.name}>{source.name}</small>
                  <span title={detail}>{detail}</span>
                </div>
                {administrative && onOpenConfiguration ? (
                  <button
                    type="button"
                    className="source-row-action"
                    onClick={() => onOpenConfiguration(source)}
                    aria-label={`${status === "ok" ? copy.viewConnector : copy.reviewConnector}: ${displaySourceName(source.name, language)}`}
                  >
                    <Wrench size={14} />
                    <span>{status === "ok" ? copy.viewConnector : copy.reviewConnector}</span>
                  </button>
                ) : null}
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
