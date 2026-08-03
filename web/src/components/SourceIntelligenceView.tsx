import { BadgeCheck, Database, FileSearch, Globe2, Layers3, LockKeyhole, RadioTower, Search } from "lucide-react";
import type { ReactNode } from "react";
import type { RunRecord, SourceStatus, ThreatEvent } from "../types";
import { buildDashboardModel, buildDomainEvidence, buildExposureAudit, extractSearchQuery, sourceEvents } from "../utils/dashboard";
import { defaultDashboardFilters } from "../data/catalog";
import { BarRanking, LineChart } from "./ChartPrimitives";
import { SourceDiagnosticsPanel } from "./SourceDiagnosticsPanel";
import { cleanEvidenceText, cleanEvidenceTitle, displaySourceName, eventEvidenceUrl } from "../utils/sourceLabels";

export function SourceIntelligenceView({ run, channel, language }: { run?: RunRecord; channel: "osint" | "darkweb"; language: "es" | "en" }) {
  const events = sourceEvents(run, channel);
  const scopedRun = run ? { ...run, summary: { ...run.summary, events } } : undefined;
  const model = buildDashboardModel(scopedRun, defaultDashboardFilters);
  const isDarkweb = channel === "darkweb";
  const copy = sourceCopy[language];
  const channelCopy = copy[channel];
  const domainEvidence = buildDomainEvidence(run, events);
  const exposureAudit = buildExposureAudit(run, events, "osint");
  const queryEvidence = events.map((event) => ({ event, query: extractSearchQuery(event) })).filter((item) => item.query);

  if (!events.length && isDarkweb) {
    return <DarkWebCoverageDashboard run={run} language={language} />;
  }

  if (!events.length) {
    return (
      <div className="view-stack">
        <section className="dashboard-grid source-dashboard-grid">
          <SourceDiagnosticsPanel run={run} channel={channel} language={language} className="span-12" />
        </section>
      </div>
    );
  }

  if (isDarkweb) {
    return (
      <DarkWebIntelligenceDashboard
        run={run}
        events={events}
        model={model}
        domainEvidence={domainEvidence}
        language={language}
      />
    );
  }

  return (
    <div className="view-stack">
      <section className="dashboard-kpis">
        <Metric icon={isDarkweb ? <LockKeyhole size={18} /> : <Globe2 size={18} />} label={copy.signals} value={String(events.length)} />
        <Metric icon={<RadioTower size={18} />} label={copy.sources} value={String(new Set(events.map((event) => displaySourceName(event.source, language))).size)} />
        <Metric icon={<Globe2 size={18} />} label={copy.actorsKpi} value={String(model.actors.length)} />
        <Metric icon={<RadioTower size={18} />} label={copy.ttps} value={String(model.ttpImpact.length)} />
      </section>

      <section className="dashboard-grid source-dashboard-grid">
        {isDarkweb ? <DarkWebSafetyPanel run={run} language={language} /> : null}
        <article className="panel chart-card span-8">
          <div className="panel-title-row compact">
            <div>
              <h2>{channelCopy.trend}</h2>
              <p>{channelCopy.subtitle}</p>
            </div>
          </div>
          <LineChart points={model.trend} language={language} />
        </article>
        <SourceDiagnosticsPanel run={run} channel={channel} language={language} className={isDarkweb ? "span-12 scroll-card" : "span-4"} />
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.categories}</h2>
              <p>{copy.categoriesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categories} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.actors}</h2>
              <p>{copy.actorsSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.actors} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.ttp}</h2>
              <p>{copy.ttpSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.ttpImpact} language={language} />
        </article>
        {!isDarkweb ? (
          <article className="panel chart-card span-4 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.domainEvidence}</h2>
                <p>{copy.domainEvidenceSubtitle}</p>
              </div>
              <FileSearch size={18} />
            </div>
            <DomainEvidenceList items={domainEvidence} language={language} />
          </article>
        ) : null}
        {!isDarkweb ? (
          <article className="panel chart-card span-8 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.exposureAudit}</h2>
                <p>{copy.exposureAuditSubtitle}</p>
              </div>
              <Search size={18} />
            </div>
            <ExposureAuditList items={exposureAudit} language={language} />
          </article>
        ) : null}
        {!isDarkweb ? (
          <article className="panel chart-card span-4 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.queries}</h2>
                <p>{copy.queriesSubtitle}</p>
              </div>
            </div>
            <div className="query-list">
            {queryEvidence.map(({ event, query }) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{query}</strong>
                <span>{displaySourceName(event.source, language)}</span>
                {eventEvidenceUrl(event) ? <code className="signal-url">{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
              {!queryEvidence.length ? <span className="muted-empty">{copy.emptyQueries}</span> : null}
            </div>
          </article>
        ) : null}
        <article className={isDarkweb ? "panel chart-card span-12 scroll-card" : "panel chart-card span-8 scroll-card"}>
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.latest}</h2>
              <p>{copy.latestSubtitle}</p>
            </div>
          </div>
          <div className="headline-list">
            {events.map((event) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{displaySourceName(event.source, language)}</strong>
                <span>{cleanEvidenceTitle(event.title)}</span>
                {eventEvidenceUrl(event) ? <code className="signal-url">{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
            {!events.length ? <span className="muted-empty">{copy.emptyLatest}</span> : null}
          </div>
        </article>
      </section>
    </div>
  );
}

const sourceCopy = {
  es: {
    signals: "Señales",
    sources: "Fuentes",
    actorsKpi: "Actores",
    ttps: "TTPs",
    categories: "Categorías",
    categoriesSubtitle: "Distribución de señales analizadas",
    actors: "Actores y grupos",
    actorsSubtitle: "Priorizados por evidencia observada",
    ttp: "Impacto TTP",
    ttpSubtitle: "Técnicas interpretadas desde la evidencia",
    domainEvidence: "Evidencia por dominio",
    domainEvidenceSubtitle: "Resultados abiertos ligados a dominios analizados",
    exposureAudit: "Auditoría defensiva de exposición",
    exposureAuditSubtitle: "Dorks defensivos sustentados en registros recolectados",
    queries: "Búsquedas recolectadas",
    queriesSubtitle: "Consultas asociadas a registros OSINT",
    emptyQueries: "Sin metadatos de busqueda en los registros OSINT actuales.",
    latest: "Registros recientes",
    latestSubtitle: "Evidencia y menciones de la corrida actual",
    emptyLatest: "Sin registros fuente para mostrar.",
    osint: {
      trend: "Tendencia OSINT",
      subtitle: "Noticias, web abierta, vulnerabilidades, RSS técnico y evidencia pública"
    },
    darkweb: {
      trend: "Tendencia Dark Web",
      subtitle: "Leaks, extorsión, ransomware e índices autorizados"
    },
    darkSafety: {
      title: "Cobertura de recolección Dark Web",
      subtitle: "Estado operativo y calidad de los canales consultados en la corrida",
      postureTitle: "Alcance",
      posture: "Índices autorizados, fuentes públicas de extorsión y registros obtenidos mediante el runtime aislado.",
      boundaryTitle: "Evidencia conservada",
      boundary: "URL o referencia canónica, título, fecha, fuente, categoría, hash y relación con el alcance.",
      legalTitle: "Lectura analítica",
      legal: "Un registro recolectado no se presenta como hallazgo hasta superar validación y relación directa con los dominios.",
      records: "registros",
      noWarning: "Sin alerta",
      empty: "Sin estado de conector dark web/Tor/ransomware en la corrida actual."
    },
    domainEvidenceEmpty: "Sin resultados OSINT ligados a dominio en la corrida actual.",
    signalsWord: "senales",
    noSource: "sin fuente",
    uncategorized: "sin categoría",
    exposureEmpty: "Sin dominios disponibles para auditoría de exposición.",
    matchedRecords: "registros coincidentes"
  },
  en: {
    signals: "Signals",
    sources: "Sources",
    actorsKpi: "Actors",
    ttps: "TTPs",
    categories: "Categories",
    categoriesSubtitle: "Distribution from analysed signals",
    actors: "Actors and groups",
    actorsSubtitle: "Ranked by observed evidence",
    ttp: "TTP impact",
    ttpSubtitle: "Techniques interpreted from evidence",
    domainEvidence: "Domain evidence",
    domainEvidenceSubtitle: "Open results tied to analysed domains",
    exposureAudit: "Defensive exposure audit",
    exposureAuditSubtitle: "Defensive dorks counted from collected evidence",
    queries: "Collected search queries",
    queriesSubtitle: "Queries attached to OSINT records",
    emptyQueries: "No query metadata in current OSINT records.",
    latest: "Latest source records",
    latestSubtitle: "Evidence and mentions from current run",
    emptyLatest: "No source records to show.",
    osint: {
      trend: "OSINT trend",
      subtitle: "Open web, news, vulnerabilities, technical RSS and public evidence"
    },
    darkweb: {
      trend: "Dark Web trend",
      subtitle: "Leaks, extortion, ransomware and authorized indexes"
    },
    darkSafety: {
      title: "Dark Web collection coverage",
      subtitle: "Operational status and quality of channels queried in the run",
      postureTitle: "Scope",
      posture: "Authorized indexes, public extortion sources and records obtained through the isolated runtime.",
      boundaryTitle: "Preserved evidence",
      boundary: "Canonical URL or reference, title, date, source, category, hash and relationship to scope.",
      legalTitle: "Analytical reading",
      legal: "A collected record is not presented as a finding until validation and a direct relationship to the domains are established.",
      records: "records",
      noWarning: "No warning",
      empty: "No dark web/Tor/ransomware connector status in the current run."
    },
    domainEvidenceEmpty: "No domain-linked OSINT results in the current run.",
    signalsWord: "signals",
    noSource: "no source",
    uncategorized: "uncategorized",
    exposureEmpty: "No domains available for exposure audit.",
    matchedRecords: "matched records"
  }
};

function DarkWebIntelligenceDashboard({
  run,
  events,
  model,
  domainEvidence,
  language
}: {
  run?: RunRecord;
  events: ThreatEvent[];
  model: ReturnType<typeof buildDashboardModel>;
  domainEvidence: ReturnType<typeof buildDomainEvidence>;
  language: "es" | "en";
}) {
  const copy = darkWebDashboardCopy[language];
  const sourceRanking = rankedValues(events, (event) => displaySourceName(event.source, language));
  const typeRanking = rankedValues(events, (event) => evidenceTypeLabel(event.evidence_type, language));
  const validated = events.filter((event) => ["validated", "confirmed"].includes(event.evidence_status ?? "")).length;

  return (
    <div className="view-stack darkweb-workspace">
      <section className="dashboard-kpis">
        <Metric icon={<Database size={18} />} label={copy.records} value={String(events.length)} />
        <Metric icon={<RadioTower size={18} />} label={copy.sources} value={String(sourceRanking.length)} />
        <Metric icon={<Globe2 size={18} />} label={copy.domains} value={String(domainEvidence.length)} />
        <Metric icon={<BadgeCheck size={18} />} label={copy.validated} value={String(validated)} />
      </section>

      <section className="dashboard-grid source-dashboard-grid darkweb-dashboard-grid">
        <article className="panel chart-card span-8 darkweb-trend-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.trend}</h2>
              <p>{copy.trendSubtitle}</p>
            </div>
          </div>
          <LineChart points={model.trend} language={language} />
        </article>
        <DarkWebSafetyPanel run={run} language={language} />

        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.categories}</h2>
              <p>{copy.categoriesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categories} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.types}</h2>
              <p>{copy.typesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={typeRanking} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.sourceCoverage}</h2>
              <p>{copy.sourceCoverageSubtitle}</p>
            </div>
          </div>
          <BarRanking items={sourceRanking} language={language} />
        </article>

        <article className="panel chart-card span-4 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.domainEvidence}</h2>
              <p>{copy.domainEvidenceSubtitle}</p>
            </div>
            <FileSearch size={18} />
          </div>
          <DomainEvidenceList items={domainEvidence} language={language} />
        </article>
        <article className="panel chart-card span-8 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.recordsTitle}</h2>
              <p>{copy.recordsSubtitle}</p>
            </div>
            <Layers3 size={18} />
          </div>
          <div className="headline-list rich-headline-list">
            {events.map((event) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{displaySourceName(event.source, language)}</strong>
                <span>{cleanEvidenceTitle(event.title)}</span>
                <em>{evidenceTypeLabel(event.evidence_type, language)} · {event.evidence_status ?? copy.underReview}</em>
                {eventEvidenceUrl(event) ? <code>{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
          </div>
        </article>

        <SourceDiagnosticsPanel run={run} channel="darkweb" language={language} className="span-12 scroll-card" />
      </section>
    </div>
  );
}

const darkWebDashboardCopy = {
  es: {
    records: "Registros recolectados",
    sources: "Fuentes observadas",
    domains: "Dominios relacionados",
    validated: "Hallazgos validados",
    trend: "Evolución de señales Dark Web",
    trendSubtitle: "Actividad temporal de registros vinculados a la corrida seleccionada",
    categories: "Tipologías observadas",
    categoriesSubtitle: "Distribución de leaks, extorsión, ransomware y otras categorías",
    types: "Formato de evidencia",
    typesSubtitle: "Cómo se materializan los registros recolectados",
    sourceCoverage: "Cobertura por fuente",
    sourceCoverageSubtitle: "Aporte de cada canal a la cobertura disponible",
    domainEvidence: "Relación por dominio",
    domainEvidenceSubtitle: "Dominios con registros trazables en la cobertura Dark Web",
    recordsTitle: "Registros verificables",
    recordsSubtitle: "Detalle con fuente, estado y URL o referencia disponible",
    underReview: "por revisar"
  },
  en: {
    records: "Collected records",
    sources: "Observed sources",
    domains: "Related domains",
    validated: "Validated findings",
    trend: "Dark Web signal evolution",
    trendSubtitle: "Temporal activity of records linked to the selected run",
    categories: "Observed typologies",
    categoriesSubtitle: "Distribution of leaks, extortion, ransomware and other categories",
    types: "Evidence format",
    typesSubtitle: "How collected records are materialized",
    sourceCoverage: "Source coverage",
    sourceCoverageSubtitle: "Contribution of each channel to available coverage",
    domainEvidence: "Domain relationship",
    domainEvidenceSubtitle: "Domains with traceable records in Dark Web coverage",
    recordsTitle: "Verifiable records",
    recordsSubtitle: "Details with source, status and available URL or reference",
    underReview: "under review"
  }
};

function DarkWebCoverageDashboard({ run, language }: { run?: RunRecord; language: "es" | "en" }) {
  const copy = darkWebCoverageCopy[language];
  const statuses = darkWebStatuses(run);
  const totalRecords = statuses.reduce((sum, status) => sum + status.records, 0);
  const statusCounts = statuses.reduce(
    (counts, status) => {
      counts[statusBucket(status)] += 1;
      return counts;
    },
    { ok: 0, partial: 0, failed: 0 }
  );
  const attentionCount = statusCounts.partial + statusCounts.failed;
  const sourceRanking = statuses
    .map((status) => ({ name: displaySourceName(status.name, language), value: status.records }))
    .sort((a, b) => b.value - a.value);
  const stateRanking = [
    { name: copy.operational, value: statusCounts.ok, tone: "low" as const },
    { name: copy.partial, value: statusCounts.partial, tone: "medium" as const },
    { name: copy.failed, value: statusCounts.failed, tone: "critical" as const }
  ];

  return (
    <div className="view-stack darkweb-coverage-workspace">
      <section className="dashboard-kpis">
        <Metric icon={<RadioTower size={18} />} label={copy.connectors} value={String(statuses.length)} />
        <Metric icon={<Database size={18} />} label={copy.records} value={String(totalRecords)} />
        <Metric icon={<BadgeCheck size={18} />} label={copy.operational} value={String(statusCounts.ok)} />
        <Metric icon={<Layers3 size={18} />} label={copy.attention} value={String(attentionCount)} />
      </section>

      <section className="dashboard-grid darkweb-coverage-grid">
        <article className="panel chart-card span-8 darkweb-coverage-chart">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.coverage}</h2>
              <p>{copy.coverageSubtitle}</p>
            </div>
            <RadioTower size={18} />
          </div>
          <BarRanking items={sourceRanking} language={language} />
        </article>

        <article className="panel chart-card span-4 darkweb-state-chart">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.state}</h2>
              <p>{copy.stateSubtitle}</p>
            </div>
            <BadgeCheck size={18} />
          </div>
          <BarRanking items={stateRanking} language={language} />
        </article>

        <article className="panel chart-card span-12 darkweb-decision-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.decision}</h2>
              <p>{copy.decisionSubtitle}</p>
            </div>
            <Layers3 size={18} />
          </div>
          <div className="darkweb-decision-grid">
            <div>
              <span>{copy.collection}</span>
              <strong>{totalRecords}</strong>
              <p>{copy.collectionReading(statuses.length)}</p>
            </div>
            <div>
              <span>{copy.scopeRelation}</span>
              <strong>{copy.notDetermined}</strong>
              <p>{copy.scopeReading}</p>
            </div>
            <div className={attentionCount ? "attention" : "controlled"}>
              <span>{copy.priority}</span>
              <strong>{attentionCount ? copy.review : copy.controlled}</strong>
              <p>{attentionCount ? copy.reviewReading(attentionCount) : copy.controlledReading}</p>
            </div>
          </div>
        </article>

        <article className="panel chart-card span-12 darkweb-connector-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.connectorDetail}</h2>
              <p>{copy.connectorDetailSubtitle}</p>
            </div>
          </div>
          <div className="darkweb-connector-grid">
            {statuses.map((status) => {
              const bucket = statusBucket(status);
              return (
                <div className={bucket} key={`${status.name}-${status.status}`}>
                  <span className="status-dot" />
                  <strong>{displaySourceName(status.name, language)}</strong>
                  <em>{statusLabel(bucket, language)}</em>
                  <b>{status.records} {copy.recordsLower}</b>
                </div>
              );
            })}
            {!statuses.length ? <div className="chart-empty">{copy.empty}</div> : null}
          </div>
        </article>
      </section>
    </div>
  );
}

const darkWebCoverageCopy = {
  es: {
    connectors: "Conectores consultados",
    records: "Registros recolectados",
    operational: "Operativos",
    partial: "Parciales",
    failed: "Con falla",
    attention: "Requieren revisión",
    coverage: "Cobertura de recolección",
    coverageSubtitle: "Aporte de cada canal Dark Web y ransomware a la corrida",
    state: "Estado de cobertura",
    stateSubtitle: "Conectores operativos, parciales y fallidos",
    decision: "Lectura para decisión",
    decisionSubtitle: "Separación entre volumen recolectado, relación con el alcance y prioridad operativa",
    collection: "Cobertura disponible",
    collectionReading: (connectors: number) => `Registros obtenidos por ${connectors} conectores; el volumen no equivale a un hallazgo.`,
    scopeRelation: "Relación con los dominios",
    notDetermined: "N/D",
    scopeReading: "No existen registros normalizados de Dark Web vinculados al alcance; no se publica riesgo ni afectación.",
    priority: "Prioridad inmediata",
    review: "Validar",
    controlled: "Controlada",
    reviewReading: (count: number) => `${count} conectores requieren completar o corregir su recolección antes de interpretar resultados.`,
    controlledReading: "Los conectores consultados finalizaron sin alertas operativas.",
    connectorDetail: "Resumen de conectores",
    connectorDetailSubtitle: "Estado y volumen sin exponer consultas técnicas extensas",
    recordsLower: "registros",
    empty: "No hay conectores Dark Web registrados en la corrida seleccionada."
  },
  en: {
    connectors: "Queried connectors",
    records: "Collected records",
    operational: "Operational",
    partial: "Partial",
    failed: "Failed",
    attention: "Require review",
    coverage: "Collection coverage",
    coverageSubtitle: "Contribution of each Dark Web and ransomware channel to the run",
    state: "Coverage status",
    stateSubtitle: "Operational, partial and failed connectors",
    decision: "Decision reading",
    decisionSubtitle: "Separation of collected volume, scope relationship and operational priority",
    collection: "Available coverage",
    collectionReading: (connectors: number) => `Records obtained through ${connectors} connectors; volume does not equal a finding.`,
    scopeRelation: "Relationship to domains",
    notDetermined: "N/A",
    scopeReading: "No normalized Dark Web records are linked to scope; no risk or impact is published.",
    priority: "Immediate priority",
    review: "Validate",
    controlled: "Controlled",
    reviewReading: (count: number) => `${count} connectors must complete or correct collection before results are interpreted.`,
    controlledReading: "Queried connectors completed without operational alerts.",
    connectorDetail: "Connector summary",
    connectorDetailSubtitle: "Status and volume without exposing long technical queries",
    recordsLower: "records",
    empty: "No Dark Web connectors are recorded for the selected run."
  }
};

function DarkWebSafetyPanel({ run, language, wide = false }: { run?: RunRecord; language: "es" | "en"; wide?: boolean }) {
  const copy = sourceCopy[language].darkSafety;
  const statuses = darkWebStatuses(run);
  return (
    <article className={`panel chart-card ${wide ? "span-12 wide" : "span-4"} darkweb-safety`}>
      <div className="panel-title-row compact">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
        <LockKeyhole size={18} />
      </div>
      <div className="safety-grid">
        <div>
          <strong>{copy.postureTitle}</strong>
          <p>{copy.posture}</p>
        </div>
        <div>
          <strong>{copy.boundaryTitle}</strong>
          <p>{copy.boundary}</p>
        </div>
        <div>
          <strong>{copy.legalTitle}</strong>
          <p>{copy.legal}</p>
        </div>
      </div>
      <div className="source-status-mini">
        {statuses.map((status) => (
          <div key={`${status.name}-${status.status}`}>
            <strong>{displaySourceName(status.name, language)}</strong>
            <span>{status.status} | {status.records} {copy.records}</span>
            <em>{cleanEvidenceText(status.warning) || copy.noWarning}</em>
          </div>
        ))}
        {!statuses.length ? <div className="chart-empty">{copy.empty}</div> : null}
      </div>
    </article>
  );
}

function darkWebStatuses(run?: RunRecord): SourceStatus[] {
  return (run?.summary.source_statuses ?? []).filter((status) =>
    /dark|tor|ransom|onion|leak/i.test(`${status.name} ${status.mode} ${status.warning ?? ""}`)
  );
}

function statusBucket(status: SourceStatus): "ok" | "partial" | "failed" {
  const value = `${status.status} ${status.warning ?? ""}`.toLowerCase();
  if (/failed|error|unavailable|denied/.test(value)) return "failed";
  if (/partial|warning|timeout|skipped|disabled|429|no_data/.test(value)) return "partial";
  return "ok";
}

function statusLabel(status: "ok" | "partial" | "failed", language: "es" | "en"): string {
  const labels = language === "es"
    ? { ok: "Operativo", partial: "Parcial", failed: "Con falla" }
    : { ok: "Operational", partial: "Partial", failed: "Failed" };
  return labels[status];
}

function rankedValues(events: ThreatEvent[], selector: (event: ThreatEvent) => string): Array<{ name: string; value: number }> {
  const counts = new Map<string, number>();
  events.forEach((event) => {
    const name = selector(event);
    counts.set(name, (counts.get(name) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

function evidenceTypeLabel(type: ThreatEvent["evidence_type"], language: "es" | "en"): string {
  const labels = language === "es"
    ? {
        document: "Documentos",
        web_page: "Páginas web",
        news: "Noticias",
        social_media: "Redes sociales",
        technology_infrastructure: "Tecnología e infraestructura",
        official_record: "Registros oficiales",
        authorized_dark_web: "Dark Web autorizada",
        other: "Otros"
      }
    : {
        document: "Documents",
        web_page: "Web pages",
        news: "News",
        social_media: "Social media",
        technology_infrastructure: "Technology and infrastructure",
        official_record: "Official records",
        authorized_dark_web: "Authorized Dark Web",
        other: "Other"
      };
  return labels[type ?? "other"];
}

function DomainEvidenceList({ items, language }: { items: ReturnType<typeof buildDomainEvidence>; language: "es" | "en" }) {
  const copy = sourceCopy[language];
  if (!items.length) return <div className="chart-empty">{copy.domainEvidenceEmpty}</div>;
  return (
    <div className="domain-evidence-list">
      {items.map((item) => (
        <div key={item.domain}>
          <strong>{item.domain}</strong>
          <span>{item.signals} {copy.signalsWord} | {item.sources.map((source) => displaySourceName(source, language)).join(", ") || copy.noSource}</span>
          <em>{item.categories.join(" / ") || copy.uncategorized}</em>
        </div>
      ))}
    </div>
  );
}

function ExposureAuditList({ items, language }: { items: ReturnType<typeof buildExposureAudit>; language: "es" | "en" }) {
  const copy = sourceCopy[language];
  if (!items.length) return <div className="chart-empty">{copy.exposureEmpty}</div>;
  return (
    <div className="exposure-audit-grid">
      {items.map((item) => (
        <div className={`exposure-audit-item ${item.tone}`} key={`${item.domain}-${item.label}`}>
          <strong>{item.label}</strong>
          <code>{item.query}</code>
          <span>{item.resultCount} {copy.matchedRecords}</span>
          <em>{item.intent}</em>
          {item.urls.length ? (
            <div className="exposure-url-list">
              {item.urls.map((url) => (
                <a href={url} target="_blank" rel="noreferrer" key={url}>{url}</a>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="dashboard-metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
