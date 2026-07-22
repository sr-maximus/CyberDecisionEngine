import { Activity, CheckCircle2, GitBranch, Globe2, MessageSquareWarning, Network, Newspaper, RadioTower, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import type { DecisionIntelligenceSnapshot, LanguageMode, RunRecord, SourceStatus } from "../types";
import { defaultDashboardFilters, localizedCountryLabel } from "../data/catalog";
import { buildDashboardModel } from "../utils/dashboard";
import type { RiskHeatRow } from "../utils/dashboard";
import { formatDateTime, formatNumber } from "../utils/format";
import { BarRanking, Gauge, LineChart, SectorMatrix } from "./ChartPrimitives";
import { FrameworkMapping, GraphInsight } from "./DecisionCharts";
import { AttackPredictionPanel, PosturePanel, RiskHeatMap, RiskRadarChart, StrategicSignalHeatmap, StrategyLensChart } from "./StrategyCharts";
import { cleanEvidenceTitle, displaySourceName, eventEvidenceUrl, publicEvidenceUrl, statusDisplayName } from "../utils/sourceLabels";
import { semanticLabel } from "../data/semanticTerms.generated";

interface StrategicDashboardProps {
  run?: RunRecord;
  language: LanguageMode;
}

const labels = {
  es: {
    currentScope: "Alcance actual",
    signals: "Registros únicos",
    maxRisk: "Riesgo máx.",
    sourcesOk: "Fuentes productivas / consultadas",
    countryScope: "País objetivo",
    executiveRadar: "Radar ejecutivo de riesgo",
    executiveRadarSubtitle: "Intensidad de riesgo desde el modelo del informe actual",
    riskHeatmap: "Mapa de calor de riesgo",
    riskHeatmapSubtitle: "Calor del informe por tipo de ciberriesgo",
    riskHeatDistribution: "Distribución de calor de riesgo",
    riskHeatDistributionSubtitle: "Lectura rápida por severidad y prioridad de atención",
    predictive: semanticLabel("signal_pressure_index", "es"),
    predictiveSubtitle: "Lectura no calibrada por modalidad, sector y TTP basada solo en evidencia directa o validada",
    vulnerabilityIntel: "Inteligencia de vulnerabilidades",
    vulnerabilityIntelSubtitle: "CVE confirmadas, KEV y tecnologías observadas sin inferir falsos positivos",
    confirmedCves: "CVE confirmadas",
    observedTech: "Tecnologías",
    surfaceAssets: "Activos",
    threatTrend: "Tendencia de amenazas desde inteligencia diaria",
    latestRun: "Última corrida",
    categories: "Categorías de amenaza",
    categoriesSubtitle: "Distribución de eventos",
    actors: "Grupos y actores cibernéticos",
    actorsSubtitle: "Ranking de señales con contexto MITRE",
    ttpImpact: "Impacto TTP",
    ttpImpactSubtitle: "Técnicas potencialmente relevantes; observadas solo con telemetría validada",
    attackActions: "Acciones de ataque",
    attackActionsSubtitle: "Actividad observada solo cuando existe evidencia técnica validada",
    locationHeat: "Calor geográfico de amenazas",
    locationHeatSubtitle: "Países, ciudades o regiones encontradas en etiquetas fuente",
    sectorMatrix: "Matriz de sector económico",
    sectorMatrixSubtitle: "Sector desde la solicitud del análisis actual",
    affectedScope: "Alcance afectado",
    affectedScopeSubtitle: "Dominios, activos o categorías afectadas por evidencia real",
    posture: semanticLabel("external_exposure_intelligence_index", "es"),
    postureSubtitle: "Índice externo de fuentes, evidencia y riesgo; no mide cumplimiento ni madurez interna",
    freshness: semanticLabel("connector_operational_coverage", "es"),
    freshnessSubtitle: "Salud, registros y estado de colectores",
    pestel: "Cyber-PESTEL",
    pestelSubtitle: "Presiones macroambientales de ciberseguridad",
    porter: "Cyber-Porter",
    porterSubtitle: "Fuerzas competitivas y exposición cibernética sectorial",
    graph: "Análisis de grafo de amenazas",
    graphSubtitle: "Grupos, acciones y TTP enlazados para soporte de decisión",
    news: "Noticias y acciones de grupos",
    newsSubtitle: "Titulares ligados a grupos y ataques observados",
    emptyNews: "Sin titulares de grupos observados en la corrida actual.",
    disarmPulse: "Pulso DISARM",
    disarmPulseSubtitle: "Señales de narrativa, influencia o confianza pública detectadas en la corrida",
    webMap: "Mapa de capas de recolección",
    webMapSubtitle: "Resultados por Surface Web, Deep Web y Dark Web en la corrida actual",
    surfaceWeb: "Surface Web",
    deepWeb: "Deep Web",
    darkWeb: "Dark Web",
    records: "resultados",
    sectionRisk: "Riesgo y predicción",
    sectionRiskText: "Lectura ejecutiva para priorizar atención inmediata",
    sectionIntel: "Señales de inteligencia",
    sectionIntelText: "Distribución por fuente, actor, técnica, región y sector",
    sectionStrategy: "Postura y estrategia",
    sectionStrategyText: "Controles, PESTEL y Porter para decisión directiva",
    strategicHeat: "Concentración estratégica de señales",
    strategicHeatSubtitle: "Intensidad, confianza y cobertura por dimensión; N/D significa ausencia de datos suficientes",
    sectionEvidence: "Evidencia y mapeo de referencia",
    sectionEvidenceText: "Grafo, noticias y frameworks preventivos mapeados a evidencia",
    frameworks: "Mapeo de frameworks para decisión",
    frameworksSubtitle: "NIST, ISO, PCI, SOC, GDPR y familias de control relacionadas",
    emptyDashboard: "Ejecuta un nuevo análisis o abre una corrida desde Historial para visualizar tableros con evidencia."
  },
  en: {
    currentScope: "Current scope",
    signals: "Unique records",
    maxRisk: "Max risk",
    sourcesOk: "Productive / attempted sources",
    countryScope: "Country scope",
    executiveRadar: "Executive risk radar",
    executiveRadarSubtitle: "Risk intensity from the current report model",
    riskHeatmap: "Risk heatmap",
    riskHeatmapSubtitle: "Report heat by cyber risk type",
    riskHeatDistribution: "Risk heat distribution",
    riskHeatDistributionSubtitle: "Fast severity and response-priority reading",
    predictive: semanticLabel("signal_pressure_index", "en"),
    predictiveSubtitle: "Non-calibrated reading by modality, sector and TTP using only direct or validated evidence",
    vulnerabilityIntel: "Vulnerability intelligence",
    vulnerabilityIntelSubtitle: "Confirmed CVEs, KEV and observed technologies without false-positive inference",
    confirmedCves: "Confirmed CVEs",
    observedTech: "Technologies",
    surfaceAssets: "Assets",
    threatTrend: "Threat trend from daily intelligence",
    latestRun: "Latest run",
    categories: "Threat categories",
    categoriesSubtitle: "Event distribution",
    actors: "Cyber groups and actors",
    actorsSubtitle: "MITRE-aware signal ranking",
    ttpImpact: "TTP impact",
    ttpImpactSubtitle: "Potentially relevant techniques; observed only with validated telemetry",
    attackActions: "Attack actions",
    attackActionsSubtitle: "Observed activity only when supported by validated technical evidence",
    locationHeat: "Threat location heat",
    locationHeatSubtitle: "Countries, cities or regions found in source tags",
    sectorMatrix: "Economic sector matrix",
    sectorMatrixSubtitle: "Sector from the current analysis request",
    affectedScope: "Affected scope",
    affectedScopeSubtitle: "Domains, assets or categories affected by real evidence",
    posture: semanticLabel("external_exposure_intelligence_index", "en"),
    postureSubtitle: "External source, evidence and risk index; not a compliance or internal maturity score",
    freshness: semanticLabel("connector_operational_coverage", "en"),
    freshnessSubtitle: "Collector health",
    pestel: "Cyber-PESTEL",
    pestelSubtitle: "Cybersecurity macro-environmental pressures",
    porter: "Cyber-Porter",
    porterSubtitle: "Competitive forces and sector cyber exposure",
    graph: "Threat graph analysis",
    graphSubtitle: "Groups, actions and TTPs linked for decision support",
    news: "Group news and actions",
    newsSubtitle: "Headlines tied to observed groups and attacks",
    emptyNews: "No observed group headlines in the current run.",
    disarmPulse: "DISARM pulse",
    disarmPulseSubtitle: "Narrative, influence or public-trust signals detected in the current run",
    webMap: "Collection layer map",
    webMapSubtitle: "Results across Surface Web, Deep Web and Dark Web in the current run",
    surfaceWeb: "Surface Web",
    deepWeb: "Deep Web",
    darkWeb: "Dark Web",
    records: "results",
    sectionRisk: "Risk and prediction",
    sectionRiskText: "Executive reading to prioritize immediate attention",
    sectionIntel: "Intelligence signals",
    sectionIntelText: "Distribution by source, actor, technique, region and sector",
    sectionStrategy: "Posture and strategy",
    sectionStrategyText: "Controls, PESTEL and Porter for executive decision",
    strategicHeat: "Strategic signal concentration",
    strategicHeatSubtitle: "Intensity, confidence and coverage by dimension; N/A means insufficient data",
    sectionEvidence: "Evidence and reference mapping",
    sectionEvidenceText: "Graph, news and preventive frameworks mapped to evidence",
    frameworks: "Framework decision mapping",
    frameworksSubtitle: "NIST, ISO, PCI, SOC, GDPR and related control families",
    emptyDashboard: "Run a new analysis or open a run from History to visualize evidence-backed dashboards."
  }
};

const dashboardItemLabelsEs: Record<string, string> = {
  unknown: "Sin atribución",
  unattributed: "No atribuido",
  external_reconnaissance: "Reconocimiento externo",
  public_evidence: "Evidencia pública",
  open_web: "Web abierta",
  external_exposure: "Exposición externa",
  vulnerability: "Vulnerabilidad",
  vulnerability_probability: "Probabilidad de vulnerabilidad",
  threat_intel: "Inteligencia de amenazas",
  attack_surface_dns: "Superficie de ataque DNS",
  phishing: "Phishing",
  brand_reputation: "Marca y reputación",
  attack_surface_web: "Superficie web",
  osint_observation: "Observación OSINT",
  "Exploit attempt": "Intento de explotación",
  "Data exposure": "Exposición de datos",
  Reconnaissance: "Reconocimiento",
  "Credential targeting": "Ataque a credenciales",
  "Brand abuse": "Abuso de marca",
  "Impact / extortion": "Impacto / extorsión"
};

function localizedDashboardItems<T extends { name: string }>(items: T[], language: LanguageMode): T[] {
  if (language === "en") return items;
  return items.map((item) => ({ ...item, name: dashboardItemLabelsEs[item.name] ?? item.name }));
}

export function StrategicDashboard({ run, language }: StrategicDashboardProps) {
  const copy = labels[language];
  if (!run) {
    return (
      <div className="view-stack">
        <section className="panel chart-card chart-empty">{copy.emptyDashboard}</section>
      </div>
    );
  }
  const model = buildDashboardModel(run, defaultDashboardFilters);
  const snapshot = run.summary.decision_snapshot;
  const disarmPulse = buildDisarmPulse(run, language);
  const rawCountry = run.request.country?.trim();
  const country = rawCountry ? localizedCountryLabel(rawCountry, language) : "-";
  const uniqueRecords = snapshotMetric(snapshot, "unique_records", run.summary.kpis.unique_records ?? run.summary.kpis.new_events);
  const maxRisk = snapshotMetric(snapshot, "max_residual_risk", run.summary.kpis.max_residual_risk ?? 0);
  const productiveSources = snapshotMetric(snapshot, "productive_sources", run.summary.kpis.productive_sources ?? run.summary.kpis.healthy_sources);
  const attemptedSources = snapshotMetric(snapshot, "queried_sources", run.summary.kpis.queried_sources ?? run.summary.kpis.total_sources);
  const riskRadarState = snapshot?.chart_eligibility?.executive_risk_radar;
  const riskHeatState = snapshot?.chart_eligibility?.risk_heatmap;
  return (
    <div className="view-stack">
      <section className="dashboard-kpis">
        <Metric icon={<RadioTower size={18} />} label={copy.signals} value={formatNumber(uniqueRecords)} />
        <Metric icon={<ShieldAlert size={18} />} label={copy.maxRisk} value={snapshot?.metrics.max_residual_risk?.value_status === "no_data" ? "N/D" : maxRisk.toFixed(1)} />
        <Metric icon={<Activity size={18} />} label={copy.sourcesOk} value={attemptedSources ? `${productiveSources}/${attemptedSources}` : "N/D"} />
        <Metric icon={<Globe2 size={18} />} label={copy.countryScope} value={country} />
      </section>

      {snapshot ? <DecisionSnapshotOverview snapshot={snapshot} language={language} /> : null}

      <section className="panel web-layer-strip">
        <PanelHeader title={copy.webMap} subtitle={copy.webMapSubtitle} icon={<Network size={18} />} />
        <WebLayerMap run={run} language={language} />
      </section>

      <section className="dashboard-grid strategic-grid">
        <div className="dashboard-section-label span-12">
          <span>01</span>
          <div>
            <strong>{copy.sectionRisk}</strong>
            <em>{copy.sectionRiskText}</em>
          </div>
        </div>

        <article className="panel chart-card span-8 premium-card">
          <PanelHeader title={copy.executiveRadar} subtitle={copy.executiveRadarSubtitle} icon={<ShieldAlert size={18} />} />
          {riskRadarState?.eligible === false ? <ChartUnavailable reason={riskRadarState.reason} language={language} /> : <RiskRadarChart rows={model.riskHeatRows} language={language} />}
        </article>

        <article className="panel chart-card span-4 premium-card">
          <PanelHeader title={copy.riskHeatmap} subtitle={copy.riskHeatmapSubtitle} />
          {riskHeatState?.eligible === false ? <ChartUnavailable reason={riskHeatState.reason} language={language} /> : <RiskHeatMap rows={model.riskHeatRows} language={language} />}
        </article>

        <article className="panel chart-card span-12 premium-card">
          <PanelHeader title={copy.predictive} subtitle={copy.predictiveSubtitle} icon={<Activity size={18} />} />
          <AttackPredictionPanel prediction={model.attackPrediction} language={language} />
        </article>

        <article className="panel chart-card span-12 premium-card">
          <PanelHeader title={copy.vulnerabilityIntel} subtitle={copy.vulnerabilityIntelSubtitle} icon={<ShieldAlert size={18} />} />
          <VulnerabilityIntelPanel model={model.vulnerabilityIntel} language={language} />
        </article>

        <div className="dashboard-section-label span-12">
          <span>02</span>
          <div>
            <strong>{copy.sectionIntel}</strong>
            <em>{copy.sectionIntelText}</em>
          </div>
        </div>

        <article className="panel chart-card span-8">
          <PanelHeader title={copy.threatTrend} subtitle={`${copy.latestRun} ${formatDateTime(run?.updated_at)}`} />
          <LineChart points={model.trend} language={language} />
        </article>

        <article className="panel chart-card span-4">
          <PanelHeader title={copy.categories} subtitle={copy.categoriesSubtitle} />
          <BarRanking items={localizedDashboardItems(model.categories, language)} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.disarmPulse} subtitle={copy.disarmPulseSubtitle} icon={<MessageSquareWarning size={18} />} />
          <BarRanking items={disarmPulse} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.actors} subtitle={copy.actorsSubtitle} />
          <BarRanking items={localizedDashboardItems(model.actors, language)} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.ttpImpact} subtitle={copy.ttpImpactSubtitle} />
          <BarRanking items={model.ttpImpact} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.attackActions} subtitle={copy.attackActionsSubtitle} />
          <BarRanking items={localizedDashboardItems(model.attackActions, language)} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.locationHeat} subtitle={copy.locationHeatSubtitle} />
          <BarRanking
            items={model.regionalHeat.map((item) => ({
              ...item,
              name: localizedCountryLabel(item.name, language)
            }))}
            language={language}
          />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.sectorMatrix} subtitle={copy.sectorMatrixSubtitle} />
          <SectorMatrix items={model.sectorMatrix} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.affectedScope} subtitle={copy.affectedScopeSubtitle} />
          <BarRanking items={model.affectedStates} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card freshness-card">
          <PanelHeader title={copy.freshness} subtitle={copy.freshnessSubtitle} />
          <SourceFreshnessPanel value={model.sourceFreshness} run={run} language={language} />
        </article>

        <article className="panel chart-card span-4 compact-card">
          <PanelHeader title={copy.riskHeatDistribution} subtitle={copy.riskHeatDistributionSubtitle} />
          <RiskHeatDistribution rows={model.riskHeatRows} language={language} />
        </article>

        <div className="dashboard-section-label span-12">
          <span>03</span>
          <div>
            <strong>{copy.sectionStrategy}</strong>
            <em>{copy.sectionStrategyText}</em>
          </div>
        </div>

        <article className="panel chart-card span-12 posture-card">
          <PanelHeader title={copy.posture} subtitle={copy.postureSubtitle} icon={<ShieldAlert size={18} />} />
          <PosturePanel score={model.postureIndex} points={model.posturePoints} language={language} />
        </article>

        <article className="panel chart-card span-6">
          <PanelHeader title={copy.pestel} subtitle={copy.pestelSubtitle} />
          <StrategyLensChart lens={model.pestel} language={language} />
        </article>

        <article className="panel chart-card span-6">
          <PanelHeader title={copy.porter} subtitle={copy.porterSubtitle} />
          <StrategyLensChart lens={model.porter} language={language} />
        </article>

        <article className="panel chart-card span-12 strategic-heatmap-card">
          <PanelHeader title={copy.strategicHeat} subtitle={copy.strategicHeatSubtitle} icon={<Activity size={18} />} />
          <StrategicSignalHeatmap pestel={model.pestel} porter={model.porter} language={language} />
        </article>

        <div className="dashboard-section-label span-12">
          <span>04</span>
          <div>
            <strong>{copy.sectionEvidence}</strong>
            <em>{copy.sectionEvidenceText}</em>
          </div>
        </div>

        <article className="panel chart-card span-12 claim-evidence-panel">
          <PanelHeader
            title={language === "en" ? "Claims and validated evidence" : "Afirmaciones y evidencia validada"}
            subtitle={language === "en" ? "Traceability from claim to evidence, limitation, decision and closure" : "Trazabilidad desde afirmación hasta evidencia, limitación, decisión y cierre"}
            icon={<CheckCircle2 size={18} />}
          />
          <ClaimEvidencePanel run={run} language={language} />
        </article>

        <article className="panel chart-card span-8 threat-graph-card">
          <PanelHeader title={copy.graph} subtitle={copy.graphSubtitle} icon={<Network size={18} />} />
          <GraphInsight metrics={model.graphMetrics} nodes={model.threatGraphNodes} links={model.threatGraphLinks} language={language} />
        </article>

        <article className="panel chart-card span-4 scroll-card threat-news-card">
          <PanelHeader title={copy.news} subtitle={copy.newsSubtitle} icon={<Newspaper size={18} />} />
          <div className="headline-list rich-headline-list">
            {model.groupHeadlines.map((event) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{event.actor && event.actor !== "unattributed" ? event.actor : event.category}</strong>
                <span>{cleanEvidenceTitle(event.title)}</span>
                <em>
                  {displaySourceName(event.source, language)}
                  {event.technique ? ` · ${event.technique}` : ""}
                  {event.observed_at ? ` · ${formatDateTime(event.observed_at)}` : ""}
                </em>
                {eventEvidenceUrl(event) ? <code>{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
            {!model.groupHeadlines.length ? <span className="muted-empty">{copy.emptyNews}</span> : null}
          </div>
        </article>

        <article className="panel chart-card span-12 frameworks-card">
          <PanelHeader title={copy.frameworks} subtitle={copy.frameworksSubtitle} icon={<GitBranch size={18} />} />
          <FrameworkMapping items={model.frameworkMappings} compact language={language} />
        </article>
      </section>
    </div>
  );
}

function ClaimEvidencePanel({ run, language }: { run: RunRecord; language: LanguageMode }) {
  const claims = run.summary.claims ?? [];
  const evidenceById = new Map((run.summary.evidence_items ?? []).map((item) => [item.evidence_id, item]));
  const interpretations = new Map((run.summary.interpretations ?? []).map((item) => [item.claim_id, item]));
  const decisions = new Map((run.summary.decisions ?? []).map((item) => [item.claim_id, item]));
  if (!claims.length) {
    return <div className="muted-empty">{language === "en" ? "No evidence-backed claims in this run." : "Sin afirmaciones respaldadas por evidencia en esta corrida."}</div>;
  }
  return (
    <div className="claim-evidence-grid">
      {claims.slice(0, 12).map((claim) => {
        const interpretation = interpretations.get(claim.claim_id);
        const decision = decisions.get(claim.claim_id);
        const evidence = claim.evidence_ids.map((id) => evidenceById.get(id)).filter(Boolean);
        return (
          <details className={`claim-evidence-card ${claim.claim_status}`} key={claim.claim_id}>
            <summary>
              <span><b>{claim.claim_id}</b><strong>{interpretation?.what_found || claim.statement}</strong></span>
              <em>{claimStatusLabel(claim.claim_status, language)} · {Math.round(claim.confidence * 100)}%</em>
            </summary>
            <div className="claim-evidence-body">
              <p><b>{language === "en" ? "What it demonstrates" : "Qué demuestra"}</b>{interpretation?.what_demonstrates || (language === "en" ? "Requires analytical interpretation." : "Requiere interpretación analítica.")}</p>
              <p><b>{language === "en" ? "What it does not demonstrate" : "Qué no demuestra"}</b>{interpretation?.what_not_demonstrates || (language === "en" ? "It does not prove a confirmed incident by itself." : "No demuestra por sí sola un incidente confirmado.")}</p>
              <p><b>{language === "en" ? "Validation" : "Validación"}</b>{validationMethodLabel(interpretation?.validation_summary || claim.validation_method, language)}</p>
              <p><b>{language === "en" ? "Decision" : "Decisión"}</b>{decision?.decision || "N/D"}</p>
              <p><b>{language === "en" ? "Owner and closure" : "Responsable y cierre"}</b>{decision ? `${decision.owner} · ${decision.closure_criteria}` : "N/D"}</p>
              <div className="claim-evidence-links">
                {evidence.map((item) => item?.canonical_url ? <a key={item.evidence_id} href={publicEvidenceUrl(item.canonical_url) ?? item.canonical_url} target="_blank" rel="noreferrer">{item.evidence_id}</a> : <span key={item?.evidence_id}>{item?.evidence_id}</span>)}
                {!evidence.length ? <span>{language === "en" ? "No linked evidence; validation required" : "Sin evidencia enlazada; requiere validación"}</span> : null}
              </div>
            </div>
          </details>
        );
      })}
    </div>
  );
}

function claimStatusLabel(status: string, language: LanguageMode): string {
  const labelsByStatus: Record<string, { es: string; en: string }> = {
    candidate: { es: "Candidata", en: "Candidate" },
    supported: { es: "Respaldada", en: "Supported" },
    validated: { es: "Validada", en: "Validated" },
    confirmed: { es: "Confirmada", en: "Confirmed" },
    materialized: { es: "Materializada", en: "Materialized" }
  };
  return labelsByStatus[status]?.[language] ?? status;
}

function validationMethodLabel(method: string | null | undefined, language: LanguageMode): string {
  if (!method) return "N/D";
  const labelsByMethod: Record<string, { es: string; en: string }> = {
    analytical_review: { es: "Revisión analítica", en: "Analytical review" },
    reproducible_http_query: { es: "Consulta HTTP reproducible", en: "Reproducible HTTP query" },
    tls_handshake: { es: "Validación de conexión TLS", en: "TLS handshake validation" },
    dns_query: { es: "Consulta DNS reproducible", en: "Reproducible DNS query" },
    exact_reference_match: { es: "Coincidencia exacta de referencia", en: "Exact reference match" }
  };
  return labelsByMethod[method]?.[language] ?? method.replace(/_/g, " ");
}

function Metric({ icon, label, value }: { icon?: ReactNode; label: string; value: string }) {
  return (
    <div className={`dashboard-metric ${icon ? "" : "metric-plain"}`}>
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PanelHeader({ title, subtitle, icon }: { title: string; subtitle: string; icon?: ReactNode }) {
  return (
    <div className="panel-title-row compact">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {icon}
    </div>
  );
}

function SourceFreshnessPanel({ value, run, language }: { value: number; run?: RunRecord; language: LanguageMode }) {
  const sources = run?.summary.source_statuses ?? [];
  const healthy = sources.filter((source) => source.status === "ok" || source.status === "healthy").length;
  const degraded = Math.max(0, sources.length - healthy);
  const totalRecords = sources.reduce((sum, source) => sum + (source.records ?? 0), 0);
  const copy = {
    es: { healthy: "saludables", degraded: "revisar", records: "registros", empty: "Sin fuentes registradas en la corrida." },
    en: { healthy: "healthy", degraded: "review", records: "records", empty: "No sources registered in this run." }
  }[language];
  return (
    <div className="source-freshness-panel">
      <Gauge value={Math.round(value)} language={language} />
      <div className="freshness-metrics">
        <FreshnessMetric value={String(healthy)} label={copy.healthy} tone="good" />
        <FreshnessMetric value={String(degraded)} label={copy.degraded} tone={degraded ? "warn" : "good"} />
        <FreshnessMetric value={formatNumber(totalRecords)} label={copy.records} tone="info" />
      </div>
      <div className="freshness-source-list">
        {sources.map((source) => (
          <SourcePill source={source} language={language} key={source.name} />
        ))}
        {!sources.length ? <span>{copy.empty}</span> : null}
      </div>
    </div>
  );
}

function FreshnessMetric({ value, label, tone }: { value: string; label: string; tone: "good" | "warn" | "info" }) {
  return (
    <div className={`freshness-metric ${tone}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function SourcePill({ source, language }: { source: SourceStatus; language: LanguageMode }) {
  const statusClass = ["ok", "healthy", "searched", "configured"].includes(source.status) ? "ok" : ["warning", "pending", "partial", "skipped"].includes(source.status) ? "warning" : "error";
  return (
    <span className={`source-pill ${statusClass}`} title={statusDisplayName(source, language)}>
      <b />
      {displaySourceName(source.name, language)}
      <em>{source.records}</em>
    </span>
  );
}

type WebLayerKey = "surface" | "deep" | "dark";

interface WebLayerStat {
  key: WebLayerKey;
  label: string;
  records: number;
}

function WebLayerMap({ run, language }: { run: RunRecord; language: LanguageMode }) {
  const copy = labels[language];
  const layers = buildWebLayerStats(run, language);
  const max = Math.max(...layers.map((layer) => layer.records), 1);
  return (
    <div className="web-layer-map" aria-label={copy.webMap}>
      {layers.map((layer, index) => (
        <div className={`web-layer-node ${layer.key}`} key={layer.key}>
          <div className="web-layer-orbit">
            <span style={{ transform: `scale(${0.72 + (layer.records / max) * 0.28})` }}>
              <strong>{formatNumber(layer.records)}</strong>
            </span>
          </div>
          <div>
            <b>{layer.label}</b>
            <em>{copy.records}</em>
          </div>
          {index < layers.length - 1 ? <i aria-hidden="true" /> : null}
        </div>
      ))}
    </div>
  );
}

function buildWebLayerStats(run: RunRecord, language: LanguageMode): WebLayerStat[] {
  const layerLabels = {
    es: { surface: labels.es.surfaceWeb, deep: labels.es.deepWeb, dark: labels.es.darkWeb },
    en: { surface: labels.en.surfaceWeb, deep: labels.en.deepWeb, dark: labels.en.darkWeb }
  }[language];
  const metrics = run.summary.metrics ?? {};
  const sourceCoverage = asRecord(metrics.source_coverage);
  const webLayers = asRecord(sourceCoverage.web_layers);
  const fromMetrics = (["surface", "deep", "dark"] as WebLayerKey[]).map((key) => {
    const item = asRecord(webLayers[key]);
    const records = numberFromUnknown(item.records) || numberFromUnknown(item.status_records);
    return { key, label: layerLabels[key], records };
  });
  if (fromMetrics.some((layer) => layer.records > 0)) return fromMetrics;

  const counters: Record<WebLayerKey, number> = { surface: 0, deep: 0, dark: 0 };
  for (const event of run.summary.events ?? []) {
    counters[classifyWebLayer(event.source, `${event.category} ${(event.tags ?? []).join(" ")}`)] += 1;
  }
  for (const status of run.summary.source_statuses ?? []) {
    if (counters.surface + counters.deep + counters.dark > 0) break;
    counters[classifyWebLayer(status.name, status.warning ?? "")] += status.records ?? 0;
  }
  return (["surface", "deep", "dark"] as WebLayerKey[]).map((key) => ({ key, label: layerLabels[key], records: counters[key] }));
}

function classifyWebLayer(source = "", evidence = ""): WebLayerKey {
  const text = `${source} ${evidence}`.toLowerCase();
  if (/(dark web|darkweb|ransomware|tor|\.onion|misp|stix|taxii|leak)/.test(text)) return "dark";
  if (/(common crawl|document|archivo|pdf|indexed_file|public_document|document_index)/.test(text)) return "deep";
  return "surface";
}

function asRecord(value: unknown): Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value)) ? (value as Record<string, unknown>) : {};
}

function numberFromUnknown(value: unknown): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? Math.max(0, Math.round(parsed)) : 0;
}

function snapshotMetric(snapshot: DecisionIntelligenceSnapshot | undefined, metricId: string, fallback: number): number {
  const value = snapshot?.metrics?.[metricId]?.value;
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function ChartUnavailable({ reason, language }: { reason: string; language: LanguageMode }) {
  return (
    <div className="decision-chart-unavailable">
      <ShieldAlert size={24} />
      <strong>{language === "en" ? "Not calculated" : "No calculado"}</strong>
      <span>{reason}</span>
    </div>
  );
}

function DecisionSnapshotOverview({ snapshot, language }: { snapshot: DecisionIntelligenceSnapshot; language: LanguageMode }) {
  const copy = language === "en"
    ? { title: "Decision state", subtitle: "One versioned record for dashboard, reports and exports", domains: "Analysed targets", records: "records", findings: "findings", risk: "risk", funnel: "Scenario funnel", templates: "Reference templates", candidate: "Candidates", supported: "Supported", validated: "Validated", confirmed: "Confirmed", decisions: "Decision possibilities", noSignal: "No direct signal", owner: "Owner", window: "Window", act: "Act now", validate: "Validate first", refs: "Evidence" }
    : { title: "Estado para decisión", subtitle: "Un registro versionado para tablero, informes y exportaciones", domains: "Objetivos analizados", records: "registros", findings: "hallazgos", risk: "riesgo", funnel: "Embudo de escenarios", templates: "Plantillas de referencia", candidate: "Candidatos", supported: "Soportados", validated: "Validados", confirmed: "Confirmados", decisions: "Posibilidades de decisión", noSignal: "Sin señal directa", owner: "Responsable", window: "Ventana", act: "Actuar ahora", validate: "Validar primero", refs: "Evidencia" };
  const funnel = snapshot.scenario_funnel;
  const subjectRows = snapshot.domains.length
    ? snapshot.domains.map((row) => ({
        id: row.domain,
        label: row.domain,
        signal: row.top_signal,
        records: row.record_count,
        findings: row.validated_findings_count,
        risk: row.max_residual_risk
      }))
    : snapshot.analyzed_entities.map((entity) => ({
        id: entity.entity_id,
        label: entity.canonical_name,
        signal: `${entity.entity_type} · ${entity.validation_status}`,
        records: snapshotMetric(snapshot, "unique_records", 0),
        findings: snapshotMetric(snapshot, "validated_findings", 0),
        risk: snapshot.metrics.max_residual_risk?.value ?? null
      }));
  return (
    <section className="panel decision-snapshot-panel">
      <PanelHeader title={copy.title} subtitle={copy.subtitle} icon={<CheckCircle2 size={18} />} />
      <div className="decision-snapshot-meta">
        <span>v{snapshot.report_context.snapshot_version}</span>
        <code>{snapshot.snapshot_hash.slice(0, 12)}</code>
        <em>{snapshot.report_context.analysis_window}</em>
      </div>
      <div className="decision-snapshot-layout">
        <div className="decision-domain-panel">
          <div className="decision-subhead"><strong>{copy.domains}</strong><span>{subjectRows.length}</span></div>
          <div className="decision-domain-rows">
            {subjectRows.map((row) => (
              <div className="decision-domain-row" key={row.id}>
                <div><strong>{row.label}</strong><span title={row.signal}>{row.signal || copy.noSignal}</span></div>
                <dl>
                  <div><dt>{copy.records}</dt><dd>{formatNumber(row.records)}</dd></div>
                  <div><dt>{copy.findings}</dt><dd>{row.findings}</dd></div>
                  <div><dt>{copy.risk}</dt><dd>{row.risk == null ? "N/D" : row.risk.toFixed(2)}</dd></div>
                </dl>
              </div>
            ))}
          </div>
        </div>
        <div className="decision-funnel-panel">
          <div className="decision-subhead"><strong>{copy.funnel}</strong><span>{funnel.supported ?? 0}</span></div>
          <div className="decision-funnel">
            {[
              [copy.templates, funnel.reference_templates],
              [copy.candidate, funnel.candidate],
              [copy.supported, funnel.supported],
              [copy.validated, funnel.validated],
              [copy.confirmed, funnel.confirmed]
            ].map(([label, value]) => <div key={String(label)}><span>{label}</span><strong>{value ?? 0}</strong></div>)}
          </div>
          <div className="decision-action-list">
            <div className="decision-subhead"><strong>{copy.decisions}</strong><span>{snapshot.decisions.length}</span></div>
            {snapshot.decisions.slice(0, 4).map((decision) => (
              <details key={decision.decision_id}>
                <summary title={decision.title}><span className={decision.status}>{decision.status === "act_now" ? copy.act : copy.validate}</span><strong>{decision.title}</strong></summary>
                <p>{decision.rationale}</p>
                <small>{copy.owner}: {decision.owner_role} · {copy.window}: {decision.due_window} · {copy.refs}: [{decision.evidence_ids.join(", ")}]</small>
              </details>
            ))}
            {!snapshot.decisions.length ? <div className="muted-empty">{language === "en" ? "No evidence-supported decision." : "Sin decisión soportada por evidencia."}</div> : null}
          </div>
        </div>
      </div>
    </section>
  );
}

function VulnerabilityIntelPanel({ model, language }: { model: ReturnType<typeof buildDashboardModel>["vulnerabilityIntel"]; language: LanguageMode }) {
  const copy = labels[language];
  const empty = language === "en" ? "No vulnerability evidence collected in this run." : "Sin evidencia de vulnerabilidades en esta corrida.";
  return (
    <div className="vuln-intel-panel">
      <div className="vuln-intel-kpis">
        <Metric label={copy.confirmedCves} value={String(model.confirmedCves)} />
        <Metric label="KEV" value={String(model.kevMatches)} />
        <Metric label={copy.observedTech} value={String(model.observedTechnologies)} />
        <Metric label={copy.surfaceAssets} value={String(model.surfaceAssets)} />
      </div>
      <p>{model.patchFocus}</p>
      <div className="vuln-intel-list">
        {model.rows.map((row, index) => (
          <a key={`${row.label}-${row.asset}-${index}`} href={publicEvidenceUrl(row.evidence_url) || "#"} target="_blank" rel="noreferrer">
            <strong>{row.label}</strong>
            <span>{row.asset}</span>
            <em>{row.status}</em>
          </a>
        ))}
        {!model.rows.length ? <span className="muted-empty">{empty}</span> : null}
      </div>
    </div>
  );
}

function RiskHeatDistribution({ rows, language }: { rows: RiskHeatRow[]; language: LanguageMode }) {
  const copy = {
    es: { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo", empty: "Sin datos de calor de riesgo disponibles." },
    en: { critical: "Critical", high: "High", medium: "Medium", low: "Low", empty: "No risk heat data available." }
  }[language];
  if (!rows.length) return <div className="chart-empty compact-empty">{copy.empty}</div>;
  const buckets = (["critical", "high", "medium", "low"] as const).map((heat) => {
    const bucketRows = rows.filter((row) => row.heat === heat);
    const top = [...bucketRows].sort((left, right) => right.score - left.score)[0];
    return {
      heat,
      label: copy[heat],
      count: bucketRows.length,
      score: top ? Math.round(top.score * 100) : 0
    };
  });
  const max = Math.max(...buckets.map((bucket) => bucket.count), 1);
  return (
    <div className="risk-heat-distribution">
      {buckets.map((bucket) => (
        <div className={`heat-bucket ${bucket.heat}`} key={bucket.heat}>
          <div>
            <span>{bucket.label}</span>
            <strong>{bucket.count}</strong>
          </div>
          <i>
            <b style={{ width: `${Math.max(8, (bucket.count / max) * 100)}%` }} />
          </i>
          <em>{bucket.score}%</em>
        </div>
      ))}
    </div>
  );
}

function buildDisarmPulse(run: RunRecord | undefined, language: LanguageMode): Array<{ name: string; value: number; tone: "medium" }> {
  if (!run) return [];
  const labelsByLanguage = {
    es: {
      narrative: "Narrativa",
      disinformation: "Desinformación",
      amplification: "Amplificación",
      impersonation: "Suplantación",
      trust: "Confianza pública"
    },
    en: {
      narrative: "Narrative",
      disinformation: "Disinformation",
      amplification: "Amplification",
      impersonation: "Impersonation",
      trust: "Public trust"
    }
  };
  const counters = new Map<string, number>([
    ["narrative", 0],
    ["disinformation", 0],
    ["amplification", 0],
    ["impersonation", 0],
    ["trust", 0]
  ]);
  const explicitEvents = (run.summary.events ?? []).filter((event) => {
    const tags = new Set((event.tags ?? []).map((tag) => tag.toLowerCase()));
    return ["direct", "validated", "confirmed"].includes(event.evidence_status ?? "") && (
      ["disinformation", "narrative_manipulation"].includes(event.category) ||
      ["disarm_signal", "narrative_manipulation", "coordinated_amplification", "influence_operation"].some((tag) => tags.has(tag))
    );
  });
  explicitEvents.forEach((event) => {
    const tags = new Set((event.tags ?? []).map((tag) => tag.toLowerCase()));
    if (tags.has("narrative_manipulation")) counters.set("narrative", (counters.get("narrative") ?? 0) + 1);
    if (event.category === "disinformation" || tags.has("disarm_signal")) counters.set("disinformation", (counters.get("disinformation") ?? 0) + 1);
    if (tags.has("coordinated_amplification")) counters.set("amplification", (counters.get("amplification") ?? 0) + 1);
    if (tags.has("impersonation")) counters.set("impersonation", (counters.get("impersonation") ?? 0) + 1);
    if (tags.has("influence_operation")) counters.set("trust", (counters.get("trust") ?? 0) + 1);
  });
  const textLabels = labelsByLanguage[language];
  return Array.from(counters.entries())
    .filter(([, value]) => value > 0)
    .map(([key, value]) => ({ name: textLabels[key as keyof typeof textLabels], value, tone: "medium" as const }))
    .sort((left, right) => right.value - left.value);
}
