import { Globe2, Network, RadioTower, SearchCode } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { defaultDashboardFilters } from "../data/catalog";
import type { LanguageMode, RunRecord, ThreatEvent } from "../types";
import { buildDashboardModel, sourceEvents } from "../utils/dashboard";
import { displaySourceName } from "../utils/sourceLabels";
import { BarRanking } from "./ChartPrimitives";
import { GraphInsight } from "./DecisionCharts";
import { SocmintView } from "./SocmintView";
import { SourceIntelligenceView } from "./SourceIntelligenceView";

type IntelligenceSection = "integrated" | "osint" | "socmint";

const copy = {
  es: {
    integrated: "Vista integrada",
    osint: "OSINT",
    socmint: "SOCMINT",
    title: "Inteligencia de fuentes abiertas y sociales",
    subtitle: "Lectura conjunta de web pública, noticias, documentos y menciones sociales de la corrida seleccionada",
    records: "Registros únicos",
    publicWeb: "Registros OSINT",
    social: "Registros SOCMINT",
    sources: "Fuentes observadas",
    coverage: "Cobertura por canal",
    coverageSubtitle: "Volumen real recolectado en la corrida actual",
    relationships: "Relaciones de inteligencia social",
    relationshipsSubtitle: "Entidades y conexiones sustentadas por menciones públicas",
    themes: "Temas observados",
    themesSubtitle: "Concentración de categorías en el conjunto integrado",
    platforms: "Plataformas y canales",
    platformsSubtitle: "Distribución de menciones sociales recolectadas",
    composition: "Composición de la inteligencia recolectada",
    compositionSubtitle: "Distribución visual por tipo de evidencia",
    sourceContribution: "Aporte por fuente",
    sourceContributionSubtitle: "Fuentes que concentran los registros únicos de la corrida",
    empty: "Sin registros OSINT o SOCMINT en la corrida seleccionada.",
    noSocialGraph: "No hay relaciones SOCMINT trazables en la corrida actual."
  },
  en: {
    integrated: "Integrated view",
    osint: "OSINT",
    socmint: "SOCMINT",
    title: "Open-source and social intelligence",
    subtitle: "Combined view of public web, news, documents and social mentions from the selected run",
    records: "Unique records",
    publicWeb: "OSINT records",
    social: "SOCMINT records",
    sources: "Observed sources",
    coverage: "Channel coverage",
    coverageSubtitle: "Actual volume collected in the current run",
    relationships: "Social intelligence relationships",
    relationshipsSubtitle: "Entities and connections supported by public mentions",
    themes: "Observed topics",
    themesSubtitle: "Category concentration across the integrated dataset",
    platforms: "Platforms and channels",
    platformsSubtitle: "Distribution of collected social mentions",
    composition: "Collected intelligence composition",
    compositionSubtitle: "Visual distribution by evidence type",
    sourceContribution: "Source contribution",
    sourceContributionSubtitle: "Sources concentrating unique records in the run",
    empty: "No OSINT or SOCMINT records in the selected run.",
    noSocialGraph: "No traceable SOCMINT relationships in the current run."
  }
};

export function OpenSourceIntelligenceView({
  run,
  language,
  initialSection = "integrated"
}: {
  run?: RunRecord;
  language: LanguageMode;
  initialSection?: IntelligenceSection;
}) {
  const labels = copy[language];
  const [section, setSection] = useState<IntelligenceSection>(initialSection);
  const osintEvents = sourceEvents(run, "osint");
  const socmintEvents = sourceEvents(run, "socmint");
  const combinedEvents = useMemo(
    () => uniqueEvents([...osintEvents, ...socmintEvents]),
    [osintEvents, socmintEvents]
  );
  const combinedRun = run ? { ...run, summary: { ...run.summary, events: combinedEvents } } : undefined;
  const socialRun = run ? { ...run, summary: { ...run.summary, events: socmintEvents } } : undefined;
  const model = buildDashboardModel(combinedRun, defaultDashboardFilters);
  const socialModel = buildDashboardModel(socialRun, defaultDashboardFilters);
  const sourceCount = new Set(combinedEvents.map((event) => displaySourceName(event.source, language))).size;
  const evidenceComposition = rankedEvents(combinedEvents, (event) => evidenceTypeName(event.evidence_type, language));
  const sourceContribution = rankedEvents(combinedEvents, (event) => displaySourceName(event.source, language));

  useEffect(() => setSection(initialSection), [initialSection]);

  return (
    <div className="view-stack public-intelligence-workspace">
      <section className="panel public-intelligence-header">
        <div>
          <h2>{labels.title}</h2>
          <p>{labels.subtitle}</p>
        </div>
        <div className="intelligence-tabs" role="tablist" aria-label={labels.title}>
          {(["integrated", "osint", "socmint"] as IntelligenceSection[]).map((item) => (
            <button
              type="button"
              role="tab"
              aria-selected={section === item}
              className={section === item ? "selected" : ""}
              onClick={() => setSection(item)}
              key={item}
            >
              {labels[item]}
            </button>
          ))}
        </div>
      </section>

      {section === "osint" ? <SourceIntelligenceView run={run} channel="osint" language={language} /> : null}
      {section === "socmint" ? <SocmintView run={run} language={language} /> : null}
      {section === "integrated" ? (
        <>
          <section className="dashboard-kpis">
            <Metric icon={<Globe2 size={18} />} label={labels.records} value={String(combinedEvents.length)} />
            <Metric icon={<SearchCode size={18} />} label={labels.publicWeb} value={String(osintEvents.length)} />
            <Metric icon={<RadioTower size={18} />} label={labels.social} value={String(socmintEvents.length)} />
            <Metric icon={<Network size={18} />} label={labels.sources} value={String(sourceCount)} />
          </section>

          <section className="dashboard-grid public-intelligence-grid">
            <article className={`panel chart-card public-channel-card ${socialModel.socmintAvailable ? "span-4" : "span-12 public-channel-card-wide"}`}>
              <PanelTitle title={labels.coverage} subtitle={labels.coverageSubtitle} />
              <BarRanking
                items={[
                  { name: "OSINT", value: osintEvents.length },
                  { name: "SOCMINT", value: socmintEvents.length }
                ]}
                language={language}
              />
            </article>

            {socialModel.socmintAvailable ? (
              <article className="panel chart-card span-8 public-relationship-card">
                <PanelTitle title={labels.relationships} subtitle={labels.relationshipsSubtitle} />
                <GraphInsight
                  metrics={socialModel.graphMetrics}
                  nodes={socialModel.socmintNodes}
                  links={socialModel.socmintLinks}
                  language={language}
                  hideConfidenceMetric
                />
              </article>
            ) : null}

            <article className={`panel chart-card compact-card ${socialModel.socmintAvailable ? "span-6" : "span-12"}`}>
              <PanelTitle title={labels.themes} subtitle={labels.themesSubtitle} />
              <BarRanking items={model.categories} language={language} />
            </article>

            {socialModel.socmintAvailable ? (
              <article className="panel chart-card span-6 compact-card">
                <PanelTitle title={labels.platforms} subtitle={labels.platformsSubtitle} />
                <BarRanking items={socialModel.platformMentions} language={language} />
              </article>
            ) : null}

            <article className="panel chart-card span-6 compact-card">
              <PanelTitle title={labels.composition} subtitle={labels.compositionSubtitle} />
              <BarRanking items={evidenceComposition} language={language} />
            </article>

            <article className="panel chart-card span-6 compact-card">
              <PanelTitle title={labels.sourceContribution} subtitle={labels.sourceContributionSubtitle} />
              <BarRanking items={sourceContribution} language={language} />
            </article>
          </section>
        </>
      ) : null}
    </div>
  );
}

function uniqueEvents(events: ThreatEvent[]): ThreatEvent[] {
  const unique = new Map<string, ThreatEvent>();
  events.forEach((event) => unique.set(event.canonical_id ?? event.content_hash ?? event.id, event));
  return [...unique.values()].sort((a, b) => b.observed_at.localeCompare(a.observed_at));
}

function rankedEvents(events: ThreatEvent[], selector: (event: ThreatEvent) => string): Array<{ name: string; value: number }> {
  const counts = new Map<string, number>();
  events.forEach((event) => {
    const name = selector(event);
    counts.set(name, (counts.get(name) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

function evidenceTypeName(type: ThreatEvent["evidence_type"], language: LanguageMode): string {
  const labels = language === "es"
    ? {
        document: "Documentos y archivos",
        web_page: "Páginas web",
        news: "Noticias y comunicados",
        social_media: "Redes sociales",
        technology_infrastructure: "Tecnología e infraestructura",
        official_record: "Registros oficiales",
        authorized_dark_web: "Dark Web autorizada",
        other: "Otros"
      }
    : {
        document: "Documents and files",
        web_page: "Web pages",
        news: "News and releases",
        social_media: "Social media",
        technology_infrastructure: "Technology and infrastructure",
        official_record: "Official records",
        authorized_dark_web: "Authorized Dark Web",
        other: "Other"
      };
  return labels[type ?? "other"];
}

function PanelTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="panel-title-row compact">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
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
