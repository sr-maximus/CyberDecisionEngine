import { Network, RadioTower, Search } from "lucide-react";
import type { LanguageMode, RunRecord } from "../types";
import { defaultDashboardFilters } from "../data/catalog";
import { buildDashboardModel, buildExposureAudit, sourceEvents } from "../utils/dashboard";
import { BarRanking } from "./ChartPrimitives";
import { GraphInsight } from "./DecisionCharts";
import { SourceDiagnosticsPanel } from "./SourceDiagnosticsPanel";
import { eventEvidenceUrl } from "../utils/sourceLabels";

const labels = {
  es: {
    audit: "Auditoria SOCMINT de exposicion",
    auditSubtitle: "Patrones defensivos de busqueda publica para menciones sociales e impersonacion",
    matchedRecords: "registros coincidentes",
    emptyAudit: "Sin dominios disponibles para auditoria SOCMINT de exposicion.",
    map: "Mapa de relaciones SOCMINT",
    mapSubtitle: "Menciones publicas, usuarios/temas relacionados y relaciones de plataforma",
    emptyGraph: "Sin senales SOCMINT disponibles. El grafo no se renderiza hasta que existan menciones sociales publicas en la corrida actual.",
    platformTrend: "Tendencia de menciones por plataforma",
    platformSubtitle: "Facebook, Instagram, TikTok, X y web publica",
    graph: "Analisis de grafo",
    graphSubtitle: "Densidad, clusters y confianza para decisiones inmediatas",
    topics: "Temas y narrativas",
    topicsSubtitle: "Temas publicos mas repetidos",
    stream: "Flujo de senales publicas",
    streamSubtitle: "Ultimas menciones publicas desde fuentes conectadas",
    emptyStream: "Sin flujo publico SOCMINT en la corrida actual."
  },
  en: {
    audit: "SOCMINT exposure audit",
    auditSubtitle: "Defensive public-search patterns for social mention and impersonation review",
    matchedRecords: "matched records",
    emptyAudit: "No domains available for SOCMINT exposure audit.",
    map: "SOCMINT relationship map",
    mapSubtitle: "Public mentions, related users/topics and platform relationships",
    emptyGraph: "No SOCMINT signals available. The node graph is intentionally not rendered until public social mentions exist in the current run.",
    platformTrend: "Platform mention trend",
    platformSubtitle: "Facebook, Instagram, TikTok, X and public web",
    graph: "Graph analysis",
    graphSubtitle: "Density, clusters and confidence for immediate decisions",
    topics: "Topics and narratives",
    topicsSubtitle: "Most repeated public themes",
    stream: "Public signal stream",
    streamSubtitle: "Latest public mentions from connected sources",
    emptyStream: "No SOCMINT public signal stream in the current run."
  }
};

export function SocmintView({ run, language }: { run?: RunRecord; language: LanguageMode }) {
  const copy = labels[language];
  const socmintEvents = sourceEvents(run, "socmint");
  const scopedRun = run ? { ...run, summary: { ...run.summary, events: socmintEvents } } : undefined;
  const model = buildDashboardModel(scopedRun, defaultDashboardFilters);
  const exposureAudit = buildExposureAudit(run, socmintEvents, "socmint");

  if (!socmintEvents.length) {
    return (
      <div className="view-stack">
        <section className="socmint-grid">
          <SourceDiagnosticsPanel run={run} channel="socmint" language={language} className="span-4" />
          <article className="panel chart-card span-8 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.audit}</h2>
                <p>{copy.auditSubtitle}</p>
              </div>
              <Search size={18} />
            </div>
            <div className="exposure-audit-grid">
              {exposureAudit.map((item) => (
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
              {!exposureAudit.length ? <div className="chart-empty">{copy.emptyAudit}</div> : null}
            </div>
          </article>
        </section>
      </div>
    );
  }

  return (
    <div className="view-stack">
      <section className="socmint-grid">
        <article className="panel chart-card socmint-main span-8">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.map}</h2>
              <p>{copy.mapSubtitle}</p>
            </div>
            <Network size={18} />
          </div>
          {model.socmintAvailable ? (
            <GraphInsight metrics={model.graphMetrics} nodes={model.socmintNodes} links={model.socmintLinks} language={language} />
          ) : (
            <div className="chart-empty socmint-empty">
              {copy.emptyGraph}
            </div>
          )}
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.platformTrend}</h2>
              <p>{copy.platformSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.platformMentions} language={language} />
        </article>
        <SourceDiagnosticsPanel run={run} channel="socmint" language={language} className="span-4" />
        <article className="panel chart-card span-8 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.audit}</h2>
              <p>{copy.auditSubtitle}</p>
            </div>
            <Search size={18} />
          </div>
          <div className="exposure-audit-grid">
            {exposureAudit.map((item) => (
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
            {!exposureAudit.length ? <div className="chart-empty">{copy.emptyAudit}</div> : null}
          </div>
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.graph}</h2>
              <p>{copy.graphSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.graphMetrics.map((metric) => ({ name: metric.label, value: Number.parseFloat(metric.value) || 0 }))} language={language} />
        </article>
        <article className="panel chart-card span-8 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.topics}</h2>
              <p>{copy.topicsSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categories} language={language} />
        </article>
        <article className="panel chart-card span-12 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.stream}</h2>
              <p>{copy.streamSubtitle}</p>
            </div>
            <RadioTower size={18} />
          </div>
          <div className="headline-list">
            {model.latestHeadlines.map((event) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{event.source}</strong>
                <span>{event.title}</span>
              </a>
            ))}
            {!model.latestHeadlines.length ? <span className="muted-empty">{copy.emptyStream}</span> : null}
          </div>
        </article>
      </section>
    </div>
  );
}
