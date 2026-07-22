import { BadgeAlert, ExternalLink, Fingerprint, RadioTower, Scale, ShieldAlert, SmilePlus, Waypoints } from "lucide-react";
import type { ReactNode } from "react";
import type { LanguageMode, RunRecord } from "../types";
import { buildBrandRiskModel } from "../utils/dashboard";
import { formatDateTime } from "../utils/format";
import { BarRanking, LineChart } from "./ChartPrimitives";

const labels = {
  es: {
    author: "Modelo creado por Edwin Peñuela",
    title: "Cyberinteligencia para riesgo de marca, fraude y decision accionable",
    body:
      "Busca menciones publicas asociadas a dominios, marca, grupo o conglomerado; consolida URL, fuente, categoria y senal de riesgo para apoyar prevencion, takedown, comunicacion, SOC, fraude e investigacion.",
    exposure: "exposicion de marca",
    pressure: "presion de fraude",
    reputation: "impacto reputacional",
    negative: "senales negativas",
    mentions: "Menciones",
    fraudSignals: "Senales de fraude",
    darkWebSignals: "Senales Dark Web",
    socmintSignals: "Senales SOCMINT",
    trend: "Tendencia de menciones de marca",
    trendSubtitle: "Solo evidencia de la corrida actual que coincide con marca/dominios",
    toneMix: "Mezcla de tono de riesgo",
    toneSubtitle: "Severidad derivada de palabras clave en titulos/etiquetas",
    sentiment: "Sentimiento por frase",
    sentimentSubtitle: "Lectura positiva, neutra o negativa calculada sobre frases recolectadas",
    domainSentiment: "Sentimiento por dominio",
    domainSentimentSubtitle: "Balance reputacional por dominio dentro de la corrida",
    lookalikes: "Dominios parecidos observados",
    lookalikesSubtitle: "Similitud detectada solo desde URLs recolectadas; requiere validacion",
    emptyLookalikes: "Sin dominios parecidos observados en las URLs de la corrida.",
    sources: "Fuentes",
    sourcesSubtitle: "Donde se menciona la marca o dominio",
    categories: "Categorias",
    categoriesSubtitle: "Taxonomia observada de riesgo e inteligencia",
    scope: "Alcance de busqueda",
    scopeSubtitle: "Terminos de marca, grupo, conglomerado y dominios",
    emptyScope: "Agrega dominios o nombre de organizacion para construir alcance de marca.",
    records: "Menciones, noticias y comentarios",
    recordsSubtitle: "Evidencia URL por URL desde internet, SOCMINT y fuentes dark web indexadas",
    emptyRecords: "Sin menciones de marca/dominio en la corrida actual.",
    actions: "Acciones de decision",
    actionsSubtitle: "Acciones de fraude, reputacion y prevencion"
  },
  en: {
    author: "Model created by Edwin Peñuela",
    title: "Cyber intelligence for brand risk, fraud and actionable decisions",
    body:
      "Searches public mentions tied to domains, brand, group or conglomerate; consolidates URL, source, category and risk signal to support prevention, takedown, communications, SOC, fraud and investigation.",
    exposure: "brand exposure",
    pressure: "fraud pressure",
    reputation: "reputation impact",
    negative: "negative signals",
    mentions: "Mentions",
    fraudSignals: "Fraud signals",
    darkWebSignals: "Dark web signals",
    socmintSignals: "SOCMINT signals",
    trend: "Brand mention trend",
    trendSubtitle: "Only current-run evidence that matches brand/domain terms",
    toneMix: "Risk tone mix",
    toneSubtitle: "Keyword-derived severity from collected titles/tags",
    sentiment: "Phrase sentiment",
    sentimentSubtitle: "Positive, neutral or negative reading calculated over collected phrases",
    domainSentiment: "Sentiment by domain",
    domainSentimentSubtitle: "Reputation balance by domain within the run",
    lookalikes: "Observed similar domains",
    lookalikesSubtitle: "Similarity detected only from collected URLs; validation required",
    emptyLookalikes: "No similar domains observed in current-run URLs.",
    sources: "Sources",
    sourcesSubtitle: "Where the brand/domain is mentioned",
    categories: "Categories",
    categoriesSubtitle: "Observed risk and intelligence taxonomy",
    scope: "Search scope",
    scopeSubtitle: "Brand, group, conglomerate and domain terms",
    emptyScope: "Add domains or organization name to build brand scope.",
    records: "Mentions, news and comments",
    recordsSubtitle: "URL-level evidence from internet/SOCMINT/dark web indexed sources",
    emptyRecords: "No brand/domain mentions found in the current run.",
    actions: "Decision actions",
    actionsSubtitle: "Fraud, reputation and prevention actions"
  }
};

export function BrandRiskView({ run, language }: { run?: RunRecord; language: LanguageMode }) {
  const copy = labels[language];
  const model = buildBrandRiskModel(run);
  return (
    <div className="view-stack">
      <section className="brand-risk-hero panel">
        <div>
          <span>{copy.author}</span>
          <h2>{copy.title}</h2>
          <p>{copy.body}</p>
        </div>
        <div className="brand-risk-score">
          <strong>{model.brandExposure}%</strong>
          <span>{copy.exposure}</span>
        </div>
        <div className="brand-risk-score fraud">
          <strong>{model.fraudPressure}%</strong>
          <span>{copy.pressure}</span>
        </div>
        <div className="brand-risk-score reputation">
          <strong>{model.reputationImpact}%</strong>
          <span>{copy.reputation}</span>
        </div>
      </section>

      <section className="dashboard-kpis">
        <Metric icon={<RadioTower size={18} />} label={copy.mentions} value={String(model.mentions.length)} />
        <Metric icon={<Fingerprint size={18} />} label={copy.fraudSignals} value={String(model.fraudSignals)} />
        <Metric icon={<ShieldAlert size={18} />} label={copy.darkWebSignals} value={String(model.darkWebSignals)} />
        <Metric icon={<BadgeAlert size={18} />} label={copy.socmintSignals} value={String(model.socmintSignals)} />
        <Metric icon={<SmilePlus size={18} />} label={copy.negative} value={String(model.negativeSignals)} />
      </section>

      <section className="dashboard-grid brand-risk-grid">
        <article className="panel chart-card span-6">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.trend}</h2>
              <p>{copy.trendSubtitle}</p>
            </div>
          </div>
          <LineChart points={model.trend} language={language} />
        </article>
        <article className="panel chart-card span-3">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.toneMix}</h2>
              <p>{copy.toneSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.toneMix} language={language} />
        </article>
        <article className="panel chart-card span-3">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.sentiment}</h2>
              <p>{copy.sentimentSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.sentimentMix} language={language} />
        </article>
        <article className="panel chart-card span-6 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.domainSentiment}</h2>
              <p>{copy.domainSentimentSubtitle}</p>
            </div>
            <Scale size={18} />
          </div>
          <div className="brand-domain-sentiment">
            {model.domainSentiment.map((item) => (
              <div key={item.domain} className="domain-sentiment-row">
                <div>
                  <strong>{item.domain}</strong>
                  <span>{item.total} señales | impacto {item.reputationImpact}%</span>
                </div>
                <div className="sentiment-stack" aria-label={`${item.domain} ${item.negative}/${item.neutral}/${item.positive}`}>
                  <i className="negative" style={{ flexGrow: item.negative }} />
                  <i className="neutral" style={{ flexGrow: item.neutral }} />
                  <i className="positive" style={{ flexGrow: item.positive }} />
                </div>
              </div>
            ))}
          </div>
        </article>
        <article className="panel chart-card span-6 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.lookalikes}</h2>
              <p>{copy.lookalikesSubtitle}</p>
            </div>
            <Waypoints size={18} />
          </div>
          <div className="lookalike-list">
            {model.lookalikes.map((item) => (
              <a className={`lookalike-row ${item.tone}`} key={`${item.targetDomain}-${item.observedDomain}-${item.url}`} href={item.url} target="_blank" rel="noreferrer">
                <div>
                  <strong>{item.observedDomain}</strong>
                  <span>{item.reason}</span>
                  <em>{item.source}</em>
                </div>
                <b>{item.similarity}%</b>
              </a>
            ))}
            {!model.lookalikes.length ? <div className="chart-empty">{copy.emptyLookalikes}</div> : null}
          </div>
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.sources}</h2>
              <p>{copy.sourcesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.sourceRanking} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.categories}</h2>
              <p>{copy.categoriesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categoryRanking} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.scope}</h2>
              <p>{copy.scopeSubtitle}</p>
            </div>
          </div>
          <div className="term-cloud">
            {model.terms.map((term) => <span key={term}>{term}</span>)}
            {!model.terms.length ? <div className="chart-empty">{copy.emptyScope}</div> : null}
          </div>
        </article>
        <article className="panel chart-card span-8 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.records}</h2>
              <p>{copy.recordsSubtitle}</p>
            </div>
            <ExternalLink size={18} />
          </div>
          <div className="mention-list">
            {model.mentions.map((mention) => (
              <a className={`mention-row ${mention.tone}`} key={mention.id} href={mention.url ?? "#"} target="_blank" rel="noreferrer">
                <div>
                  <strong>{mention.title}</strong>
                  <span>{mention.source} | {mention.category} | {formatDateTime(mention.observedAt)}</span>
                  <em>{mention.driver}</em>
                </div>
                <b>{mention.term}</b>
              </a>
            ))}
            {!model.mentions.length ? <div className="chart-empty">{copy.emptyRecords}</div> : null}
          </div>
        </article>
        <article className="panel chart-card span-4 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.actions}</h2>
              <p>{copy.actionsSubtitle}</p>
            </div>
          </div>
          <div className="decision-list">
            {model.recommendations.map((item) => <p key={item}>{item}</p>)}
          </div>
        </article>
      </section>
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
