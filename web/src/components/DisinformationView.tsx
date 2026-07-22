import { AlertTriangle, GitBranch, Network, ShieldAlert, Target } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { getDisinformationFramework } from "../api";
import type { DisinformationFrameworkResponse, LanguageMode, RunRecord } from "../types";
import { cleanEvidenceTitle, displaySourceName } from "../utils/sourceLabels";
import { BarRanking } from "./ChartPrimitives";

const labels = {
  es: {
    title: "Inteligencia de narrativas, desinformación y riesgo reputacional",
    subtitle: "Noticias, quejas, rumores, fraude y narrativas se conservan por estado. DISARM solo se activa cuando existen indicadores trazables de coordinación.",
    activeSignals: "Señales relacionadas",
    reviewSignals: "Señales por revisar",
    supportedSignals: "Respaldadas / confirmadas",
    disarmTechniques: "Técnicas DISARM",
    disarmTactics: "Tácticas DISARM",
    currentRisk: "Soporte de evidencia",
    tacticMap: "Mapa DISARM por táctica",
    tacticSubtitle: "Tácticas activadas por evidencia de la corrida; si no hay coincidencias no se dibuja mapa.",
    evidenceTitle: "Lectura por estado",
    noEvidence: "No hay señales narrativas relacionadas en la cobertura disponible.",
    noTactics: "Sin tácticas activadas por la evidencia de esta corrida.",
    source: "Fuente framework"
  },
  en: {
    title: "Narrative intelligence, disinformation and reputational risk",
    subtitle: "News, complaints, rumors, fraud and narratives remain visible by state. DISARM activates only with traceable coordination indicators.",
    activeSignals: "Related signals",
    reviewSignals: "Signals to review",
    supportedSignals: "Supported / confirmed",
    disarmTechniques: "DISARM techniques",
    disarmTactics: "DISARM tactics",
    currentRisk: "Evidence support",
    tacticMap: "DISARM tactic map",
    tacticSubtitle: "Tactics activated by run evidence; when no matches exist, no map is drawn.",
    evidenceTitle: "Reading by state",
    noEvidence: "No related narrative signals in the available coverage.",
    noTactics: "No tactics activated by the evidence in this run.",
    source: "Framework source"
  }
};

const disarmMarkers = ["disarm", "disinformation", "misinformation", "influence_operation", "coordinated_amplification", "narrative_manipulation"];

export function DisinformationView({ run, language }: { run?: RunRecord; language: LanguageMode }) {
  const t = labels[language];
  const [framework, setFramework] = useState<DisinformationFrameworkResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDisinformationFramework()
      .then(setFramework)
      .catch((exc) => setError(exc instanceof Error ? exc.message : String(exc)));
  }, []);

  const evidence = useMemo(() => narrativeClaims(run), [run]);
  const reviewSignals = evidence.filter((item) => ["candidate", "under_review"].includes(item.status));
  const supportedSignals = evidence.filter((item) => ["supported", "validated", "confirmed"].includes(item.status));
  const disarmEvidence = evidence.filter((item) => item.disarmEligible);
  const tacticItems = useMemo(() => buildActiveDisarmTactics(disarmEvidence, language), [disarmEvidence, language]);

  return (
    <div className="view-stack">
      <section className="panel module-hero">
        <div>
          <Network size={24} />
          <h2>{t.title}</h2>
          <p>{t.subtitle}</p>
        </div>
        <div className="privacy-note">
          <GitBranch size={18} />
          <span>{framework?.techniques.length ?? 0} {t.disarmTechniques} · {framework?.tactics.length ?? 0} {t.disarmTactics}</span>
        </div>
      </section>

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="dashboard-kpis">
        <Metric icon={<AlertTriangle size={18} />} label={t.activeSignals} value={String(evidence.length)} />
        <Metric icon={<AlertTriangle size={18} />} label={t.reviewSignals} value={String(reviewSignals.length)} />
        <Metric icon={<ShieldAlert size={18} />} label={t.supportedSignals} value={String(supportedSignals.length)} />
        <Metric icon={<Target size={18} />} label={t.disarmTactics} value={String(tacticItems.length)} />
      </section>

      <section className="disinfo-layout">
        <article className="panel chart-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{t.tacticMap}</h2>
              <p>{t.tacticSubtitle}</p>
            </div>
            <Target size={18} />
          </div>
          {tacticItems.length ? <BarRanking items={tacticItems} language={language} /> : <div className="chart-empty">{t.noTactics}</div>}
          {framework?.source_url ? <a className="source-link" href={framework.source_url} target="_blank" rel="noreferrer">{t.source}: DISARM Foundation</a> : null}
        </article>

        <article className="panel chart-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{t.evidenceTitle}</h2>
              <p>{run?.domains.join(", ") || "n/a"}</p>
            </div>
          </div>
          {evidence.length ? <div className="narrative-state-groups">
            <NarrativeGroup title={t.reviewSignals} claims={reviewSignals} language={language} />
            <NarrativeGroup title={t.supportedSignals} claims={supportedSignals} language={language} />
            <NarrativeGroup title={language === "es" ? "Contradicciones y desmentidos" : "Contradictions and corrections"} claims={evidence.filter((item) => item.status === "contradicted" || item.contentType === "correction_or_denial" || item.contentType === "fact_check")} language={language} />
          </div> : <div className="chart-empty">{t.noEvidence}</div>}
        </article>
      </section>
    </div>
  );
}

interface NarrativeClaimView {
  id: string;
  title: string;
  source: string;
  sourceRefs: string[];
  url?: string | null;
  contentType: string;
  truthStatus: string;
  coordinationStatus: string;
  status: string;
  confidence: number;
  relevance: number;
  reviewReason: string;
  disarmEligible: boolean;
}

function buildActiveDisarmTactics(evidence: NarrativeClaimView[], language: LanguageMode) {
  const names =
    language === "en"
      ? {
          narrative: "Narrative trust pressure",
          amplification: "Coordinated amplification",
          manipulation: "Influence manipulation",
          reputation: "Brand deception signal"
        }
      : {
          narrative: "Presión sobre confianza narrativa",
          amplification: "Amplificación coordinada",
          manipulation: "Manipulación de influencia",
          reputation: "Señal de engaño de marca"
        };
  const counts = {
    narrative: 0,
    amplification: 0,
    manipulation: 0,
    reputation: 0
  };
  for (const item of evidence) {
    const text = `${item.title} ${item.contentType} ${item.coordinationStatus} ${item.source}`.toLowerCase();
    if (/desinform|disinform|misinform|fake|rumor|narrative|narrativa/.test(text)) counts.narrative += 1;
    if (/bot|coordin|viral|meme|amplif/.test(text)) counts.amplification += 1;
    if (/propaganda|influenc|manipul/.test(text)) counts.manipulation += 1;
    if (/farsa|fraud|scam|phish|suplant|imperson/.test(text)) counts.reputation += 1;
  }
  return Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([key, value]) => ({
      name: names[key as keyof typeof names],
      value,
      tone: value >= 4 ? "high" as const : "medium" as const
    }));
}

function narrativeClaims(run?: RunRecord): NarrativeClaimView[] {
  const metrics = run?.summary.metrics as { narrative_intelligence?: { claims?: Array<Record<string, unknown>> } } | undefined;
  const modeled = metrics?.narrative_intelligence?.claims ?? [];
  if (modeled.length) {
    return modeled.map((claim) => ({
      id: String(claim.claimId ?? ""),
      title: String(claim.claimText ?? claim.title ?? ""),
      source: String(claim.source ?? ""),
      sourceRefs: Array.isArray(claim.sourceRefs) ? claim.sourceRefs.map(String) : [],
      url: typeof claim.url === "string" ? claim.url : null,
      contentType: String(claim.contentType ?? "unverified_claim"),
      truthStatus: String(claim.truthStatus ?? "unverified"),
      coordinationStatus: String(claim.coordinationStatus ?? "insufficient_data"),
      status: String(claim.status ?? "under_review"),
      confidence: Number(claim.confidence ?? 0),
      relevance: Number(claim.cybersecurityRelevance ?? 0),
      reviewReason: String(claim.reviewReason ?? ""),
      disarmEligible: Boolean(claim.disarmEligible)
    }));
  }
  const events = run?.summary.records ?? run?.summary.events ?? [];
  return events
    .map((event) => {
      const tags = (event.tags ?? []).map((tag) => tag.toLowerCase());
      const category = event.category.toLowerCase();
      const status = event.evidence_status ?? "raw";
      const explicit = category === "disinformation" || /fraud|complaint|rumor|narrativ|imperson|phish|fake/.test(`${category} ${tags.join(" ")}`) || tags.some((tag) => disarmMarkers.includes(tag) || tag.startsWith("disarm:"));
      if (!explicit) return null;
      return {
        id: event.canonical_id ?? event.id,
        title: event.title,
        source: event.source,
        sourceRefs: event.source_refs ?? [],
        url: event.evidence_url,
        contentType: category === "disinformation" ? "potential_disinformation" : category,
        truthStatus: "unverified",
        coordinationStatus: "insufficient_data",
        status: ["direct", "validated", "confirmed"].includes(status) ? status : "under_review",
        confidence: event.confidence_score ?? 0,
        relevance: 0,
        reviewReason: languageFallbackReviewReason,
        disarmEligible: false
      };
    })
    .filter(Boolean)
    .slice(0, 40) as NarrativeClaimView[];
}

const languageFallbackReviewReason = "Related signal pending deterministic reprocessing.";

function NarrativeGroup({ title, claims, language }: { title: string; claims: NarrativeClaimView[]; language: LanguageMode }) {
  if (!claims.length) return null;
  return <details className="narrative-state-group" open>
    <summary><strong>{title}</strong><span>{claims.length}</span></summary>
    <div className="signal-list narrative-signal-list">
      {claims.map((item) => (
        <a href={item.url ?? "#"} target="_blank" rel="noreferrer" key={item.id}>
          <strong>{cleanEvidenceTitle(item.title)}</strong>
          <span>{displaySourceName(item.source, language)} · {item.contentType.replace(/_/g, " ")}</span>
          <small>{item.truthStatus.replace(/_/g, " ")} · {item.coordinationStatus.replace(/_/g, " ")} · {Math.round(item.confidence)}%</small>
          <em>{item.reviewReason}</em>
        </a>
      ))}
    </div>
  </details>;
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
