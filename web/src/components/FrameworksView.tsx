import { GitBranch, ShieldAlert, ShieldCheck, Target } from "lucide-react";
import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import type { LanguageMode, RunRecord } from "../types";
import { defaultDashboardFilters } from "../data/catalog";
import { buildDashboardModel, FRAMEWORK_REFERENCES_VERIFIED_AT, type FrameworkMappingItem } from "../utils/dashboard";
import { localizeFrameworkList, localizeFrameworkText } from "../utils/frameworkLocalization";
import { BarRanking } from "./ChartPrimitives";
import { FrameworkMapping } from "./DecisionCharts";

const labels = {
  es: {
    frameworks: "Frameworks",
    criticalHigh: "Crítico / Alto",
    coverageAvg: "Cobertura prom.",
    decisionScope: "Alcance decisión",
    enterprise: "empresa",
    title: "Mapeo de controles por framework",
    subtitle: "NIST CSF, ISO 27001, PCI DSS, SOC 2, GDPR, CIS, MITRE ATT&CK, D3FEND, ATLAS y COBIT",
    exposure: "Ranking de exposición",
    exposureSubtitle: "Prioridad de decisión por framework",
    alignment: "Alineación con amenazas",
    alignmentSubtitle: "Familias de control ligadas a señales activas",
    matrixTitle: "Matriz avanzada de controles",
    matrixSubtitle: "Cruce tipo matriz para revisar qué dominios, controles y aspectos se relacionan entre frameworks",
    matrixDetail: "Detalle del cruce",
    mappingIntensity: "Intensidad de mapeo",
    intensityTitle: "Cómo leer la intensidad",
    intensityHelp:
      "No mide cumplimiento ni madurez. Es una señal de relación calculada con dominios, aspectos afectados, evidencia activa y exposición del framework.",
    referenceBase: "Base oficial",
    referenceDate: "Fecha de referencia",
    verifiedAt: `Verificado con fuentes oficiales el ${FRAMEWORK_REFERENCES_VERIFIED_AT}`,
    affectedSpecifics: "Qué afecta",
    mappedEvidence: "Evidencia relacionada",
    decisionReading: "Lectura de decisión",
    noDirectMap: "Sin relación directa en los datos actuales",
    matrixAxes: {
      governance: "Gobierno",
      identity: "Identidad",
      protect: "Protección",
      detect: "Detección",
      response: "Respuesta",
      privacy: "Datos y privacidad",
      vulnerability: "Vulnerabilidad",
      fraud: "Fraude y marca",
      ai: "Abuso de IA",
      adversary: "Comportamiento adversario"
    }
  },
  en: {
    frameworks: "Frameworks",
    criticalHigh: "Critical / High",
    coverageAvg: "Coverage avg",
    decisionScope: "Decision scope",
    enterprise: "enterprise",
    title: "Framework control mapping",
    subtitle: "NIST CSF, ISO 27001, PCI DSS, SOC 2, GDPR, CIS, MITRE ATT&CK, D3FEND, ATLAS and COBIT",
    exposure: "Exposure ranking",
    exposureSubtitle: "Decision priority by framework",
    alignment: "Threat alignment",
    alignmentSubtitle: "Control families linked to active signals",
    matrixTitle: "Advanced control matrix",
    matrixSubtitle: "Matrix-style crosswalk to review which domains, controls and aspects relate across frameworks",
    matrixDetail: "Crosswalk detail",
    mappingIntensity: "Mapping intensity",
    intensityTitle: "How to read intensity",
    intensityHelp:
      "It is not compliance or maturity. It is a relationship signal calculated from domains, affected aspects, active evidence and framework exposure.",
    referenceBase: "Official base",
    referenceDate: "Reference date",
    verifiedAt: `Verified against official sources on ${FRAMEWORK_REFERENCES_VERIFIED_AT}`,
    affectedSpecifics: "Affected specifics",
    mappedEvidence: "Related evidence",
    decisionReading: "Decision reading",
    noDirectMap: "No direct relation in current data",
    matrixAxes: {
      governance: "Governance",
      identity: "Identity",
      protect: "Protection",
      detect: "Detection",
      response: "Response",
      privacy: "Data and privacy",
      vulnerability: "Vulnerability",
      fraud: "Fraud and brand",
      ai: "AI abuse",
      adversary: "Adversary behavior"
    }
  }
};

type MatrixAxisId = keyof typeof labels.es.matrixAxes;

interface MatrixAxis {
  id: MatrixAxisId;
  keywords: string[];
}

interface MatrixCell {
  id: string;
  framework: FrameworkMappingItem;
  axis: MatrixAxis;
  score: number;
  controls: string[];
  evidence: string[];
  tone: "none" | "low" | "medium" | "high";
}

const matrixAxes: MatrixAxis[] = [
  { id: "governance", keywords: ["govern", "governance", "leadership", "risk", "context", "cobit", "ownership", "assurance", "decision", "lawful"] },
  { id: "identity", keywords: ["identity", "access", "credential", "account", "session", "privileged", "mfa", "ato"] },
  { id: "protect", keywords: ["protect", "hardening", "configuration", "isolate", "evict", "recover", "controls", "safeguard"] },
  { id: "detect", keywords: ["detect", "monitor", "monitoring", "logging", "evidence", "detection", "source", "hunting"] },
  { id: "response", keywords: ["respond", "response", "recover", "recovery", "playbook", "notification", "incident", "continuity"] },
  { id: "privacy", keywords: ["privacy", "personal", "data", "confidentiality", "breach", "processor", "lawful", "cardholder"] },
  { id: "vulnerability", keywords: ["vulnerability", "kev", "cve", "exploit", "patch", "testing", "external", "surface"] },
  { id: "fraud", keywords: ["fraud", "phishing", "brand", "impersonation", "payment", "trust", "abuse", "social"] },
  { id: "ai", keywords: ["ai", "atlas", "model", "prompt", "agent", "training", "llm", "autonomy"] },
  { id: "adversary", keywords: ["attack", "mitre", "ttp", "tactic", "technique", "initial", "execution", "persistence", "impact"] }
];

export function FrameworksView({ run, language }: { run?: RunRecord; language: LanguageMode }) {
  const copy = labels[language];
  const model = buildDashboardModel(run, defaultDashboardFilters);
  const critical = model.frameworkMappings.filter((item) => item.tone === "critical").length;
  const high = model.frameworkMappings.filter((item) => item.tone === "high").length;
  const avgCoverage = Math.round(model.frameworkMappings.reduce((sum, item) => sum + item.coverage, 0) / Math.max(1, model.frameworkMappings.length));
  const exposureRank = model.frameworkMappings.map((item) => ({ name: item.name, value: item.exposure, tone: item.tone }));

  return (
    <div className="view-stack">
      <section className="dashboard-kpis">
        <Metric icon={<GitBranch size={18} />} label={copy.frameworks} value={String(model.frameworkMappings.length)} />
        <Metric icon={<ShieldAlert size={18} />} label={copy.criticalHigh} value={`${critical}/${high}`} />
        <Metric icon={<ShieldCheck size={18} />} label={copy.coverageAvg} value={`${avgCoverage}%`} />
        <Metric icon={<Target size={18} />} label={copy.decisionScope} value={copy.enterprise} />
      </section>

      <section className="framework-layout">
        <article className="panel chart-card framework-main framework-workbench-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.title}</h2>
              <p>{copy.subtitle}</p>
            </div>
            <GitBranch size={18} />
          </div>
          <FrameworkMapping items={model.frameworkMappings} compact language={language} />
        </article>

        <article className="panel chart-card framework-matrix-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.matrixTitle}</h2>
              <p>{copy.matrixSubtitle}</p>
            </div>
            <GitBranch size={18} />
          </div>
          <FrameworkControlMatrix items={model.frameworkMappings} language={language} />
        </article>

        <article className="panel chart-card framework-rank-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.exposure}</h2>
              <p>{copy.exposureSubtitle}</p>
            </div>
          </div>
          <BarRanking items={exposureRank} language={language} />
        </article>

        <article className="panel chart-card framework-rank-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.alignment}</h2>
              <p>{copy.alignmentSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categories} language={language} />
        </article>
      </section>
    </div>
  );
}

function FrameworkControlMatrix({ items, language }: { items: FrameworkMappingItem[]; language: LanguageMode }) {
  const copy = labels[language];
  const cells = useMemo(() => buildMatrixCells(items), [items]);
  const [selectedCellId, setSelectedCellId] = useState<string | null>(null);
  const selectedCell = useMemo(() => {
    return cells.find((cell) => cell.id === selectedCellId) ?? cells.find((cell) => cell.score > 0) ?? cells[0];
  }, [cells, selectedCellId]);

  return (
    <div className="framework-control-matrix">
      <div className="framework-matrix-scroll" role="region" aria-label={copy.matrixTitle}>
        <div className="framework-matrix-grid" style={{ gridTemplateColumns: `174px repeat(${matrixAxes.length}, minmax(112px, 1fr))` }}>
          <div className="framework-matrix-corner">{copy.frameworks}</div>
          {matrixAxes.map((axis) => (
            <div className="framework-matrix-column" key={axis.id}>{copy.matrixAxes[axis.id]}</div>
          ))}
          {items.map((item) => (
            <div className="framework-matrix-row" key={item.name}>
              <div className="framework-matrix-row-head">
                <strong>{item.name}</strong>
                <span>{localizeFrameworkText(item.family, language)}</span>
              </div>
              {matrixAxes.map((axis) => {
                const cell = cells.find((value) => value.framework.name === item.name && value.axis.id === axis.id);
                if (!cell) return null;
                const controlPreview = localizeFrameworkList(cell.controls, language).slice(0, 2).join(" / ");
                return (
                  <button
                    type="button"
                    className={`framework-matrix-cell ${cell.tone} ${selectedCell?.id === cell.id ? "selected" : ""}`}
                    key={cell.id}
                    onClick={() => setSelectedCellId(cell.id)}
                    aria-label={`${item.name} ${copy.matrixAxes[axis.id]} ${cell.score}%`}
                  >
                    <span>{cell.score > 0 ? `${cell.score}%` : "·"}</span>
                    <em>{controlPreview || copy.noDirectMap}</em>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {selectedCell ? (
        <aside className={`framework-matrix-detail ${selectedCell.tone}`}>
          <div>
            <span>{copy.matrixDetail}</span>
            <h3>{selectedCell.framework.name}</h3>
            <p>
              {localizeFrameworkText(selectedCell.framework.family, language)} · {copy.matrixAxes[selectedCell.axis.id]}
            </p>
          </div>
          <div className="framework-matrix-score">
            <strong>{selectedCell.score}%</strong>
            <span>{copy.mappingIntensity}</span>
          </div>
          <div className="framework-matrix-detail-block framework-matrix-help">
            <strong>{copy.intensityTitle}</strong>
            <p>{copy.intensityHelp}</p>
          </div>
          <div className="framework-matrix-detail-block framework-matrix-reference">
            <strong>{copy.referenceBase}</strong>
            {selectedCell.framework.sourceUrl ? (
              <a href={selectedCell.framework.sourceUrl} target="_blank" rel="noreferrer">
                {selectedCell.framework.sourceLabel}
              </a>
            ) : (
              <p>{selectedCell.framework.sourceLabel}</p>
            )}
            <span>
              {copy.referenceDate}: {selectedCell.framework.sourceDate ?? copy.noDirectMap}
            </span>
            <em>{copy.verifiedAt}</em>
          </div>
          <div className="framework-matrix-detail-block">
            <strong>{copy.affectedSpecifics}</strong>
            <ul>
              {(selectedCell.controls.length ? localizeFrameworkList(selectedCell.controls, language) : [copy.noDirectMap]).map((value) => (
                <li key={value}>{value}</li>
              ))}
            </ul>
          </div>
          <div className="framework-matrix-detail-block">
            <strong>{copy.mappedEvidence}</strong>
            <ul>
              {(selectedCell.evidence.length ? localizeFrameworkList(selectedCell.evidence, language) : [copy.noDirectMap]).map((value) => (
                <li key={value}>{value}</li>
              ))}
            </ul>
          </div>
          <div className="framework-matrix-detail-block">
            <strong>{copy.decisionReading}</strong>
            <p>{selectedCell.score > 0 ? localizeFrameworkText(selectedCell.framework.analysisUse, language) : copy.noDirectMap}</p>
          </div>
        </aside>
      ) : null}
    </div>
  );
}

function buildMatrixCells(items: FrameworkMappingItem[]): MatrixCell[] {
  return items.flatMap((item) => matrixAxes.map((axis) => buildMatrixCell(item, axis)));
}

function buildMatrixCell(item: FrameworkMappingItem, axis: MatrixAxis): MatrixCell {
  const pools = {
    controls: uniqueText([...item.domains, ...item.affectedAspects, ...item.considerations]),
    evidence: uniqueText(item.evidenceFocus)
  };
  const corpus = normalizeText([
    item.name,
    item.family,
    item.analysisUse,
    item.decision,
    item.sourceLabel,
    ...pools.controls,
    ...pools.evidence
  ].join(" "));
  const keywordHits = axis.keywords.filter((keyword) => corpus.includes(keyword)).length;
  const controls = pools.controls.filter((value) => axis.keywords.some((keyword) => normalizeText(value).includes(keyword))).slice(0, 6);
  const evidence = pools.evidence.filter((value) => axis.keywords.some((keyword) => normalizeText(value).includes(keyword))).slice(0, 5);
  const baseScore = keywordHits * 18 + controls.length * 12 + evidence.length * 10;
  const exposureWeight = Math.round(item.exposure * 0.18);
  const score = keywordHits || controls.length || evidence.length ? Math.min(100, Math.max(12, baseScore + exposureWeight)) : 0;
  return {
    id: `${item.name}-${axis.id}`,
    framework: item,
    axis,
    score,
    controls,
    evidence,
    tone: score >= 72 ? "high" : score >= 42 ? "medium" : score > 0 ? "low" : "none"
  };
}

function uniqueText(values: string[]): string[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = normalizeText(value);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeText(value: string): string {
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/&/g, " and ");
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
