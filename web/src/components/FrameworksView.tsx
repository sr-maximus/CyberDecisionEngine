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
    frameworks: "Marcos de referencia",
    criticalHigh: "Validada / directa",
    coverageAvg: "Cruces con evidencia",
    decisionScope: "Lectura",
    enterprise: "organizacional",
    title: "Correspondencia entre marcos y evidencia",
    subtitle: "Lectura comparada de controles, exposición y aspectos afectados en los marcos disponibles",
    exposure: "Intensidad de registros por marco",
    exposureSubtitle: "Registros únicos relacionados con cada marco en la corrida actual",
    alignment: "Señales por ámbito de control",
    alignmentSubtitle: "Concentración de registros en las áreas que requieren revisión",
    matrixTitle: "Matriz de relación entre evidencia, controles y riesgos",
    matrixSubtitle: "Seleccione un cruce para revisar qué se relaciona, qué lo sustenta y qué decisión puede apoyar",
    matrixDetail: "Análisis del cruce seleccionado",
    mappingIntensity: "registros relacionados",
    intensityTitle: "Cómo leer la celda",
    intensityHelp:
      "El número es un conteo de registros únicos de esta corrida. No mide cumplimiento, madurez, eficacia de control ni probabilidad.",
    referenceBase: "Base oficial",
    referenceDate: "Fecha de referencia",
    verifiedAt: `Verificado con fuentes oficiales el ${FRAMEWORK_REFERENCES_VERIFIED_AT}`,
    affectedSpecifics: "Qué afecta",
    mappedEvidence: "Evidencia relacionada",
    validatedEvidence: "Validada / directa / por revisar",
    decisionReading: "Lectura de decisión",
    noDirectMap: "Sin relación directa en los datos actuales",
    matrixAxes: {
      governance: "Gobierno y riesgo",
      identity: "Identidad y acceso",
      protect: "Protección",
      detect: "Detección y monitoreo",
      response: "Respuesta y recuperación",
      privacy: "Datos y privacidad",
      vulnerability: "Gestión de vulnerabilidades",
      fraud: "Fraude y marca",
      ai: "Abuso de IA",
      adversary: "Comportamiento adversario"
    },
    matrixAxisHelp: {
      governance: "Dirección, contexto y propiedad",
      identity: "Cuentas, acceso y privilegios",
      protect: "Salvaguardas y endurecimiento",
      detect: "Visibilidad, registros y alertas",
      response: "Contención, continuidad y recuperación",
      privacy: "Datos personales y confidencialidad",
      vulnerability: "CVE, parches y exposición",
      fraud: "Suplantación, phishing y confianza",
      ai: "Modelos, agentes y prompts",
      adversary: "Tácticas, técnicas y comportamiento"
    }
  },
  en: {
    frameworks: "Reference frameworks",
    criticalHigh: "Validated / direct",
    coverageAvg: "Evidence crosswalks",
    decisionScope: "Reading",
    enterprise: "organizational",
    title: "Framework-to-evidence correspondence",
    subtitle: "Comparative reading of controls, exposure and affected aspects across available frameworks",
    exposure: "Record intensity by framework",
    exposureSubtitle: "Unique records related to each framework in the current run",
    alignment: "Signals by control domain",
    alignmentSubtitle: "Record concentration across areas requiring review",
    matrixTitle: "Evidence, control and risk relationship matrix",
    matrixSubtitle: "Select a crosswalk to inspect the relationship, its support and the decision it may inform",
    matrixDetail: "Selected crosswalk analysis",
    mappingIntensity: "related records",
    intensityTitle: "How to read the cell",
    intensityHelp:
      "The number is a unique current-run record count. It does not measure compliance, maturity, control effectiveness or probability.",
    referenceBase: "Official base",
    referenceDate: "Reference date",
    verifiedAt: `Verified against official sources on ${FRAMEWORK_REFERENCES_VERIFIED_AT}`,
    affectedSpecifics: "Affected specifics",
    mappedEvidence: "Related evidence",
    validatedEvidence: "Validated / direct / under review",
    decisionReading: "Decision reading",
    noDirectMap: "No direct relation in current data",
    matrixAxes: {
      governance: "Governance and risk",
      identity: "Identity and access",
      protect: "Protection",
      detect: "Detection and monitoring",
      response: "Response and recovery",
      privacy: "Data and privacy",
      vulnerability: "Vulnerability management",
      fraud: "Fraud and brand",
      ai: "AI abuse",
      adversary: "Adversary behavior"
    },
    matrixAxisHelp: {
      governance: "Direction, context and ownership",
      identity: "Accounts, access and privileges",
      protect: "Safeguards and hardening",
      detect: "Visibility, logging and alerts",
      response: "Containment, continuity and recovery",
      privacy: "Personal data and confidentiality",
      vulnerability: "CVEs, patching and exposure",
      fraud: "Impersonation, phishing and trust",
      ai: "Models, agents and prompts",
      adversary: "Tactics, techniques and behavior"
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
  recordCount: number;
  validatedCount: number;
  directCount: number;
  relatedCount: number;
  controls: string[];
  evidence: FrameworkMappingItem["axisMappings"][number]["evidence"];
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
  const validated = model.frameworkMappings.reduce((sum, item) => sum + item.validatedCount, 0);
  const direct = model.frameworkMappings.reduce((sum, item) => sum + item.directCount, 0);
  const mappedCells = model.frameworkMappings.reduce((sum, item) => sum + item.axisMappings.length, 0);
  const exposureRank = model.frameworkMappings.map((item) => ({ name: item.name, value: item.exposure, tone: item.tone }));

  return (
    <div className="view-stack">
      <section className="dashboard-kpis">
        <Metric icon={<GitBranch size={18} />} label={copy.frameworks} value={String(model.frameworkMappings.length)} />
        <Metric icon={<ShieldAlert size={18} />} label={copy.criticalHigh} value={`${validated}/${direct}`} />
        <Metric icon={<ShieldCheck size={18} />} label={copy.coverageAvg} value={String(mappedCells)} />
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
    return cells.find((cell) => cell.id === selectedCellId) ?? cells.find((cell) => cell.recordCount > 0) ?? cells[0];
  }, [cells, selectedCellId]);

  return (
    <div className="framework-control-matrix">
      <div className="framework-matrix-scroll" role="region" aria-label={copy.matrixTitle}>
        <div className="framework-matrix-grid" style={{ gridTemplateColumns: `184px repeat(${matrixAxes.length}, minmax(138px, 1fr))` }}>
          <div className="framework-matrix-corner">{copy.frameworks}</div>
          {matrixAxes.map((axis) => (
            <div className="framework-matrix-column" key={axis.id}>
              <strong>{copy.matrixAxes[axis.id]}</strong>
              <span>{copy.matrixAxisHelp[axis.id]}</span>
            </div>
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
                    aria-label={`${item.name} ${copy.matrixAxes[axis.id]} ${cell.recordCount} ${copy.mappingIntensity}`}
                  >
                    <span>{cell.recordCount > 0 ? cell.recordCount : "·"}</span>
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
            <strong>{selectedCell.recordCount}</strong>
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
            <p>{copy.validatedEvidence}: {selectedCell.validatedCount} / {selectedCell.directCount} / {selectedCell.relatedCount}</p>
            <ul className="framework-evidence-links">
              {selectedCell.evidence.length ? selectedCell.evidence.map((value) => (
                <li key={value.evidenceId}>
                  {value.url ? <a href={value.url} target="_blank" rel="noreferrer">{value.title}</a> : value.title}
                  <small>{value.domain || value.source} · {value.status} · {value.relationship}</small>
                </li>
              )) : <li>{copy.noDirectMap}</li>}
            </ul>
          </div>
          <div className="framework-matrix-detail-block">
            <strong>{copy.decisionReading}</strong>
            <p>{selectedCell.recordCount > 0 ? localizeFrameworkText(selectedCell.framework.analysisUse, language) : copy.noDirectMap}</p>
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
  const mapping = item.axisMappings.find((value) => value.axis === axis.id);
  const recordCount = mapping?.recordCount ?? 0;
  const validatedCount = mapping?.validatedCount ?? 0;
  const directCount = mapping?.directCount ?? 0;
  const relatedCount = mapping?.relatedCount ?? 0;
  return {
    id: `${item.name}-${axis.id}`,
    framework: item,
    axis,
    recordCount,
    validatedCount,
    directCount,
    relatedCount,
    controls: mapping?.controls ?? [],
    evidence: mapping?.evidence ?? [],
    tone: validatedCount > 0 ? "high" : directCount > 0 ? "medium" : recordCount > 0 ? "low" : "none"
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
