import { ExternalLink, ShieldAlert } from "lucide-react";
import type { Finding, LanguageMode } from "../types";
import { formatRisk, riskTone } from "../utils/format";

interface FindingsTableProps {
  findings: Finding[];
  language: LanguageMode;
}

const labels = {
  es: {
    title: "Hallazgos principales",
    subtitle: "resultados priorizados",
    finding: "Hallazgo",
    category: "Categoria",
    residual: "Residual",
    matrix: "Matriz",
    owner: "Responsable",
    evidence: "Evidencia",
    recommendation: "Accion sugerida",
    source: "Fuente",
    empty: "Sin hallazgos cargados"
  },
  en: {
    title: "Top findings",
    subtitle: "prioritized results",
    finding: "Finding",
    category: "Category",
    residual: "Residual",
    matrix: "Matrix",
    owner: "Owner",
    evidence: "Evidence",
    recommendation: "Suggested action",
    source: "Source",
    empty: "No findings loaded"
  }
};

export function FindingsTable({ findings, language }: FindingsTableProps) {
  const copy = labels[language];
  const rows = findings.slice(0, 12);
  return (
    <section className="panel table-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{rows.length} {copy.subtitle}</p>
        </div>
      </div>

      {rows.length ? (
        <div className="finding-card-grid">
          {rows.map((finding) => {
            const tone = riskTone(finding.residual_risk);
            const evidence = finding.evidence?.[0];
            return (
              <article className={`finding-card ${tone}`} key={`${finding.title}-${finding.category}`}>
                <div className="finding-card-head">
                  <span className="finding-card-icon"><ShieldAlert size={18} /></span>
                  <strong>{finding.title}</strong>
                  <span className={`risk-badge ${tone}`}>{formatRisk(finding.residual_risk)}</span>
                </div>
                <dl className="finding-card-meta">
                  <div><dt>{copy.category}</dt><dd>{categoryLabel(finding.category, language)}</dd></div>
                  <div><dt>{copy.matrix}</dt><dd>{finding.matrix_label}</dd></div>
                  <div><dt>{copy.owner}</dt><dd>{finding.owner}</dd></div>
                </dl>
                {finding.recommendations?.[0] ? (
                  <p className="finding-card-action"><b>{copy.recommendation}:</b> {finding.recommendations[0]}</p>
                ) : null}
                <div className="finding-card-evidence">
                  <span>{copy.evidence}</span>
                  {evidence?.startsWith("http") ? (
                    <a href={evidence} target="_blank" rel="noreferrer" title={evidence}>
                      <ExternalLink size={15} />
                      <span>{copy.source}</span>
                    </a>
                  ) : (
                    <p>{evidence ?? copy.source}</p>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      ) : <div className="chart-empty">{copy.empty}</div>}
    </section>
  );
}

function categoryLabel(value: string, language: LanguageMode): string {
  const key = value.trim().toLowerCase();
  const names: Record<string, [string, string]> = {
    attack_surface: ["Superficie de ataque", "Attack surface"],
    vulnerability: ["Vulnerabilidades", "Vulnerabilities"],
    brand_reputation: ["Marca y reputacion", "Brand and reputation"],
    fraud: ["Fraude", "Fraud"],
    dark_web: ["Dark web", "Dark web"],
    socmint: ["Inteligencia SOCMINT", "SOCMINT intelligence"],
    disinformation: ["Desinformacion", "Disinformation"]
  };
  return names[key]?.[language === "es" ? 0 : 1] ?? value.replace(/_/g, " ");
}
