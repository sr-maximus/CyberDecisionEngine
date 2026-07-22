import { ExternalLink } from "lucide-react";
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

      <div className="table-wrap">
        <table>
          <colgroup>
            <col className="col-finding" />
            <col className="col-category" />
            <col className="col-residual" />
            <col className="col-matrix" />
            <col className="col-owner" />
            <col className="col-evidence" />
          </colgroup>
          <thead>
            <tr>
              <th>{copy.finding}</th>
              <th>{copy.category}</th>
              <th>{copy.residual}</th>
              <th>{copy.matrix}</th>
              <th>{copy.owner}</th>
              <th>{copy.evidence}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length ? (
              rows.map((finding) => {
                const tone = riskTone(finding.residual_risk);
                const evidence = finding.evidence?.[0];
                return (
                  <tr key={`${finding.title}-${finding.category}`}>
                    <td>
                      <strong className="finding-title">{finding.title}</strong>
                    </td>
                    <td>{finding.category}</td>
                    <td>
                      <span className={`risk-badge ${tone}`}>{formatRisk(finding.residual_risk)}</span>
                    </td>
                    <td>{finding.matrix_label}</td>
                    <td>{finding.owner}</td>
                    <td>
                      {evidence?.startsWith("http") ? (
                        <a className="table-link" href={evidence} target="_blank" rel="noreferrer">
                          <ExternalLink size={15} />
                          <span>{copy.source}</span>
                        </a>
                      ) : (
                        <span className="evidence-text" title={evidence ?? copy.source}>{evidence ?? copy.source}</span>
                      )}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={6} className="empty-cell">
                  {copy.empty}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
