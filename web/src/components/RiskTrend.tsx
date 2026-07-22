import type { DomainSignal, LanguageMode } from "../types";
import { formatDateTime, formatRisk, riskTone } from "../utils/format";

interface RiskTrendProps {
  signals: DomainSignal[];
  language: LanguageMode;
}

const labels = {
  es: {
    noDomain: "Sin dominio",
    title: "Intensidad de senales por dominio",
    subtitle: "Riesgo residual, eventos y ultima observacion",
    events: "eventos"
  },
  en: {
    noDomain: "No domain",
    title: "Domain signal intensity",
    subtitle: "Residual risk, collected records and latest observation",
    events: "records"
  }
};

export function RiskTrend({ signals, language }: RiskTrendProps) {
  const copy = labels[language];
  const rows = signals.length ? signals : [{ domain: copy.noDomain, events: 0, findings: 0, max_residual_risk: 0 }];
  const max = Math.max(...rows.map((row) => row.max_residual_risk ?? 0), 1);
  return (
    <section className="panel risk-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
      </div>

      <div className="bar-list">
        {rows.map((row) => {
          const hasRisk = row.max_residual_risk != null;
          const risk = row.max_residual_risk ?? 0;
          const width = hasRisk ? Math.max(6, (risk / max) * 100) : 0;
          const tone = riskTone(risk);
          return (
            <div className="bar-row" key={row.domain}>
              <div className="bar-meta">
                <strong>{row.domain}</strong>
                <span>{row.events} {copy.events}</span>
              </div>
              <div className="bar-track">
                <span className={`bar-fill ${tone}`} style={{ width: `${width}%` }} />
              </div>
              <div className="bar-score">
                <strong>{hasRisk ? formatRisk(risk) : "N/D"}</strong>
                <span>{formatDateTime(row.last_seen)}</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
