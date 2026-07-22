import { Database, Gauge, RadioTower, ShieldAlert } from "lucide-react";
import type { KpiSummary, LanguageMode } from "../types";
import { formatNumber, formatRisk } from "../utils/format";

interface KpiStripProps {
  kpis: KpiSummary;
  language: LanguageMode;
  findingCount?: number;
}

const emptyKpis: KpiSummary = {
  active_domains: 0,
  new_events: 0,
  max_residual_risk: 0,
    avg_residual_risk: 0,
    healthy_sources: 0,
    total_sources: 0,
    queried_sources: 0,
    productive_sources: 0,
    registered_sources: 0
};

const labels = {
  es: {
    domains: "Dominios",
    events: "Registros recolectados",
    records: "Registros únicos",
    residualRisk: "Riesgo residual",
    findings: "Hallazgos priorizados"
  },
  en: {
    domains: "Domains",
    events: "Events",
    records: "Unique records",
    residualRisk: "Residual risk",
    findings: "Prioritized findings"
  }
};

export function KpiStrip({ kpis = emptyKpis, language, findingCount = 0 }: KpiStripProps) {
  const copy = labels[language];
  return (
    <section className="kpi-strip">
      <div className="kpi">
        <Database size={19} />
        <span>{copy.domains}</span>
        <strong>{formatNumber(kpis.active_domains)}</strong>
      </div>
      <div className="kpi">
        <RadioTower size={19} />
        <span>{copy.records}</span>
        <strong>{formatNumber(kpis.unique_records ?? kpis.new_events)}</strong>
      </div>
      <div className="kpi">
        <Gauge size={19} />
        <span>{copy.residualRisk}</span>
        <strong>{kpis.max_residual_risk == null ? "N/D" : formatRisk(kpis.max_residual_risk)}</strong>
      </div>
      <div className="kpi">
        <ShieldAlert size={19} />
        <span>{copy.findings}</span>
        <strong>{formatNumber(findingCount)}</strong>
      </div>
    </section>
  );
}
