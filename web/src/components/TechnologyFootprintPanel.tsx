import { Box, Cpu, Factory, RadioTower, Server, ShieldCheck } from "lucide-react";
import type { LanguageMode, MultidomainIntelligence, TechnologyDomain } from "../types";
import { formatNumber } from "../utils/format";

interface TechnologyFootprintPanelProps {
  intelligence?: MultidomainIntelligence;
  language: LanguageMode;
  compact?: boolean;
}

const domainMeta: Record<TechnologyDomain, { label: string; className: string; icon: typeof Server }> = {
  it: { label: "IT", className: "domain-it", icon: Server },
  iot: { label: "IoT", className: "domain-iot", icon: RadioTower },
  iiot: { label: "IIoT", className: "domain-iiot", icon: Cpu },
  ot: { label: "OT", className: "domain-ot", icon: Factory },
  unknown: { label: "N/D", className: "domain-unknown", icon: Box }
};

export function TechnologyFootprintPanel({ intelligence, language, compact = false }: TechnologyFootprintPanelProps) {
  const footprint = intelligence?.technology_footprint;
  const rows = footprint?.rows ?? [];
  const total = Math.max(1, footprint?.total_records ?? 0);
  if (!footprint || footprint.status === "no_data" || !footprint.total_records) {
    return (
      <section className="panel technology-footprint-panel">
        <div className="technology-footprint-header">
          <div>
            <span>{language === "es" ? "HUELLA TECNOLÓGICA PÚBLICA" : "PUBLIC TECHNOLOGY FOOTPRINT"}</span>
            <h2>{language === "es" ? "Sin elementos tecnológicos atribuibles" : "No attributable technology elements"}</h2>
            <p>{language === "es" ? "La cobertura actual no permite clasificar elementos como IT, IoT, IIoT u OT." : "Current coverage does not support classifying elements as IT, IoT, IIoT, or OT."}</p>
          </div>
        </div>
      </section>
    );
  }
  return (
    <section className={`panel technology-footprint-panel${compact ? " compact" : ""}`}>
      <div className="technology-footprint-header">
        <div>
          <span>{language === "es" ? "HUELLA TECNOLÓGICA PÚBLICA" : "PUBLIC TECHNOLOGY FOOTPRINT"}</span>
          <h2>{language === "es" ? "Superficie tecnológica multidominio" : "Multidomain technology surface"}</h2>
          <p>{language === "es" ? "Elementos observados externamente, separados por contexto tecnológico y nivel de atribución." : "Externally observed elements, separated by technology context and attribution level."}</p>
        </div>
        <div className="footprint-assurance">
          <ShieldCheck size={22} />
          <strong>{formatNumber(footprint.attributed_records)}</strong>
          <span>{language === "es" ? "atribuidos" : "attributed"}</span>
        </div>
      </div>
      <div className="technology-domain-strip" role="img" aria-label={language === "es" ? "Distribución por dominio tecnológico" : "Technology domain distribution"}>
        {rows.map((row) => (
          <span key={row.domain} className={domainMeta[row.domain].className} style={{ flexGrow: Math.max(1, row.records) }} title={`${domainMeta[row.domain].label}: ${row.records}`} />
        ))}
      </div>
      <div className="technology-domain-grid">
        {rows.map((row) => {
          const meta = domainMeta[row.domain];
          const Icon = meta.icon;
          return (
            <article key={row.domain} className={`technology-domain-row ${meta.className}`}>
              <div className="technology-domain-icon"><Icon size={18} /></div>
              <div className="technology-domain-main">
                <div><strong>{meta.label}</strong><em>{Math.round((row.records / total) * 100)}%</em></div>
                <span>{formatNumber(row.records)} {language === "es" ? "registros" : "records"} · {formatNumber(row.assured_records)} {language === "es" ? "sustentados" : "supported"}</span>
                {!compact ? <small>{[...row.products, ...row.protocols, ...row.vendors].slice(0, 5).join(" · ") || (language === "es" ? "Sin producto o protocolo corroborado" : "No corroborated product or protocol")}</small> : null}
              </div>
            </article>
          );
        })}
      </div>
      <p className="technology-footprint-disclaimer">{language === "es" ? intelligence?.disclaimer_es : intelligence?.disclaimer_en}</p>
    </section>
  );
}
