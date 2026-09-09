import { Check, Filter, RotateCcw } from "lucide-react";
import type { AnalysisDomain, LanguageMode, TechnologyDomain } from "../types";
import {
  analysisDomainOptions,
  defaultIntelligenceFilters,
  technologyDomainOptions,
  type IntelligenceFilters
} from "../utils/intelligenceProjection";

interface IntelligenceDomainFilterProps {
  filters: IntelligenceFilters;
  language: LanguageMode;
  onChange: (filters: IntelligenceFilters) => void;
}

const technologyLabels: Record<TechnologyDomain, string> = {
  it: "IT",
  iot: "IoT",
  iiot: "IIoT",
  ot: "OT",
  unknown: "Sin clasificar"
};

const analysisLabels: Record<AnalysisDomain, { es: string; en: string }> = {
  cyber: { es: "Cyber", en: "Cyber" },
  fraud: { es: "Fraude", en: "Fraud" },
  brand: { es: "Marca", en: "Brand" },
  disinformation: { es: "Desinformación", en: "Disinformation" },
  ai_security: { es: "Seguridad de IA", en: "AI security" }
};

function toggle<T extends string>(current: T[], value: T, all: T[]): T[] {
  if (current.includes(value)) {
    const next = current.filter((item) => item !== value);
    return next.length ? next : [value];
  }
  const next = [...current, value];
  return all.filter((item) => next.includes(item));
}

export function IntelligenceDomainFilter({ filters, language, onChange }: IntelligenceDomainFilterProps) {
  const allSelected = filters.technologyDomains.length === technologyDomainOptions.length
    && filters.analysisDomains.length === analysisDomainOptions.length;
  return (
    <section className="intelligence-filter panel" aria-label={language === "es" ? "Filtros globales de inteligencia" : "Global intelligence filters"}>
      <div className="intelligence-filter-heading">
        <Filter size={17} aria-hidden="true" />
        <div>
          <strong>{language === "es" ? "Perspectiva de inteligencia" : "Intelligence perspective"}</strong>
          <span>{language === "es" ? "Proyección compartida; la corrida original no se modifica." : "Shared projection; the original run remains unchanged."}</span>
        </div>
      </div>
      <fieldset>
        <legend>{language === "es" ? "Dominio tecnológico" : "Technology domain"}</legend>
        <div className="filter-segments">
          <button
            type="button"
            className={filters.technologyDomains.length === technologyDomainOptions.length ? "active" : ""}
            aria-pressed={filters.technologyDomains.length === technologyDomainOptions.length}
            onClick={() => onChange({ ...filters, technologyDomains: [...technologyDomainOptions] })}
          >
            {filters.technologyDomains.length === technologyDomainOptions.length ? <Check size={13} /> : null}
            {language === "es" ? "Todos" : "All"}
          </button>
          {technologyDomainOptions.map((domain) => (
            <button
              key={domain}
              type="button"
              className={filters.technologyDomains.includes(domain) ? "active" : ""}
              aria-pressed={filters.technologyDomains.includes(domain)}
              onClick={() => onChange({ ...filters, technologyDomains: toggle(filters.technologyDomains, domain, technologyDomainOptions) })}
            >
              {filters.technologyDomains.includes(domain) ? <Check size={13} /> : null}
              {domain === "unknown" && language === "en" ? "Unclassified" : technologyLabels[domain]}
            </button>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>{language === "es" ? "Dimensión analítica" : "Analysis dimension"}</legend>
        <div className="filter-segments">
          <button
            type="button"
            className={filters.analysisDomains.length === analysisDomainOptions.length ? "active" : ""}
            aria-pressed={filters.analysisDomains.length === analysisDomainOptions.length}
            onClick={() => onChange({ ...filters, analysisDomains: [...analysisDomainOptions] })}
          >
            {filters.analysisDomains.length === analysisDomainOptions.length ? <Check size={13} /> : null}
            {language === "es" ? "Todos" : "All"}
          </button>
          {analysisDomainOptions.map((domain) => (
            <button
              key={domain}
              type="button"
              className={filters.analysisDomains.includes(domain) ? "active" : ""}
              aria-pressed={filters.analysisDomains.includes(domain)}
              onClick={() => onChange({ ...filters, analysisDomains: toggle(filters.analysisDomains, domain, analysisDomainOptions) })}
            >
              {filters.analysisDomains.includes(domain) ? <Check size={13} /> : null}
              {analysisLabels[domain][language]}
            </button>
          ))}
        </div>
      </fieldset>
      <button
        className="icon-button filter-reset"
        type="button"
        title={language === "es" ? "Restablecer filtros" : "Reset filters"}
        aria-label={language === "es" ? "Restablecer filtros" : "Reset filters"}
        disabled={allSelected}
        onClick={() => onChange(defaultIntelligenceFilters)}
      >
        <RotateCcw size={16} />
      </button>
    </section>
  );
}
