import { AlertTriangle, Bot, CalendarX2, CheckCircle2, Clock3, Globe2, Loader2, Network, Save, ScanSearch, ShieldAlert, X } from "lucide-react";
import { ANALYSIS_WINDOWS, analysisWindowConfig } from "../data/analysisWindows";
import { localizedCountryLabel, localizedSectorLabel } from "../data/catalog";
import type { AnalysisMode, AnalysisWindow, LanguageMode } from "../types";

export interface DomainComposerProps {
  rawDomains: string;
  rawCompetitorDomains: string;
  organizationName: string;
  domains: string[];
  competitorDomains: string[];
  selectedSectors: string[];
  selectedCountries: string[];
  sectorOptions: string[];
  countryOptions: string[];
  language: LanguageMode;
  mode: AnalysisMode;
  analysisWindow: AnalysisWindow;
  scanTimeBudgetMinutes: number;
  reportDisplayAt: string;
  canOverrideReportDate: boolean;
  realOnly: boolean;
  authorizedScope: boolean;
  allowTor: boolean;
  isRunning: boolean;
  onRawDomainsChange: (value: string) => void;
  onRawCompetitorDomainsChange: (value: string) => void;
  onOrganizationNameChange: (value: string) => void;
  onSectorsChange: (value: string[]) => void;
  onCountriesChange: (value: string[]) => void;
  onModeChange: (value: AnalysisMode) => void;
  onAnalysisWindowChange: (value: AnalysisWindow) => void;
  onScanTimeBudgetChange: (value: number) => void;
  onReportDisplayAtChange: (value: string) => void;
  onRealOnlyChange: (value: boolean) => void;
  onAuthorizedScopeChange: (value: boolean) => void;
  onAllowTorChange: (value: boolean) => void;
  onRemoveDomain: (value: string) => void;
  onRun: () => void;
  onAssistedRun: () => void;
  canSaveDefaults?: boolean;
  onSaveDefaults?: () => void;
  defaultScopeMessage?: string | null;
  reusableScopeName?: string | null;
}

const copy = {
  es: {
    title: "Configurar y ejecutar análisis",
    targets: "objetivos definidos",
    run: "Ejecutar análisis",
    assistedRun: "Búsqueda profunda segura",
    assistedHint: "Activa modo profundo, TOR autorizado y colectores permitidos. Respeta límites, caché, backoff y fuentes públicas/autorizadas.",
    assistedConfirm:
      "Se ejecutará una búsqueda profunda segura con fuentes públicas/autorizadas, backoff, caché y TOR contenerizado cuando aplique. No se habilita evasión de bloqueos, captchas ni controles. ¿Continuar?",
    running: "Ejecutando",
    organization: "Marca, grupo o conglomerado",
    organizationPlaceholder: "Organizacion, marca o holding",
    domains: "Dominios autorizados",
    domainsHint: "Opcional para una organización; necesario para analizar superficie externa.",
    competitors: "Dominios de competencia para benchmark",
    competitorsPlaceholder: "competidor.com, rival.com",
    sectors: "Sector(es) económico(s)",
    countries: "País(es) objetivo",
    mode: "Modo de análisis",
    snapshot: "Snapshot",
    deep: "Profundo",
    lookback: "Rango de análisis",
    scanBudget: "Tiempo máximo de corrida",
    scanBudgetHint: "El backend sigue trabajando aunque cierres sesión; este valor ajusta profundidad y timeouts.",
    reportDate: "Fecha/hora oficial del informe",
    reportDateHint: "Solo superadmin. Si queda vacía, el informe usa la fecha actual del backend.",
    reportDatePlaceholder: "Fecha actual del sistema",
    clearReportDate: "Usar fecha actual",
    authorized: "Alcance autorizado",
    realOnly: "Solo datos reales",
    torSearch: "TOR seguro",
    torHint: "Proxy TOR contenerizado para busqueda profunda autorizada",
    saveDefault: "Guardar default",
    noCountry: "Todos los países",
    noSector: "Todos los sectores",
    missingScopeTitle: "Falta alcance de análisis",
    missingScope: "Ingresa al menos una organización o dominio autorizado. Sin alcance no se lanza recolección ni análisis.",
    missingGroupTitle: "Falta identificar el grupo",
    missingGroup: "Para varios dominios indica la marca, grupo o conglomerado. Así PESTEL, Porter, escenarios e informe comparten el mismo contexto.",
    reusableProfile: "Se recuperará el perfil declarado de este alcance exacto. La evidencia y los enlaces se recolectarán de nuevo para esta corrida."
  },
  en: {
    title: "Configure and run analysis",
    targets: "defined targets",
    run: "Run analysis",
    assistedRun: "Safe deep search",
    assistedHint: "Enables deep mode, authorized TOR and allowlisted collectors with limits, cache, backoff and public/authorized sources.",
    assistedConfirm:
      "A safe deep search will run with public/authorized sources, backoff, cache and containerized TOR when applicable. Block/captcha/control evasion is not enabled. Continue?",
    running: "Running",
    organization: "Brand, group or conglomerate",
    organizationPlaceholder: "Organization, brand or holding name",
    domains: "Authorized domains",
    domainsHint: "Optional for an organization; required for external-surface analysis.",
    competitors: "Competitor domains for benchmark",
    competitorsPlaceholder: "competitor.com, rival.com",
    sectors: "Economic sector(s)",
    countries: "Target country/countries",
    mode: "Analysis mode",
    snapshot: "Snapshot",
    deep: "Deep",
    lookback: "Analysis range",
    scanBudget: "Run time limit",
    scanBudgetHint: "The backend keeps working if the session closes; this tunes depth and timeouts.",
    reportDate: "Official report date/time",
    reportDateHint: "Superadmin only. If empty, the report uses the current backend date.",
    reportDatePlaceholder: "Current system date",
    clearReportDate: "Use current date",
    authorized: "Authorized scope",
    realOnly: "Real-only data",
    torSearch: "Safe TOR",
    torHint: "Containerized TOR proxy for authorized deep lookup",
    saveDefault: "Save default",
    noCountry: "All countries",
    noSector: "All sectors",
    missingScopeTitle: "Analysis scope missing",
    missingScope: "Enter at least one organization or authorized domain. Without scope, collection and analysis do not start.",
    missingGroupTitle: "Group identity missing",
    missingGroup: "For multiple domains, enter the brand, group or conglomerate so PESTEL, Porter, scenarios and reports share one context.",
    reusableProfile: "The declared profile for this exact scope will be restored. Evidence and links will be collected again for this run."
  }
};

export function DomainComposer({
  rawDomains,
  rawCompetitorDomains,
  organizationName,
  domains,
  competitorDomains,
  selectedSectors,
  selectedCountries,
  sectorOptions,
  countryOptions,
  language,
  mode,
  analysisWindow,
  scanTimeBudgetMinutes,
  reportDisplayAt,
  canOverrideReportDate,
  realOnly,
  authorizedScope,
  allowTor,
  isRunning,
  onRawDomainsChange,
  onRawCompetitorDomainsChange,
  onOrganizationNameChange,
  onSectorsChange,
  onCountriesChange,
  onModeChange,
  onAnalysisWindowChange,
  onScanTimeBudgetChange,
  onReportDisplayAtChange,
  onRealOnlyChange,
  onAuthorizedScopeChange,
  onAllowTorChange,
  onRemoveDomain,
  onRun,
  onAssistedRun,
  canSaveDefaults,
  onSaveDefaults,
  defaultScopeMessage,
  reusableScopeName
}: DomainComposerProps) {
  const labels = copy[language];
  const currentWindow = analysisWindowConfig(analysisWindow);
  const needsOrganizationName = domains.length > 1 && organizationName.trim().length === 0 && !reusableScopeName;
  const hasRunnableScope = (domains.length > 0 || organizationName.trim().length > 0) && !needsOrganizationName;
  const targetCount = domains.length + (organizationName.trim() ? 1 : 0);
  const scanBudgetOptions = [
    { value: 0, label: "Auto" },
    { value: 10, label: "10 min" },
    { value: 30, label: "30 min" },
    { value: 60, label: "60 min" },
    { value: 120, label: "120 min" }
  ];
  return (
    <section className="domain-panel panel">
      <div className="panel-title-row">
        <div>
          <h2>{labels.title}</h2>
          <p>{targetCount} {labels.targets}</p>
        </div>
        <div className="domain-action-stack">
          <button className="primary-button" disabled={isRunning || !hasRunnableScope} onClick={onRun}>
            {isRunning ? <Loader2 className="spin" size={18} /> : <ScanSearch size={18} />}
            <span>{isRunning ? labels.running : labels.run}</span>
          </button>
          <button
            className="secondary-button assisted-search-button"
            disabled={isRunning || !hasRunnableScope}
            onClick={() => {
              if (window.confirm(labels.assistedConfirm)) onAssistedRun();
            }}
            type="button"
            title={labels.assistedHint}
          >
            <Bot size={17} />
            <span>{labels.assistedRun}</span>
          </button>
        </div>
      </div>
      <div className="guided-alert compact safe-search-alert">
        <AlertTriangle size={17} />
        <div>
          <strong>{labels.assistedRun}</strong>
          <p>{labels.assistedHint}</p>
        </div>
      </div>

      <label className="field-control domain-scope-field">
        <span><Globe2 size={16} /> {labels.domains}</span>
        <textarea
          className="domain-input"
          value={rawDomains}
          onChange={(event) => onRawDomainsChange(event.target.value)}
          placeholder="example.com, api.example.com"
          rows={3}
        />
        <small>{labels.domainsHint}</small>
      </label>
      {!hasRunnableScope ? (
        <div className="guided-alert compact scope-alert">
          <AlertTriangle size={17} />
          <div>
            <strong>{needsOrganizationName ? labels.missingGroupTitle : labels.missingScopeTitle}</strong>
            <p>{needsOrganizationName ? labels.missingGroup : labels.missingScope}</p>
          </div>
        </div>
      ) : null}
      {reusableScopeName && !organizationName.trim() ? (
        <div className="guided-alert compact scope-profile-alert">
          <CheckCircle2 size={17} />
          <div>
            <strong>{reusableScopeName}</strong>
            <p>{labels.reusableProfile}</p>
          </div>
        </div>
      ) : null}

      <label className="field-control">
        <span>{labels.organization}</span>
        <input
          value={organizationName}
          onChange={(event) => onOrganizationNameChange(event.target.value)}
          placeholder={labels.organizationPlaceholder}
        />
      </label>

      <div className="scope-select-grid">
        <label className="field-control">
          <span>{labels.sectors}</span>
          <select
            multiple
            value={selectedSectors}
            onChange={(event) => onSectorsChange(Array.from(event.currentTarget.selectedOptions).map((option) => option.value))}
          >
            {sectorOptions.map((sector) => (
              <option key={sector} value={sector}>
                {localizedSectorLabel(sector, language)}
              </option>
            ))}
          </select>
        </label>
        <label className="field-control">
          <span>{labels.countries}</span>
          <select
            multiple
            value={selectedCountries}
            onChange={(event) => onCountriesChange(Array.from(event.currentTarget.selectedOptions).map((option) => option.value))}
          >
            {countryOptions.map((country) => (
              <option key={country} value={country}>
                {localizedCountryLabel(country, language)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <label className="field-control">
        <span>{labels.competitors}</span>
        <textarea
          className="domain-input compact"
          value={rawCompetitorDomains}
          onChange={(event) => onRawCompetitorDomainsChange(event.target.value)}
          placeholder={labels.competitorsPlaceholder}
          rows={2}
        />
      </label>

      <div className="chip-row" aria-label="Normalized domains">
        {domains.map((domain) => (
          <span className="domain-chip" key={domain}>
            {domain}
            <button onClick={() => onRemoveDomain(domain)} aria-label={`Remove ${domain}`}>
              <X size={14} />
            </button>
          </span>
        ))}
        {competitorDomains.map((domain) => (
          <span className="domain-chip competitor" key={`competitor-${domain}`}>
            {domain}
          </span>
        ))}
      </div>

      <div className="control-grid">
        <div className="segmented" aria-label={labels.mode}>
          <button className={mode === "snapshot" ? "selected" : ""} onClick={() => onModeChange("snapshot")}>
            {labels.snapshot}
          </button>
          <button className={mode === "deep" ? "selected" : ""} onClick={() => onModeChange("deep")}>
            {labels.deep}
          </button>
        </div>

        <label className="window-control">
          <Clock3 size={18} />
          <span>{labels.lookback}</span>
          <select value={analysisWindow} onChange={(event) => onAnalysisWindowChange(event.target.value as AnalysisWindow)}>
            {ANALYSIS_WINDOWS.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label[language]}
              </option>
            ))}
          </select>
          <small>{currentWindow.description[language]}</small>
        </label>

        <label className="window-control scan-budget-control">
          <Clock3 size={18} />
          <span>{labels.scanBudget}</span>
          <select value={scanTimeBudgetMinutes} onChange={(event) => onScanTimeBudgetChange(Number(event.target.value))}>
            {scanBudgetOptions.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
          <small>{labels.scanBudgetHint}</small>
        </label>

        <label className="toggle">
          <input
            type="checkbox"
            checked={authorizedScope}
            onChange={(event) => onAuthorizedScopeChange(event.target.checked)}
          />
          <CheckCircle2 size={18} />
          <span>{labels.authorized}</span>
        </label>

        <label className="toggle">
          <input
            type="checkbox"
            checked={realOnly}
            onChange={(event) => onRealOnlyChange(event.target.checked)}
          />
          <ShieldAlert size={18} />
          <span>{labels.realOnly}</span>
        </label>

        <label className={`toggle tor-toggle ${!authorizedScope ? "disabled" : ""}`} title={labels.torHint}>
          <input
            type="checkbox"
            checked={allowTor && authorizedScope}
            disabled={!authorizedScope}
            onChange={(event) => onAllowTorChange(event.target.checked)}
          />
          <Network size={18} />
          <span>{labels.torSearch}</span>
        </label>
      </div>
      {canOverrideReportDate ? (
        <div className="report-date-control">
          <div>
            <Clock3 size={18} />
            <div>
              <span>{labels.reportDate}</span>
              <small>{labels.reportDateHint}</small>
            </div>
          </div>
          <input
            type="datetime-local"
            value={reportDisplayAt}
            onChange={(event) => onReportDisplayAtChange(event.target.value)}
            aria-label={labels.reportDate}
            placeholder={labels.reportDatePlaceholder}
          />
          <button className="secondary-button compact" type="button" onClick={() => onReportDisplayAtChange("")}>
            <CalendarX2 size={16} />
            {labels.clearReportDate}
          </button>
        </div>
      ) : null}
      {canSaveDefaults ? (
        <div className="default-scope-row">
          <button className="secondary-button compact" type="button" onClick={onSaveDefaults}>
            <Save size={16} />
            {labels.saveDefault}
          </button>
          {defaultScopeMessage ? <span>{defaultScopeMessage}</span> : null}
        </div>
      ) : null}
    </section>
  );
}
