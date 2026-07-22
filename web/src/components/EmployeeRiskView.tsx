import { Download, FileInput, Play, Rows3, UploadCloud, UserRound, Users } from "lucide-react";
import { useMemo, useState } from "react";
import { apiUrl, runEmployeeRiskAnalysis } from "../api";
import { ALL_CONTINENTS, countriesFor, isoCodesForCountries } from "../data/catalog";
import type { EmployeeRiskRunResponse, LanguageMode } from "../types";

type EntryMode = "single" | "bulk";

const employeeColumns = [
  "employee_id",
  "full_name",
  "personal_email",
  "corporate_email",
  "identification_document",
  "role",
  "department",
  "organization",
  "country",
  "city",
  "access_level",
  "access_category",
  "consent_status",
  "consent_date",
  "authorized_personal_email"
];

const copy = {
  es: {
    title: "Riesgo virtual de empleados",
    subtitle: "Ejecuta el modelo OSINT de exposición pública por persona. Puedes analizar un empleado individual o cargar una lista estructurada.",
    single: "Empleado individual",
    bulk: "Carga masiva",
    singleSubtitle: "Formulario rápido para un solo usuario",
    bulkSubtitle: "CSV/XLSX con la estructura esperada",
    structure: "Estructura del archivo",
    template: "Descargar plantilla CSV",
    file: "Archivo de empleados CSV/XLSX",
    manual: "Resultados manuales opcionales",
    searchClient: "Cliente de búsqueda",
    results: "Resultados por query",
    keywords: "Keywords por dimensión",
    queries: "Queries por empleado",
    confidence: "Confianza mínima",
    allowPersonal: "Permitir correo personal autorizado",
    skipWeb: "Analizar solo resultados manuales",
    noIdentity: "Desactivar descubrimiento amplio de identidad",
    run: "Generar informe",
    running: "Generando informe...",
    employeeId: "ID empleado",
    fullName: "Nombre completo",
    corporateEmail: "Correo corporativo",
    personalEmail: "Correo personal",
    role: "Cargo",
    department: "Área",
    organization: "Organización",
    country: "País",
    city: "Ciudad",
    accessLevel: "Nivel de acceso",
    accessCategory: "Categoría de acceso",
    employees: "Empleados",
    evidence: "Evidencias",
    maxRisk: "Riesgo máximo",
    download: "Descargar informe",
    open: "Abrir informe",
    output: "Archivos generados",
    noReport: "Carga datos y genera el informe; el resultado se verá dentro de este tablero.",
    error: "No se pudo generar el informe",
    required: "Completa ID empleado y nombre completo.",
    requiredBulk: "Carga un archivo CSV/XLSX con employee_id, full_name y consent_status.",
    contextRequired: "Agrega al menos un dato contextual: correo, organización, cargo, país o ciudad.",
    invalidConfidence: "La confianza mínima debe estar entre 0 y 1.",
    invalidAccessLevel: "El nivel de acceso debe estar entre 1 y 5.",
    manualRequired: "Si analizas solo resultados manuales, carga el archivo de resultados.",
    countryHint: "Catálogo internacional",
    cityHint: "Escribe o selecciona una ciudad del país elegido"
  },
  en: {
    title: "Employee virtual risk",
    subtitle: "Runs the public-exposure OSINT model by person. Analyze one employee directly or upload a structured list.",
    single: "Single employee",
    bulk: "Bulk upload",
    singleSubtitle: "Fast form for one user",
    bulkSubtitle: "CSV/XLSX with the expected structure",
    structure: "File structure",
    template: "Download CSV template",
    file: "Employee CSV/XLSX file",
    manual: "Optional manual results",
    searchClient: "Search client",
    results: "Results per query",
    keywords: "Keywords per dimension",
    queries: "Queries per employee",
    confidence: "Minimum confidence",
    allowPersonal: "Allow authorized personal email",
    skipWeb: "Analyze manual results only",
    noIdentity: "Disable broad identity discovery",
    run: "Generate report",
    running: "Generating report...",
    employeeId: "Employee ID",
    fullName: "Full name",
    corporateEmail: "Corporate email",
    personalEmail: "Personal email",
    role: "Role",
    department: "Department",
    organization: "Organization",
    country: "Country",
    city: "City",
    accessLevel: "Access level",
    accessCategory: "Access category",
    employees: "Employees",
    evidence: "Evidence",
    maxRisk: "Max risk",
    download: "Download report",
    open: "Open report",
    output: "Generated files",
    noReport: "Enter data and generate the report; the result will render inside this board.",
    error: "Unable to generate report",
    required: "Complete employee ID and full name.",
    requiredBulk: "Upload a CSV/XLSX file with employee_id, full_name and consent_status.",
    contextRequired: "Add at least one context field: email, organization, role, country or city.",
    invalidConfidence: "Minimum confidence must be between 0 and 1.",
    invalidAccessLevel: "Access level must be between 1 and 5.",
    manualRequired: "If you analyze manual results only, upload the results file.",
    countryHint: "International catalog",
    cityHint: "Type or select a city from the selected country"
  }
};

export function EmployeeRiskView({ language, onReportReady }: { language: LanguageMode; onReportReady?: () => Promise<void> }) {
  const t = copy[language];
  const [entryMode, setEntryMode] = useState<EntryMode>("single");
  const [employeeFile, setEmployeeFile] = useState<File | null>(null);
  const [manualFile, setManualFile] = useState<File | null>(null);
  const [singleEmployee, setSingleEmployee] = useState({
    employee_id: "",
    full_name: "",
    personal_email: "",
    corporate_email: "",
    identification_document: "",
    role: "",
    department: "",
    organization: "",
    country: "",
    city: "",
    access_level: "3",
    access_category: "general"
  });
  const [searchClient, setSearchClient] = useState("multi_noapi");
  const [resultsPerQuery, setResultsPerQuery] = useState(3);
  const [maxKeywords, setMaxKeywords] = useState(8);
  const [maxQueries, setMaxQueries] = useState(10);
  const [minConfidence, setMinConfidence] = useState("0.35");
  const [allowPersonalEmail, setAllowPersonalEmail] = useState(false);
  const [skipWebSearch, setSkipWebSearch] = useState(false);
  const [noIdentityDiscovery, setNoIdentityDiscovery] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<EmployeeRiskRunResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validationMessages, setValidationMessages] = useState<string[]>([]);
  const [cityNames, setCityNames] = useState<string[]>([]);

  const countries = useMemo(() => countriesFor([ALL_CONTINENTS]).slice(1), []);

  async function loadCities() {
    if (cityNames.length) return;
    const isoCode = isoCodesForCountries([singleEmployee.country])[0];
    if (!isoCode) return;
    const { City } = await import("country-state-city");
    const loaded = (City.getCitiesOfCountry(isoCode) ?? [])
      .map((city) => city.name)
      .sort((left, right) => left.localeCompare(right));
    setCityNames(Array.from(new Set(loaded)).slice(0, 6000));
  }

  const templateHref = useMemo(() => {
    const sample = [
      employeeColumns.join(","),
      [
        "E001",
        "Nombre Apellido",
        "",
        "nombre.apellido@empresa.com",
        "",
        "Cargo",
        "Área",
        "Empresa",
        "Colombia",
        "Bogotá",
        "3",
        "general",
        "approved",
        new Date().toISOString().slice(0, 10),
        "false"
      ].join(",")
    ].join("\n");
    return `data:text/csv;charset=utf-8,${encodeURIComponent(sample)}`;
  }, []);

  async function submit() {
    setError(null);
    const messages = entryMode === "single"
      ? validateSingleEmployee(singleEmployee, minConfidence, skipWebSearch, manualFile, t)
      : validateBulkEmployee(employeeFile, minConfidence, skipWebSearch, manualFile, t);
    setValidationMessages(messages);
    if (messages.length) return;
    const inputFile = entryMode === "single" ? buildSingleEmployeeFile(singleEmployee) : employeeFile;
    if (!inputFile) {
      setError(entryMode === "single" ? t.required : t.requiredBulk);
      return;
    }
    setIsRunning(true);
    try {
      const form = new FormData();
      form.append("employees_file", inputFile);
      if (manualFile) form.append("manual_results_file", manualFile);
      form.append("search_client", searchClient);
      form.append("results_per_query", String(resultsPerQuery));
      form.append("max_keywords_per_dimension", String(maxKeywords));
      form.append("max_queries_per_employee", String(maxQueries));
      form.append("min_confidence", minConfidence);
      form.append("allow_personal_email", String(allowPersonalEmail));
      form.append("skip_web_search", String(skipWebSearch));
      form.append("no_identity_discovery", String(noIdentityDiscovery));
      const response = await runEmployeeRiskAnalysis(form);
      setResult(response);
      await onReportReady?.();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : t.error);
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="view-stack">
      <section className="panel module-hero employee-hero">
        <div>
          <Users size={24} />
          <h2>{t.title}</h2>
          <p>{t.subtitle}</p>
        </div>
        <div className="mode-switch" role="tablist" aria-label={t.title}>
          <button className={entryMode === "single" ? "selected" : ""} onClick={() => setEntryMode("single")}>
            <UserRound size={17} />
            <span>{t.single}</span>
          </button>
          <button className={entryMode === "bulk" ? "selected" : ""} onClick={() => setEntryMode("bulk")}>
            <Rows3 size={17} />
            <span>{t.bulk}</span>
          </button>
        </div>
      </section>

      <section className="employee-risk-layout refined">
        <article className="panel chart-card employee-risk-form">
          <div className="panel-title-row compact">
            <div>
              <h2>{entryMode === "single" ? t.single : t.bulk}</h2>
              <p>{entryMode === "single" ? t.singleSubtitle : t.bulkSubtitle}</p>
            </div>
            <UploadCloud size={18} />
          </div>

          {entryMode === "single" ? (
            <div className="single-employee-grid">
              <TextControl label={t.employeeId} value={singleEmployee.employee_id} onChange={(value) => setSingleEmployee({ ...singleEmployee, employee_id: value })} />
              <TextControl label={t.fullName} value={singleEmployee.full_name} onChange={(value) => setSingleEmployee({ ...singleEmployee, full_name: value })} />
              <TextControl label={t.corporateEmail} value={singleEmployee.corporate_email} onChange={(value) => setSingleEmployee({ ...singleEmployee, corporate_email: value })} />
              <TextControl label={t.personalEmail} value={singleEmployee.personal_email} onChange={(value) => setSingleEmployee({ ...singleEmployee, personal_email: value })} />
              <TextControl label={t.role} value={singleEmployee.role} onChange={(value) => setSingleEmployee({ ...singleEmployee, role: value })} />
              <TextControl label={t.department} value={singleEmployee.department} onChange={(value) => setSingleEmployee({ ...singleEmployee, department: value })} />
              <TextControl label={t.organization} value={singleEmployee.organization} onChange={(value) => setSingleEmployee({ ...singleEmployee, organization: value })} />
              <SelectControl
                label={t.country}
                value={singleEmployee.country}
                options={countries}
                placeholder={language === "es" ? "Seleccione un país" : "Select a country"}
                hint={t.countryHint}
                onChange={(value) => {
                  setCityNames([]);
                  setSingleEmployee({ ...singleEmployee, country: value, city: "" });
                }}
              />
              <DatalistControl
                label={t.city}
                value={singleEmployee.city}
                options={cityNames}
                listId="employee-city-options"
                hint={t.cityHint}
                onFocus={() => void loadCities()}
                onChange={(value) => setSingleEmployee({ ...singleEmployee, city: value })}
              />
              <SelectControl label={t.accessLevel} value={singleEmployee.access_level} options={["1", "2", "3", "4", "5"]} onChange={(value) => setSingleEmployee({ ...singleEmployee, access_level: value })} />
              <TextControl label={t.accessCategory} value={singleEmployee.access_category} onChange={(value) => setSingleEmployee({ ...singleEmployee, access_category: value })} />
            </div>
          ) : (
            <div className="bulk-upload-stack">
              <label className="file-drop">
                <FileInput size={18} />
                <span>{employeeFile?.name ?? t.file}</span>
                <input type="file" accept=".csv,.xlsx" onChange={(event) => setEmployeeFile(event.target.files?.[0] ?? null)} />
              </label>
              <div className="schema-card">
                <strong>{t.structure}</strong>
                <code>{employeeColumns.join(", ")}</code>
                <a href={templateHref} download="employee-risk-template.csv">{t.template}</a>
              </div>
            </div>
          )}

          <label className="file-drop subtle">
            <FileInput size={18} />
            <span>{manualFile?.name ?? t.manual}</span>
            <input type="file" accept=".csv,.xlsx" onChange={(event) => setManualFile(event.target.files?.[0] ?? null)} />
          </label>

          <div className="form-grid">
            <label>
              <span>{t.searchClient}</span>
              <select value={searchClient} onChange={(event) => setSearchClient(event.target.value)}>
                <option value="multi_noapi">multi_noapi</option>
                <option value="duckduckgo_lite">duckduckgo_lite</option>
                <option value="bing_html">bing_html</option>
                <option value="mock">mock</option>
                <option value="bing">bing API</option>
                <option value="google_cse">google_cse API</option>
              </select>
            </label>
            <NumberControl label={t.results} value={resultsPerQuery} min={1} max={20} onChange={setResultsPerQuery} />
            <NumberControl label={t.keywords} value={maxKeywords} min={1} max={50} onChange={setMaxKeywords} />
            <NumberControl label={t.queries} value={maxQueries} min={1} max={100} onChange={setMaxQueries} />
            <label>
              <span>{t.confidence}</span>
              <input value={minConfidence} onChange={(event) => setMinConfidence(event.target.value)} />
            </label>
          </div>

          <div className="toggle-list compact">
            <label><input type="checkbox" checked={allowPersonalEmail} onChange={(event) => setAllowPersonalEmail(event.target.checked)} />{t.allowPersonal}</label>
            <label><input type="checkbox" checked={skipWebSearch} onChange={(event) => setSkipWebSearch(event.target.checked)} />{t.skipWeb}</label>
            <label><input type="checkbox" checked={noIdentityDiscovery} onChange={(event) => setNoIdentityDiscovery(event.target.checked)} />{t.noIdentity}</label>
          </div>

          <button className="primary-action full" disabled={isRunning || (entryMode === "bulk" && !employeeFile)} onClick={submit}>
            <Play size={18} />
            <span>{isRunning ? t.running : t.run}</span>
          </button>
          {validationMessages.length ? (
            <div className="validation-list" role="alert">
              {validationMessages.map((message) => <span key={message}>{message}</span>)}
            </div>
          ) : null}
          {error ? <div className="error-banner inline">{error}</div> : null}
        </article>

        <article className="panel chart-card employee-risk-results">
          {result ? (
            <>
              <div className="dashboard-kpis compact-kpis">
                <Metric label={t.employees} value={String(result.employee_count)} />
                <Metric label={t.evidence} value={String(result.evidence_count)} />
                <Metric label={t.maxRisk} value={String(result.max_risk)} />
              </div>
              <div className="report-actions-row">
                {result.report_url ? <a className="icon-text-button" href={apiUrl(result.report_url)} target="_blank" rel="noreferrer">{t.open}</a> : null}
                {result.download_url ? <a className="icon-text-button" href={apiUrl(result.download_url)}><Download size={16} />{t.download}</a> : null}
              </div>
              {result.report_url ? <iframe className="report-frame" src={apiUrl(result.report_url)} title={t.title} /> : <pre className="command-output">{result.command_output}</pre>}
              <div className="output-links">
                <strong>{t.output}</strong>
                {Object.entries(result.output_urls).map(([name, url]) => (
                  <a href={apiUrl(url)} key={name} target="_blank" rel="noreferrer">{name}</a>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state">{t.noReport}</div>
          )}
        </article>
      </section>
    </div>
  );
}

function buildSingleEmployeeFile(employee: Record<string, string>): File | null {
  if (!employee.employee_id.trim() || !employee.full_name.trim()) return null;
  const row: Record<string, string> = {
    ...employee,
    consent_status: "approved",
    consent_date: new Date().toISOString().slice(0, 10),
    authorized_personal_email: employee.personal_email ? "true" : "false"
  };
  const csv = [employeeColumns.join(","), employeeColumns.map((column) => csvCell(row[column] ?? "")).join(",")].join("\n");
  return new File([csv], "single_employee.csv", { type: "text/csv" });
}

function validateSingleEmployee(
  employee: Record<string, string>,
  minConfidence: string,
  skipWebSearch: boolean,
  manualFile: File | null,
  t: typeof copy.es
): string[] {
  const messages: string[] = [];
  if (!employee.employee_id.trim() || !employee.full_name.trim()) messages.push(t.required);
  const hasContext = [
    employee.personal_email,
    employee.corporate_email,
    employee.organization,
    employee.role,
    employee.department,
    employee.country,
    employee.city
  ].some((value) => value.trim().length > 0);
  if (!hasContext) messages.push(t.contextRequired);
  const accessLevel = Number(employee.access_level);
  if (!Number.isFinite(accessLevel) || accessLevel < 1 || accessLevel > 5) messages.push(t.invalidAccessLevel);
  messages.push(...validateSharedInputs(minConfidence, skipWebSearch, manualFile, t));
  return messages;
}

function validateBulkEmployee(employeeFile: File | null, minConfidence: string, skipWebSearch: boolean, manualFile: File | null, t: typeof copy.es): string[] {
  const messages: string[] = [];
  if (!employeeFile) messages.push(t.requiredBulk);
  messages.push(...validateSharedInputs(minConfidence, skipWebSearch, manualFile, t));
  return messages;
}

function validateSharedInputs(minConfidence: string, skipWebSearch: boolean, manualFile: File | null, t: typeof copy.es): string[] {
  const messages: string[] = [];
  const confidence = Number(minConfidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) messages.push(t.invalidConfidence);
  if (skipWebSearch && !manualFile) messages.push(t.manualRequired);
  return messages;
}

function csvCell(value: string): string {
  const escaped = String(value ?? "").replace(/"/g, '""');
  return /[",\n]/.test(escaped) ? `"${escaped}"` : escaped;
}

function TextControl({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label>
      <span>{label}</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function SelectControl({ label, value, options, placeholder, hint, onChange }: { label: string; value: string; options: string[]; placeholder?: string; hint?: string; onChange: (value: string) => void }) {
  return (
    <label>
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {placeholder ? <option value="">{placeholder}</option> : null}
        {options.map((option) => <option value={option} key={option}>{option}</option>)}
      </select>
      {hint ? <em>{hint}</em> : null}
    </label>
  );
}

function DatalistControl({ label, value, options, listId, hint, onFocus, onChange }: { label: string; value: string; options: string[]; listId: string; hint?: string; onFocus?: () => void; onChange: (value: string) => void }) {
  return (
    <label>
      <span>{label}</span>
      <input value={value} list={listId} onFocus={onFocus} onChange={(event) => onChange(event.target.value)} />
      <datalist id={listId}>
        {options.map((option) => <option value={option} key={option} />)}
      </datalist>
      {hint ? <em>{hint}</em> : null}
    </label>
  );
}

function NumberControl({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  return (
    <label>
      <span>{label}</span>
      <input type="number" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} />
    </label>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="dashboard-metric metric-plain">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
