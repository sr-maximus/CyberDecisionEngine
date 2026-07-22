export type RunStatus = "queued" | "running" | "completed" | "failed";
export type AnalysisMode = "snapshot" | "deep";
export type SubjectType = "organization" | "person";
export type AnalysisWindow = "1h" | "24h" | "7d" | "30d" | "180d" | "365d";
export type UserRole = "super_admin" | "admin" | "analyst" | "executive" | "viewer";
export type ThemeMode = "light" | "dark";
export type LanguageMode = "es" | "en";
export type ViewKey =
  | "overview"
  | "dashboards"
  | "scenarios"
  | "brand"
  | "attackSurface"
  | "employeeRisk"
  | "disinformation"
  | "socmint"
  | "osint"
  | "darkweb"
  | "frameworks"
  | "ai"
  | "runs"
  | "reports"
  | "help"
  | "settings";

export interface DomainAnalysisRequest {
  domains: string[];
  competitor_domains?: string[];
  organization_name?: string;
  subject_type?: SubjectType;
  person_name?: string;
  person_aliases?: string[];
  legal_name?: string;
  sector: string;
  subsector?: string;
  country: string;
  brands?: string[];
  subsidiaries?: string[];
  parent_organizations?: string[];
  products?: string[];
  strategic_assets?: string[];
  critical_suppliers?: string[];
  declared_competitors?: string[];
  countries_of_operation?: string[];
  entity_aliases?: Array<Record<string, unknown>>;
  language?: LanguageMode;
  mode: AnalysisMode;
  analysis_window: AnalysisWindow;
  lookback_hours: number;
  lookback_days: number;
  real_only: boolean;
  authorized_scope: boolean;
  allow_tor: boolean;
  scan_time_budget_minutes: number;
  report_display_at?: string | null;
  scope_profile_source_run_id?: string | null;
  scope_profile_applied_fields?: string[];
}

export interface LocalUser {
  id: string;
  username: string;
  passwordHash: string;
  password?: string;
  fullName: string;
  role: UserRole;
  permissions: string[];
  companyId?: string;
  companyName?: string;
  licenseModules?: ViewKey[];
  mfaEnabled?: boolean;
  mfaCodeHash?: string;
  mfaCodeIssuedAt?: string;
  mfaCodeExpiresAt?: number;
  failedLoginCount?: number;
  lockedUntil?: number;
  passwordUpdatedAt?: string;
  mustChangePassword?: boolean;
  createdAt: string;
}

export type LicenseStatus = "active" | "trial" | "suspended" | "expired";
export type LicenseUserStatus = "active" | "inactive";

export interface LicenseModuleCatalogItem {
  key: ViewKey;
  group: string;
  label: Record<LanguageMode, string>;
  description: Record<LanguageMode, string>;
}

export interface LicensePlan {
  code: string;
  name: string;
  description: Record<LanguageMode, string>;
  max_users: number;
  modules: ViewKey[];
  status: "active" | "inactive";
  created_at: string;
  updated_at: string;
}

export interface LicenseCompany {
  id: string;
  name: string;
  slug: string;
  status: "active" | "inactive";
  parent_id?: string | null;
  country: string;
  sector: string;
  created_at: string;
  updated_at: string;
}

export interface CompanyLicense {
  id: string;
  company_id: string;
  plan_code: string;
  status: LicenseStatus;
  seats: number;
  starts_at: string;
  expires_at?: string | null;
  modules_override: ViewKey[];
  effective_modules: ViewKey[];
  created_at: string;
  updated_at: string;
}

export interface LicenseControlUser {
  id: string;
  company_id: string;
  username: string;
  full_name: string;
  role: UserRole;
  plan_code?: string | null;
  status: LicenseUserStatus;
  modules: ViewKey[];
  effective_modules: ViewKey[];
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface LicenseAuditLogEntry {
  id: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  company_id?: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface LicensingOverview {
  generated_at: string;
  module_catalog: LicenseModuleCatalogItem[];
  plans: LicensePlan[];
  companies: LicenseCompany[];
  licenses: CompanyLicense[];
  users: LicenseControlUser[];
  audit_log: LicenseAuditLogEntry[];
}

export interface ReportSummary {
  path: string;
  url: string;
  download_url?: string | null;
  technical_path?: string | null;
  technical_url?: string | null;
  technical_download_url?: string | null;
  generated_at: string;
}

export interface ReportCatalogItem {
  name: string;
  path: string;
  url: string;
  download_url: string;
  size_bytes: number;
  modified_at: string;
  report_type: "executive" | "technical";
  run_id?: string | null;
}

export interface MitreGroup {
  id: string;
  name: string;
  aliases: string[];
  techniques: string[];
  description?: string | null;
}

export interface KpiSummary {
  active_domains: number;
  new_events: number;
  raw_records?: number;
  unique_records?: number;
  validated_evidence?: number;
  validated_findings?: number;
  confirmed_findings?: number;
  confirmed_incidents?: number;
  false_positives?: number;
  max_residual_risk: number | null;
  avg_residual_risk: number | null;
  healthy_sources: number;
  total_sources: number;
  queried_sources?: number;
  productive_sources?: number;
  registered_sources?: number;
}

export interface DomainSignal {
  domain: string;
  events: number;
  findings: number;
  max_residual_risk: number | null;
  last_seen?: string | null;
}

export interface SourceStatus {
  name: string;
  status: string;
  records: number;
  mode: string;
  warning?: string | null;
  registered?: boolean;
  configured?: boolean;
  enabled?: boolean;
  eligible?: boolean;
  attempted?: boolean;
  succeeded?: boolean;
  productive?: boolean;
  empty?: boolean;
  degraded?: boolean;
  skipped?: boolean;
  unconfigured?: boolean;
  disabled?: boolean;
  queried?: boolean;
  success?: boolean;
  partial?: boolean;
  no_data?: boolean;
  rate_limited?: boolean;
  timed_out?: boolean;
  failed?: boolean;
  coverage_score?: number;
  source_health_score?: number;
  source_completeness_score?: number;
}

export interface Finding {
  title: string;
  category: string;
  residual_risk: number;
  matrix_label: string;
  owner: string;
  evidence: string[];
  recommendations: string[];
  demo?: boolean;
  evidence_status?: string;
  confidence_score?: number;
  linked_evidence_ids?: string[];
  incident_confirmed?: boolean;
  vulnerability_status?: string;
}

export interface ThreatEvent {
  id: string;
  title: string;
  category: string;
  source: string;
  observed_at: string;
  actor?: string | null;
  technique?: string | null;
  tags?: string[];
  evidence_url?: string | null;
  demo?: boolean;
  canonical_id?: string | null;
  content_hash?: string | null;
  record_kind?: string;
  evidence_status?: string;
  confidence_level?: string;
  confidence_score?: number;
  relationship_to_scope?: string;
  validation_result?: string;
  technical_validation?: Record<string, unknown>;
  asset?: string | null;
  host?: string | null;
  indicator?: string | null;
  external_id?: string | null;
  source_refs?: string[];
  duplicate_count?: number;
  vulnerability_status?: string;
  attack_mapping_status?: string;
  incident_confirmed?: boolean;
  human_reviewed?: boolean;
  contradiction_count?: number;
}

export interface AnalysisSummary {
  kpis: KpiSummary;
  domain_signals: DomainSignal[];
  findings: Finding[];
  events: ThreatEvent[];
  records?: ThreatEvent[];
  source_statuses: SourceStatus[];
  metrics: Record<string, unknown>;
  processing_summary?: Record<string, unknown>;
  decision_snapshot?: DecisionIntelligenceSnapshot;
  claims?: ClaimSummary[];
  evidence_items?: EvidenceSummary[];
  claim_evidence_links?: ClaimEvidenceLinkSummary[];
  contradicting_evidence?: Record<string, unknown>[];
  interpretations?: InterpretationSummary[];
  decisions?: ClaimDecisionSummary[];
  semantic_registry_version?: string;
  claim_evidence_model_version?: string;
}

export interface ClaimSummary {
  claim_id: string;
  statement: string;
  claim_status: string;
  confidence: number;
  evidence_ids: string[];
  limitations: string[];
  validation_method?: string | null;
}

export interface EvidenceSummary {
  evidence_id: string;
  source_id: string;
  canonical_url?: string | null;
  evidence_status: string;
  validation_method?: string | null;
}

export interface ClaimEvidenceLinkSummary {
  claim_id: string;
  evidence_id: string;
  relation: string;
  strength: number;
}

export interface InterpretationSummary {
  claim_id: string;
  what_found: string;
  what_demonstrates: string;
  what_not_demonstrates: string;
  validation_summary: string;
}

export interface ClaimDecisionSummary {
  claim_id: string;
  decision: string;
  owner: string;
  recommended_action: string;
  closure_criteria: string;
}

export type DecisionValueStatus = "valid_value" | "observed_zero" | "no_data" | "insufficient_evidence" | "source_unavailable" | "not_applicable" | "not_calculated" | "stale_data" | "partial_data" | "error";

export interface DecisionMetricValue {
  metric_id: string;
  label: string;
  value?: number | null;
  unit: string;
  value_status: DecisionValueStatus;
  numerator?: number | null;
  denominator?: number | null;
  period: string;
  confidence: number;
  definition: string;
  formula: string;
  evidence_ids: string[];
}

export interface DecisionDomainRow {
  domain: string;
  record_count: number;
  direct_evidence_count: number;
  validated_evidence_count: number;
  validated_findings_count: number;
  supported_scenarios_count: number;
  max_residual_risk?: number | null;
  risk_value_status: DecisionValueStatus;
  source_count: number;
  last_observed_at?: string | null;
  top_signal: string;
  evidence_ids: string[];
}

export interface DecisionSnapshotScenario {
  scenario_id: string;
  title: string;
  status: string;
  framework: string;
  domain: string;
  rationale: string;
  decision_question: string;
  decision_possibility: string;
  owner_role: string;
  due_window: string;
  success_measure: string;
  confidence: number;
  evidence_ids: string[];
}

export interface DecisionSnapshotAction {
  decision_id: string;
  status: string;
  title: string;
  rationale: string;
  owner_role: string;
  due_window: string;
  success_measure: string;
  confidence: number;
  evidence_ids: string[];
}

export interface DecisionIntelligenceSnapshot {
  schema_version: string;
  report_context: {
    run_id: string;
    snapshot_version: string;
    engine_version: string;
    generated_at: string;
    report_date: string;
    language: string;
    analysis_window: string;
    lookback_hours: number;
    organization_name: string;
    subject_name: string;
    subject_type: SubjectType;
    organization_identity_status: string;
    primary_domains: string[];
    comparison_domains: string[];
    sector: string;
    country: string;
    data_basis: string;
  };
  metrics: Record<string, DecisionMetricValue>;
  analyzed_entities: Array<{
    entity_id: string;
    canonical_name: string;
    entity_type: string;
    validation_status: string;
    aliases?: string[];
    domains: string[];
  }>;
  domains: DecisionDomainRow[];
  evidence_references: Array<Record<string, unknown>>;
  scenario_funnel: Record<string, number>;
  supported_scenarios: DecisionSnapshotScenario[];
  decisions: DecisionSnapshotAction[];
  strategic_drivers: Array<Record<string, unknown>>;
  strategic_models: Record<string, unknown>;
  chart_eligibility: Record<string, { eligible: boolean; reason: string; evidence_count: number }>;
  limitations: string[];
  reference_integrity: Record<string, unknown>;
  formula_versions: Record<string, string>;
  snapshot_hash: string;
}

export interface RunRecord {
  id: string;
  status: RunStatus;
  stage: string;
  created_at: string;
  updated_at: string;
  request: DomainAnalysisRequest;
  domains: string[];
  progress: number;
  estimated_seconds?: number;
  error?: string | null;
  report?: ReportSummary | null;
  summary: AnalysisSummary;
}

export type MonitoringCadence = "manual" | "1h" | "6h" | "24h" | "7d" | "continuous";
export type MonitoringStatus = "active" | "paused" | "disabled";
export type AlertStatus = "open" | "acknowledged" | "closed" | "false_positive";
export type PlatformLogLevel = "info" | "warning" | "error";

export interface MonitoringProfileRequest {
  name: string;
  request: DomainAnalysisRequest;
  cadence: MonitoringCadence;
  collection_duration_minutes: number;
  enabled: boolean;
  created_by?: string;
}

export interface MonitoringProfile {
  id: string;
  name: string;
  request: DomainAnalysisRequest;
  cadence: MonitoringCadence;
  collection_duration_minutes: number;
  status: MonitoringStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
  last_run_id?: string | null;
  last_started_at?: string | null;
  last_completed_at?: string | null;
  next_run_at?: string | null;
  processed_run_ids: string[];
  seen_fingerprints: string[];
  alert_count: number;
  new_signal_count: number;
  last_error?: string | null;
}

export interface MonitoringAlert {
  id: string;
  profile_id: string;
  run_id: string;
  fingerprint: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  category: string;
  evidence_url?: string | null;
  validation: string;
  created_at: string;
  status: AlertStatus;
}

export interface PlatformLogEntry {
  id: string;
  level: PlatformLogLevel;
  component: string;
  message: string;
  run_id?: string | null;
  profile_id?: string | null;
  user?: string | null;
  created_at: string;
}

export interface SupportTicket {
  id: string;
  subject: string;
  description: string;
  user: string;
  run_id?: string | null;
  severity: "low" | "medium" | "high";
  status: "open" | "in_review" | "resolved";
  created_at: string;
  updated_at: string;
}

export interface MonitoringOverview {
  generated_at: string;
  profiles: MonitoringProfile[];
  alerts: MonitoringAlert[];
  logs: PlatformLogEntry[];
  support_tickets: SupportTicket[];
}

export type AIProvider = "openai" | "azure_openai" | "anthropic" | "gemini" | "mistral" | "local_openai_compatible" | "openclaw_gateway";

export interface AIProviderDescriptor {
  key: AIProvider;
  label: string;
  endpoint_hint: string;
  model_hint: string;
  headers_required: string[];
  enabled?: boolean;
  execution_policy?: string;
  mode?: string;
  runtime_status?: string;
  model_status?: string;
}

export interface AIOrchestrationConfig {
  prompt_version: string;
  provider_catalog: AIProviderDescriptor[];
  token_policy: Record<string, unknown>;
  approval_required: boolean;
  automation_default: string;
  openclaw_gateway?: Record<string, unknown>;
}

export interface AIAnalysisRequest {
  run_id: string;
  providers: AIProvider[];
  audience: "executive" | "technical" | "board" | "incident" | "fraud";
  depth: "standard" | "deep" | "board";
  objective: string;
  language: LanguageMode;
  input_token_budget: number;
  output_token_budget: number;
  include_findings_limit: number;
  include_events_limit: number;
  custom_instructions?: string | null;
}

export interface AIProviderPayload {
  provider: AIProvider;
  endpoint_hint: string;
  model_hint: string;
  headers_required: string[];
  body: Record<string, unknown>;
}

export interface AIAnalysisPackage {
  id: string;
  status: "draft" | "approved";
  prompt_version: string;
  generated_at: string;
  run_id: string;
  subject: string;
  token_estimate: Record<string, number>;
  token_policy: Record<string, unknown>;
  system_prompt: string;
  user_prompt: string;
  context_digest: Record<string, unknown>;
  evidence_manifest: Record<string, unknown>;
  guardrails: string[];
  output_schema: Record<string, unknown>;
  provider_payloads: AIProviderPayload[];
  approval_question: string;
}

export interface DashboardFilters {
  sectors: string[];
  continents: string[];
  countries: string[];
  cities: string[];
  threatGroups: string[];
  sourceModes: string[];
  dateRange: string;
}

export interface AttackSurfaceDns {
  status: string;
  addresses: string[];
  error?: string;
}

export interface AttackSurfaceCertificate {
  status: string;
  issuer?: string;
  subject?: string;
  expires_at?: string | null;
  days_remaining?: number | null;
  san_count?: number;
  error?: string;
}

export interface AttackSurfaceRdap {
  status: string;
  handle?: string;
  registrar?: string | null;
  events: Array<Record<string, unknown>>;
  nameservers: string[];
  error?: string;
}

export interface AttackSurfaceDomain {
  domain: string;
  scope: "own" | "competitor";
  risk_score: number;
  dns: AttackSurfaceDns;
  certificate: AttackSurfaceCertificate;
  rdap: AttackSurfaceRdap;
  tool_surface?: AttackSurfaceToolSurface;
}

export interface AttackSurfaceToolRun {
  tool: string;
  status: string;
  records: number;
  warning?: string | null;
}

export interface AttackSurfaceToolFinding {
  type: string;
  severity: string;
  title: string;
  asset?: string;
  url?: string;
  tool?: string;
}

export interface AttackSurfaceWebAsset {
  url?: string;
  host?: string;
  status_code?: number;
  title?: string;
  webserver?: string;
  technologies?: string[];
  cdn?: string | boolean;
  tool?: string;
}

export interface AttackSurfaceToolSurface {
  status?: string;
  subdomains: string[];
  web_assets: AttackSurfaceWebAsset[];
  findings: AttackSurfaceToolFinding[];
  tool_runs: AttackSurfaceToolRun[];
  warning?: string | null;
}

export interface AttackSurfaceSummary {
  own_count: number;
  competitor_count: number;
  own_avg_risk: number;
  competitor_avg_risk: number;
  cert_errors: number;
  rdap_errors: number;
  tool_surface_status?: string;
  tool_surface_warning?: string | null;
  tool_findings?: number;
  tool_subdomains?: number;
  tool_web_assets?: number;
}

export interface AttackSurfaceResponse {
  generated_at: string;
  domains: AttackSurfaceDomain[];
  summary: AttackSurfaceSummary;
}

export interface EmployeeRiskRunResponse {
  id: string;
  status: "completed" | "failed";
  stage: string;
  report_url?: string | null;
  download_url?: string | null;
  output_urls: Record<string, string>;
  employee_count: number;
  evidence_count: number;
  max_risk: number;
  command_output: string;
}

export interface DisinformationScenario {
  id: string;
  sector: string;
  title_es: string;
  title_en: string;
  frameworks: {
    attack: { id: string; name: string; tactics: string[] };
    disarm: { id: string; name: string; tactic: string };
    d3fend: { id: string; name: string };
    atlas: { id: string; name: string };
  };
  scores: {
    likelihood: number;
    impact: number;
    inherent_risk: number;
    control_effectiveness: number;
    residual_risk: number;
    geographic_relevance: number;
  };
  math: {
    z: number;
    formula: string;
    variables: Record<string, number>;
  };
  recommendation_es: string;
  recommendation_en: string;
  strategic_question_es: string;
  strategic_question_en: string;
}

export interface DisinformationFrameworkResponse {
  source?: string;
  source_url?: string;
  tactics: Array<Record<string, unknown>>;
  techniques: Array<Record<string, unknown>>;
  tactic_counts: Array<{ name: string; value: number }>;
  scenario_count: number;
  math_model: Record<string, string>;
  top_scenarios: DisinformationScenario[];
}

export interface ScenarioLibraryResponse {
  scenario_count: number;
  reference_template_count: number;
  defined_scenario_count: number;
  executable_scenario_count: number;
  tested_scenario_count: number;
  triggered_scenario_count: number;
  object_type: "reference_template";
  sources: string[];
  math_model: Record<string, string>;
  framework_counts: {
    reference_templates: number;
    attack_techniques: number;
    d3fend_controls: number;
    atlas_tactics: number;
    disarm_techniques: number;
  };
  scenarios: DisinformationScenario[];
}

export interface MethodologyVariable {
  id: string;
  label: string;
  range: string;
}

export interface MethodologyRecord {
  methodId: string;
  name: Record<LanguageMode, string>;
  version: string;
  status: "active" | "reference_only" | "inactive";
  purpose: Record<LanguageMode, string>;
  formula: string;
  variables: MethodologyVariable[];
  weights: Record<string, number>;
  thresholds: Record<string, unknown>;
  missingDataPolicy: string;
  deduplicationPolicy: string;
  inputFields: string[];
  outputRange: string;
  interpretation: Record<LanguageMode, string>;
  limitations: string[];
  example: string;
  frameworkReferences: string[];
  implementationReference: string;
  testReferences: string[];
  effectiveFrom: string;
}

export interface MethodologyRegistryResponse {
  registryVersion: string;
  effectiveFrom: string;
  methods: MethodologyRecord[];
}
