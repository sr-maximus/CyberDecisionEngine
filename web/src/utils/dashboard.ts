import type { DashboardFilters, Finding, RunRecord, SourceStatus, ThreatEvent } from "../types";
import { ALL_GROUPS, ALL_SOURCES, includesAll } from "../data/catalog";
import { predictionModelWeights, predictionModes, sectorPredictionWeights } from "../data/threatPredictionCatalog";

export interface TrendPoint {
  label: string;
  value: number;
}

export interface RankedItem {
  name: string;
  value: number;
  tone?: "low" | "medium" | "high" | "critical";
}

export interface GeographicCountryItem {
  name: string;
  code: string;
  records: number;
  declared: boolean;
  status: "declared_scope" | "declared_and_mentioned" | "mention_only" | "supported_operational_context";
}

export interface SocmintNode {
  id: string;
  label: string;
  group: "platform" | "topic" | "user" | "mention";
  x: number;
  y: number;
  size: number;
}

export interface SocmintLink {
  from: string;
  to: string;
}

export interface GraphMetric {
  label: string;
  value: string;
  helper: string;
  tone?: "low" | "medium" | "high" | "critical";
}

export interface FrameworkMappingItem {
  name: string;
  family: string;
  coverage: number;
  coverageAssessed: boolean;
  exposure: number;
  domains: string[];
  affectedAspects: string[];
  considerations: string[];
  evidenceFocus: string[];
  analysisUse: string;
  sourceLabel: string;
  sourceUrl?: string;
  sourceDate?: string;
  decision: string;
  tone: "low" | "medium" | "high" | "critical";
  recordCount: number;
  validatedCount: number;
  directCount: number;
  axisMappings: FrameworkAxisMapping[];
}

export interface FrameworkEvidenceRecord {
  evidenceId: string;
  title: string;
  url: string;
  source: string;
  status: string;
  relationship: string;
  domain: string;
  observedAt: string;
}

export interface FrameworkAxisMapping {
  axis: string;
  controls: string[];
  recordCount: number;
  validatedCount: number;
  directCount: number;
  relatedCount: number;
  findingCount: number;
  domains: string[];
  evidence: FrameworkEvidenceRecord[];
}

export interface StrategyDimension {
  name: string;
  shortName: string;
  key: string;
  score: number | null;
  signalScore: number | null;
  validatedPressure: number | null;
  confidence: number;
  evidenceCoverage: number;
  status: string;
  delta: number | null;
  clusterCount: number;
  independentSourceCount: number;
  directCount: number;
  groupCount: number;
  sectorCount: number;
  why: string;
  decision: string;
  whatChanged: string;
  evidenceUrls: string[];
  events: StrategyEvent[];
  calculation: {
    evidenceMass: number;
    directionIndex: number | null;
    sourceDiversity: number;
    weightedDirectness: number;
    directionAgreement: number;
    extractionQuality: number;
    contributionCount: number;
    publicationGatePassed: boolean;
  };
}

export interface StrategyEvent {
  id: string;
  title: string;
  relationship: string;
  direction: string;
  magnitude: string;
  mappingReason: string;
  evidenceUrls: string[];
}

export interface StrategySnapshot {
  windowDays: number;
  score: number | null;
  confidence: number;
  coverageRatio: number;
  status: string;
}

export interface StrategyLens {
  title: string;
  index: number | null;
  overallConfidence: number;
  coverageRatio: number;
  evidenceCoverageRatio: number;
  clusterCount: number;
  articleCount: number;
  meaning: string;
  dimensions: StrategyDimension[];
  assessmentStatus: string;
  isRiskScore: boolean;
  signalCount: number;
  snapshots: StrategySnapshot[];
  analysisBasis?: {
    declaredContextCoverage: number;
    historicalEvidenceReused: boolean;
    context: Record<string, string[]>;
  };
}

export interface RiskHeatRow {
  index: number;
  name: string;
  score: number;
  heat: "low" | "medium" | "high" | "critical";
  evidenceCount: number;
  maxResidualRisk: number;
  decision: string;
}

export interface PosturePoint {
  name: string;
  value: number;
  tone: "low" | "medium" | "high" | "critical";
}

export interface DomainEvidenceItem {
  domain: string;
  signals: number;
  sources: string[];
  categories: string[];
  latest?: ThreatEvent;
}

export interface ExposureAuditItem {
  domain: string;
  label: string;
  query: string;
  intent: string;
  resultCount: number;
  urls: string[];
  tone: "low" | "medium" | "high" | "critical";
}

export interface PredictionDriver {
  name: string;
  value: number;
  explanation: string;
}

export interface PredictionScenario {
  id?: string;
  modality: string;
  technique: string;
  group: string;
  sector: string;
  supportScore: number;
  evidenceCount: number;
  decision: string;
  evidence: ThreatEvent[];
  status?: string;
  sourceCount?: number;
}

export interface AttackPredictionModel {
  status: "assessed" | "insufficient_evidence" | "legacy_fallback";
  pressure7d: number;
  pressure14d: number;
  pressure30d: number;
  pressure90d: number;
  signalRateDaily: number;
  evidenceConfidence: number;
  calibrated: false;
  probabilityValue: number | null;
  probabilityStatus: string;
  trendDirection: "rising" | "stable" | "falling" | "insufficient_evidence";
  trendChangeRatio: number | null;
  modelVersion: string;
  leadingScenario?: PredictionScenario;
  drivers: PredictionDriver[];
  scenarios: PredictionScenario[];
  methodology: string;
}

export interface BrandMentionItem {
  id: string;
  title: string;
  source: string;
  category: string;
  observedAt: string;
  url?: string | null;
  term: string;
  domain: string;
  tone: "low" | "medium" | "high" | "critical";
  sentiment: "positive" | "neutral" | "negative";
  phrase: string;
  driver: string;
}

export interface BrandDomainSentiment {
  domain: string;
  positive: number;
  neutral: number;
  negative: number;
  reputationImpact: number;
  total: number;
}

export interface BrandLookalikeSignal {
  targetDomain: string;
  observedDomain: string;
  url: string;
  source: string;
  reason: string;
  similarity: number;
  tone: "low" | "medium" | "high" | "critical";
}

export interface BrandRiskModel {
  terms: string[];
  mentions: BrandMentionItem[];
  trend: TrendPoint[];
  sourceRanking: RankedItem[];
  categoryRanking: RankedItem[];
  toneMix: RankedItem[];
  sentimentMix: RankedItem[];
  domainSentiment: BrandDomainSentiment[];
  lookalikes: BrandLookalikeSignal[];
  reputationImpact: number;
  negativeSignals: number;
  positiveSignals: number;
  fraudPressure: number;
  brandExposure: number;
  fraudSignals: number;
  darkWebSignals: number;
  socmintSignals: number;
  recommendations: string[];
}

export interface VulnerabilityIntelModel {
  confirmedCves: number;
  candidateCves: number;
  contextualCves: number;
  kevMatches: number;
  publicExploitReferences: number;
  cvssV4Records: number;
  observedTechnologies: number;
  surfaceAssets: number;
  patchFocus: string;
  rows: Array<{
    type: string;
    label: string;
    asset: string;
    status: string;
    decision: string;
    cvssScore: number | null;
    cvssVersion: string;
    cvssVector: string;
    product: string;
    observedVersion: string;
    affectedRange: string;
    applicabilityBasis: string;
    evidence_url?: string | null;
  }>;
}

export interface QuantitativeRiskModel {
  layered: {
    status: string;
    currency: string;
    scenarioCount: number;
    aggregateExpectedAnnualLoss: number | null;
    modelVersion: string;
    scenarios: Array<{
      name: string;
      resultingFrequency: number;
      expectedAnnualLoss: number;
      riskReduction: number;
      layerCount: number;
    }>;
  };
}

export interface DashboardModel {
  trend: TrendPoint[];
  categories: RankedItem[];
  actors: RankedItem[];
  ttpImpact: RankedItem[];
  attackActions: RankedItem[];
  affectedStates: RankedItem[];
  regionalHeat: RankedItem[];
  geographicCountries: GeographicCountryItem[];
  sectorMatrix: RankedItem[];
  sourceFreshness: number;
  socmintNodes: SocmintNode[];
  socmintLinks: SocmintLink[];
  socmintAvailable: boolean;
  threatGraphNodes: SocmintNode[];
  threatGraphLinks: SocmintLink[];
  graphMetrics: GraphMetric[];
  frameworkMappings: FrameworkMappingItem[];
  postureIndex: number;
  posturePoints: PosturePoint[];
  pestel: StrategyLens;
  porter: StrategyLens;
  riskHeatRows: RiskHeatRow[];
  platformMentions: RankedItem[];
  latestHeadlines: ThreatEvent[];
  groupHeadlines: ThreatEvent[];
  osintEvents: ThreatEvent[];
  darkwebEvents: ThreatEvent[];
  attackPrediction: AttackPredictionModel;
  vulnerabilityIntel: VulnerabilityIntelModel;
  quantitativeRisk: QuantitativeRiskModel;
}

const platformNames = ["Facebook", "Instagram", "TikTok", "X", "Public web"];
export const FRAMEWORK_REFERENCES_VERIFIED_AT = "2026-07-26";
const frameworkCatalog = [
  {
    name: "NIST CSF",
    family: "Cyber risk",
    domains: ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
    focus: ["vulnerability", "ransomware", "threat_intel", "account_takeover"],
    considerations: ["Governance ownership", "External exposure inventory", "Detection coverage", "Response playbooks"],
    evidenceFocus: ["KEV/CVE evidence", "risk findings", "source health", "incident response maturity"],
    analysisUse: "Prioritize executive cyber risk decisions across govern, protect, detect, respond and recover functions.",
    sourceLabel: "NIST Cybersecurity Framework 2.0 / CSWP 29",
    sourceUrl: "https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final",
    sourceDate: "2024-02-26"
  },
  {
    name: "ISO 27001",
    family: "ISMS",
    domains: ["Context", "Leadership", "Risk", "Controls", "Improvement"],
    focus: ["vulnerability", "fraud", "business_email_compromise", "open_web"],
    considerations: ["Risk treatment", "supplier control", "access control", "monitoring evidence"],
    evidenceFocus: ["control maturity", "findings evidence", "supplier/open web signals", "recommendations"],
    analysisUse: "Translate threat intelligence into ISMS control gaps, evidence needs and treatment priorities.",
    sourceLabel: "ISO/IEC 27001:2022 + Amendment 1:2024",
    sourceUrl: "https://www.iso.org/standard/88435.html",
    sourceDate: "2024"
  },
  {
    name: "PCI DSS",
    family: "Payments",
    domains: ["Network", "Data", "Access", "Monitoring", "Testing"],
    focus: ["fraud", "phishing", "account_takeover", "brand_impersonation"],
    considerations: ["Cardholder data exposure", "payment fraud", "credential access", "security testing"],
    evidenceFocus: ["fraud signals", "phishing records", "ATO mentions", "external payment surface"],
    analysisUse: "Identify payment-control impact when threat signals touch channels, accounts or customer data.",
    sourceLabel: "PCI DSS v4.0.1",
    sourceUrl: "https://www.pcisecuritystandards.org/document_library/",
    sourceDate: "2024-06"
  },
  {
    name: "SOC 2",
    family: "Trust",
    domains: ["Security", "Availability", "Confidentiality", "Privacy"],
    focus: ["open_web", "account_takeover", "business_email_compromise"],
    considerations: ["Trust service criteria", "availability exposure", "confidentiality impact", "privacy control evidence"],
    evidenceFocus: ["source reliability", "identity abuse", "service disruption", "data handling signals"],
    analysisUse: "Connect intelligence findings to trust criteria that matter for assurance and customer confidence.",
    sourceLabel: "AICPA Trust Services Criteria with Revised Points of Focus 2022",
    sourceUrl: "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    sourceDate: "2022"
  },
  {
    name: "GDPR",
    family: "Privacy",
    domains: ["Lawfulness", "Data rights", "Security", "Breach response"],
    focus: ["privacy", "leak", "fraud", "phishing"],
    considerations: ["Personal data exposure", "breach notification", "processor control", "data subject impact"],
    evidenceFocus: ["leak indicators", "privacy mentions", "phishing/social engineering", "breach-source records"],
    analysisUse: "Surface privacy and breach-response implications when open-source or dark-web evidence touches personal data.",
    sourceLabel: "Regulation (EU) 2016/679 - General Data Protection Regulation",
    sourceUrl: "https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng",
    sourceDate: "2016-04-27"
  },
  {
    name: "CIS Controls",
    family: "Controls",
    domains: ["Inventory", "Hardening", "Access", "Logging", "Response"],
    focus: ["vulnerability", "kev", "cve", "exploit_broker"],
    considerations: ["Asset inventory", "secure configuration", "patch priority", "logging and response"],
    evidenceFocus: ["CVE/KEV signals", "exploit patterns", "control score", "residual risk"],
    analysisUse: "Convert threat activity into concrete safeguard priorities for hardening, monitoring and response.",
    sourceLabel: "CIS Critical Security Controls v8.1",
    sourceUrl: "https://www.cisecurity.org/controls/v8-1",
    sourceDate: "2024-06"
  },
  {
    name: "MITRE ATT&CK",
    family: "Adversary behavior",
    domains: ["Initial access", "Execution", "Persistence", "Impact"],
    focus: ["ransomware", "phishing", "exploit_broker", "threat_intel"],
    considerations: ["Observed tactics", "mapped techniques", "coverage gaps", "example evidence"],
    evidenceFocus: ["technique_counts", "tactic coverage", "event technique", "source examples"],
    analysisUse: "Explain what adversary behavior is visible so detection and response can be prioritized by technique.",
    sourceLabel: "MITRE ATT&CK Enterprise v19.1",
    sourceUrl: "https://attack.mitre.org/resources/versions/",
    sourceDate: "2026-04-28"
  },
  {
    name: "MITRE D3FEND",
    family: "Defensive countermeasures",
    domains: ["Detect", "Harden", "Isolate", "Evict", "Restore"],
    focus: ["d3fend", "detect", "detection", "response", "hardening", "incident"],
    considerations: ["Countermeasure fit", "defensive tooling", "response action", "control uplift"],
    evidenceFocus: ["D3FEND rows", "ATT&CK mapped techniques", "samples", "recommended actions"],
    analysisUse: "Translate observed ATT&CK techniques into defensive actions and tool families.",
    sourceLabel: "MITRE D3FEND Ontology v1.4.0",
    sourceUrl: "https://d3fend.mitre.org/version/",
    sourceDate: "2026-03-31"
  },
  {
    name: "MITRE ATLAS",
    family: "AI system risk",
    domains: ["Model", "Agent", "Data", "Prompt", "Supply chain"],
    focus: ["ai", "artificial intelligence", "machine learning", "ml", "llm", "large language model", "model", "agent", "prompt", "atlas"],
    considerations: ["AI asset exposure", "prompt handling", "model supply chain", "agent autonomy"],
    evidenceFocus: ["AI/LLM matched signals", "ATLAS sections", "automation mentions", "supply-chain records"],
    analysisUse: "Review AI and automation risk only when explicit AI/model/agent/prompt signals are present.",
    sourceLabel: "MITRE ATLAS Data v5.6.0",
    sourceUrl: "https://github.com/mitre-atlas/atlas-data/releases/tag/v5.6.0",
    sourceDate: "2026-05-04"
  },
  {
    name: "MITRE F3",
    family: "Fraud behavior",
    domains: ["Reconnaissance", "Resource development", "Initial access", "Stealth", "Defense impairment", "Positioning", "Execution", "Monetization"],
    focus: ["fraud", "account_takeover", "brand_impersonation", "fake_domain", "phishing", "credential_stuffing"],
    considerations: ["Fraud actor behavior", "identity and transaction abuse", "impersonation infrastructure", "monetization path"],
    evidenceFocus: ["explicit F3 mappings", "assured current-run records", "fraud and brand evidence", "identity abuse signals"],
    analysisUse: "Map assured fraud-related evidence to official F3 tactics and techniques without treating a behavioral match as a confirmed fraud incident.",
    sourceLabel: "MITRE Fight Fraud Framework (F3) v1.1",
    sourceUrl: "https://ctid.mitre.org/fraud",
    sourceDate: "2026-06-23"
  },
  {
    name: "COBIT",
    family: "Governance",
    domains: ["Evaluate", "Align", "Build", "Deliver", "Monitor"],
    focus: ["risk", "governance", "open_web", "fraud"],
    considerations: ["Decision rights", "risk ownership", "performance monitoring", "assurance evidence"],
    evidenceFocus: ["strategic risk", "governance signals", "source coverage", "control maturity"],
    analysisUse: "Support board-level governance decisions by connecting intelligence signals to ownership and assurance.",
    sourceLabel: "COBIT 2019 - ISACA",
    sourceUrl: "https://www.isaca.org/resources/cobit",
    sourceDate: "2019"
  }
];

export function buildDashboardModel(run: RunRecord | undefined, filters: DashboardFilters): DashboardModel {
  const events = filterEvents(run?.summary.events ?? [], filters);
  const findings = run?.summary.findings ?? [];
  const statuses = run?.summary.source_statuses ?? [];
  const categories = topCounts(events.map(dashboardCategory));
  const actors = actorCounts(events, findings);
  const ttpImpact = buildTtpImpact(events, findings);
  const socmintEvents = events.filter(isSocmintEvent);
  const socmintNodes = buildSocmintNodes(socmintEvents);
  const socmintLinks = buildSocmintLinks(socmintEvents);
  const threatGraphNodes = buildThreatGraphNodes(events, actors, ttpImpact);
  const threatGraphLinks = buildThreatGraphLinks(threatGraphNodes, events);
  const strategicNews = objectMetric(run?.summary.metrics?.strategic_news);
  const strategicSnapshots = Array.isArray(strategicNews.snapshots) ? strategicNews.snapshots : [];
  return {
    trend: buildTrend(events, filters.dateRange),
    categories,
    actors,
    ttpImpact,
    attackActions: buildAttackActions(events, findings),
    affectedStates: buildAffectedStates(events, run, findings),
    regionalHeat: buildRegionalHeat(events, run),
    geographicCountries: buildGeographicCountries(events, run),
    sectorMatrix: buildSectorMatrix(run, findings, events),
    sourceFreshness: buildSourceFreshness(statuses),
    socmintNodes,
    socmintLinks,
    socmintAvailable: socmintEvents.length > 0,
    threatGraphNodes,
    threatGraphLinks,
    graphMetrics: buildGraphMetrics(events, threatGraphNodes, threatGraphLinks),
    frameworkMappings: buildFrameworkMappings(findings, events, run?.summary.metrics),
    postureIndex: numberMetric(run?.summary.metrics?.posture_index, 0),
    posturePoints: buildPosturePoints(run?.summary.metrics),
    pestel: buildStrategyLens("PESTEL", run?.summary.metrics?.pestel, noDataLens("PESTEL", "PESTEL requires report metrics generated by the analysis pipeline."), strategicSnapshots),
    porter: buildStrategyLens("Porter", run?.summary.metrics?.porter, noDataLens("Porter", "Porter requires report metrics generated by the analysis pipeline."), strategicSnapshots),
    riskHeatRows: buildRiskHeatRows(run?.summary.metrics?.risk_heat_radar, findings, events),
    platformMentions: buildPlatformMentions(socmintEvents),
    latestHeadlines: events.slice(0, 8),
    groupHeadlines: buildGroupHeadlines(events, filters, run?.summary.metrics),
    osintEvents: events.filter(isOsintEvent),
    darkwebEvents: events.filter(isDarkwebEvent),
    attackPrediction: buildAttackPrediction(run, events, findings),
    vulnerabilityIntel: buildVulnerabilityIntel(run?.summary.metrics),
    quantitativeRisk: buildQuantitativeRisk(run?.summary.metrics)
  };
}

function buildVulnerabilityIntel(metrics?: Record<string, unknown>): VulnerabilityIntelModel {
  const data = objectMetric(metrics?.vulnerability_intelligence);
  const rows = Array.isArray(data.rows) ? data.rows.slice(0, 8) : [];
  return {
    confirmedCves: Math.round(numberMetric(data.confirmed_cves, 0)),
    candidateCves: Math.round(numberMetric(data.candidate_cves, 0)),
    contextualCves: Math.round(numberMetric(data.contextual_cves, 0)),
    kevMatches: Math.round(numberMetric(data.kev_matches, 0)),
    publicExploitReferences: Math.round(numberMetric(data.public_exploit_references, 0)),
    cvssV4Records: Math.round(numberMetric(data.cvss_v4_records, 0)),
    observedTechnologies: Math.round(numberMetric(data.observed_technologies, 0)),
    surfaceAssets: Math.round(numberMetric(data.surface_assets, 0)),
    patchFocus: stringMetric(data.patch_focus, "Sin datos de vulnerabilidades en la corrida actual."),
    rows: rows.map((row) => {
      const item = objectMetric(row);
      return {
        type: stringMetric(item.type, "potential"),
        label: stringMetric(item.label, "n/a"),
        asset: stringMetric(item.asset, "scope"),
        status: stringMetric(item.status, "sin estado"),
        decision: stringMetric(item.decision, ""),
        cvssScore: optionalNumber(item.cvss_score),
        cvssVersion: stringMetric(item.cvss_version, ""),
        cvssVector: stringMetric(item.cvss_vector, ""),
        product: stringMetric(item.product, ""),
        observedVersion: stringMetric(item.observed_version, ""),
        affectedRange: stringMetric(item.affected_range, ""),
        applicabilityBasis: stringMetric(item.applicability_basis, ""),
        evidence_url: stringMetric(item.evidence_url, "")
      };
    })
  };
}

function buildQuantitativeRisk(metrics?: Record<string, unknown>): QuantitativeRiskModel {
  const layered = objectMetric(metrics?.layered_scenario_risk);
  const scenarios = Array.isArray(layered.scenarios) ? layered.scenarios : [];
  return {
    layered: {
      status: stringMetric(layered.status, "no_data"),
      currency: stringMetric(layered.currency, ""),
      scenarioCount: Math.round(numberMetric(layered.scenario_count, 0)),
      aggregateExpectedAnnualLoss: optionalNumber(layered.aggregate_expected_annual_loss),
      modelVersion: stringMetric(layered.model_version, "CDE-LAYERED-SCENARIO-1.0"),
      scenarios: scenarios.map((value) => {
        const item = objectMetric(value);
        const protectionLayers = Array.isArray(item.protection_layers) ? item.protection_layers : [];
        return {
          name: stringMetric(item.scenario_name, "Scenario"),
          resultingFrequency: numberMetric(item.resulting_event_frequency, 0),
          expectedAnnualLoss: numberMetric(item.expected_annual_loss, 0),
          riskReduction: numberMetric(item.relative_risk_reduction, 0),
          layerCount: protectionLayers.length
        };
      })
    }
  };
}

export function filterEvents(events: ThreatEvent[], filters: DashboardFilters): ThreatEvent[] {
  return events.filter((event) => {
    const text = `${event.title} ${event.source} ${event.actor ?? ""} ${(event.tags ?? []).join(" ")}`.toLowerCase();
    if (!matchesAny(filters.threatGroups, ALL_GROUPS, text)) return false;
    if (!matchesSource(filters.sourceModes, text)) return false;
    return true;
  });
}

function buildTrend(events: ThreatEvent[], range: string): TrendPoint[] {
  const size = range === "24h" ? 8 : range === "7d" ? 7 : range === "90d" ? 9 : range === "365d" ? 12 : 10;
  const buckets = Array.from({ length: size }, (_, index) => ({ label: labelFor(index, size, range), value: 0 }));
  const dates = events.map((event) => Date.parse(event.observed_at)).filter((value) => Number.isFinite(value));
  if (!dates.length) return buckets;
  const end = Math.max(...dates);
  const rangeMs = rangeToMs(range);
  const start = end - rangeMs;
  const bucketMs = rangeMs / size;
  dates.forEach((date) => {
    if (date < start) return;
    const bucketIndex = Math.min(size - 1, Math.max(0, Math.floor((date - start) / bucketMs)));
    buckets[bucketIndex].value += 1;
  });
  return buckets;
}

function labelFor(index: number, size: number, range: string): string {
  if (range === "24h") return `${index * 3}h`;
  if (range === "365d") return `M${index + 1}`;
  return `D${index + 1}`;
}

function rangeToMs(range: string): number {
  const day = 24 * 60 * 60 * 1000;
  if (range === "24h") return day;
  if (range === "7d") return 7 * day;
  if (range === "90d") return 90 * day;
  if (range === "365d") return 365 * day;
  return 30 * day;
}

function topCounts(values: string[]): RankedItem[] {
  const counts = new Map<string, number>();
  values.filter(Boolean).forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  const rows = Array.from(counts, ([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  return rows.slice(0, 8);
}

function actorCounts(events: ThreatEvent[], _findings: Finding[]): RankedItem[] {
  return topCounts(events.map((event) => explicitActor(event.actor)).filter(Boolean));
}

function explicitActor(value?: string | null): string {
  if (!value) return "";
  return ["unattributed", "unknown", "sin atribución", "no atribuido", "open_web", "public_web"].includes(
    value.toLowerCase()
  )
    ? ""
    : value;
}

function buildRegionalHeat(events: ThreatEvent[], run: RunRecord | undefined): RankedItem[] {
  const geographic = objectMetric(run?.summary.metrics?.geographic_intelligence);
  const supportedRows = Array.isArray(geographic.evidence_supported_countries)
    ? geographic.evidence_supported_countries
    : [];
  const supported = supportedRows
    .map((value) => {
      const row = objectMetric(value);
      const count = Math.round(numberMetric(row.records, 0));
      return {
        name: stringMetric(row.country, ""),
        value: count,
        tone: toneForCount(count)
      };
    })
    .filter((item) => item.name && item.value > 0);
  if (supported.length) return supported;
  const explicitLocations = topCounts(events.flatMap(extractLocations));
  return explicitLocations.map((item) => ({ ...item, tone: toneForCount(item.value) }));
}

function buildGeographicCountries(events: ThreatEvent[], run: RunRecord | undefined): GeographicCountryItem[] {
  const geographic = objectMetric(run?.summary.metrics?.geographic_intelligence);
  const rows = Array.isArray(geographic.country_inventory) ? geographic.country_inventory : [];
  const inventory = rows
    .map((value) => {
      const row = objectMetric(value);
      const status = stringMetric(row.status, "mention_only");
      return {
        name: stringMetric(row.country, ""),
        code: stringMetric(row.code, ""),
        records: Math.max(0, Math.round(numberMetric(row.records, 0))),
        declared: Boolean(row.declared),
        status: (
          ["declared_scope", "declared_and_mentioned", "mention_only", "supported_operational_context"].includes(status)
            ? status
            : "mention_only"
        ) as GeographicCountryItem["status"]
      };
    })
    .filter((item) => item.name);
  if (inventory.length) return inventory;
  return buildRegionalHeat(events, run).map((item) => ({
    name: item.name,
    code: "",
    records: item.value,
    declared: false,
    status: "mention_only"
  }));
}

function buildSectorMatrix(run: RunRecord | undefined, findings: Finding[], events: ThreatEvent[]): RankedItem[] {
  const sectorIntelligence = objectMetric(run?.summary.metrics?.sector_intelligence);
  const supportedRows = Array.isArray(sectorIntelligence.evidence_supported_sectors)
    ? sectorIntelligence.evidence_supported_sectors
    : [];
  const supported = supportedRows
    .map((value) => {
      const row = objectMetric(value);
      const count = Math.round(numberMetric(row.records, 0));
      return {
        name: stringMetric(row.sector, ""),
        value: count,
        tone: toneForCount(count)
      };
    })
    .filter((item) => item.name && item.value > 0)
    .slice(0, 8);
  if (supported.length) return supported;

  const sector = run?.request?.sector?.trim();
  const maxRisk = Math.max(...findings.map((finding) => finding.residual_risk), 0);
  const kpiRisk = run?.summary.kpis.max_residual_risk ?? 0;
  const signalCount = events.length || run?.summary.kpis.new_events || 0;
  const value = maxRisk || kpiRisk || signalCount;
  if (!value) return [];
  if (sector) {
    return [{ name: formatScopeName(sector), value: Math.round(value), tone: maxRisk || kpiRisk ? toneForExposure(value * 3) : toneForCount(value) }];
  }
  const inferred = inferEconomicSectors(events, findings);
  return inferred.map((item) => ({ ...item, value: Math.max(item.value, Math.round(value / Math.max(1, inferred.length))) })).slice(0, 4);
}

function buildSourceFreshness(statuses: SourceStatus[]): number {
  if (!statuses.length) return 0;
  const ok = statuses.filter((status) => status.status === "ok").length;
  return Math.round((ok / statuses.length) * 100);
}

function buildGraphMetrics(events: ThreatEvent[], nodes: SocmintNode[], links: SocmintLink[]): GraphMetric[] {
  if (!events.length || !nodes.length) {
    return [
      { label: "Connected signals", value: "0", helper: "No relationships mapped", tone: "low" },
      { label: "Narrative clusters", value: "0", helper: "No active cluster", tone: "low" },
      { label: "Decision confidence", value: "0%", helper: "No graph density", tone: "low" }
    ];
  }
  const topics = nodes.filter((node) => node.group === "topic" || node.group === "mention");
  const strongest = topics.sort((left, right) => right.size - left.size)[0]?.label ?? "pending";
  const density = Math.min(100, Math.round((links.length / Math.max(1, nodes.length * 2)) * 100));
  const confidence = Math.min(96, Math.max(42, events.length * 2 + links.length * 3 + 34));
  return [
    {
      label: "Connected signals",
      value: `${nodes.length}`,
      helper: `${links.length} relationships mapped`,
      tone: "low"
    },
    {
      label: "Narrative clusters",
      value: `${topics.length}`,
      helper: `Strongest: ${strongest}`,
      tone: density > 55 ? "high" : "medium"
    },
    {
      label: "Decision confidence",
      value: `${confidence}%`,
      helper: `${density}% graph density`,
      tone: confidence > 78 ? "high" : "medium"
    }
  ];
}

function buildFrameworkMappings(findings: Finding[], events: ThreatEvent[], metrics: Record<string, unknown> | undefined): FrameworkMappingItem[] {
  const controlScores = objectMetric(metrics?.control_scores);
  const backendMapping = objectMetric(metrics?.framework_mapping);
  const backendRows = Array.isArray(backendMapping.mappings) ? backendMapping.mappings.map((item) => objectMetric(item)) : [];

  return frameworkCatalog.map((framework) => {
    const axisMappings = backendRows.length
      ? backendRows.filter((row) => stringMetric(row.framework, "") === framework.name).map(parseFrameworkAxisMapping)
      : deriveFrameworkAxisMappings(framework, events, findings);
    const recordCount = new Set(axisMappings.flatMap((item) => item.evidence.map((evidence) => evidence.evidenceId))).size;
    const validatedCount = new Set(
      axisMappings.flatMap((item) => item.evidence.filter((evidence) => ["validated", "confirmed"].includes(evidence.status)).map((evidence) => evidence.evidenceId))
    ).size;
    const directCount = new Set(
      axisMappings.flatMap((item) => item.evidence.filter((evidence) => evidence.status === "direct").map((evidence) => evidence.evidenceId))
    ).size;
    const hasFrameworkEvidence = recordCount > 0;
    const exposure = recordCount;
    const coverageValue = frameworkCoverage(framework.name, controlScores);
    const coverage = coverageValue === null ? 0 : Math.round(coverageValue * 100);
    const tone = validatedCount > 0 ? "high" : directCount > 0 ? "medium" : recordCount > 0 ? "low" : "low";
    const mappedAxes = axisMappings.map((item) => item.axis.replace(/_/g, " "));
    return {
      name: framework.name,
      family: framework.family,
      domains: framework.domains,
      affectedAspects: hasFrameworkEvidence ? mappedAxes : ["No active evidence"],
      considerations: framework.considerations,
      evidenceFocus: axisMappings.flatMap((item) => item.evidence.map((evidence) => evidence.title)).slice(0, 8),
      analysisUse: framework.analysisUse,
      sourceLabel: framework.sourceLabel,
      sourceUrl: framework.sourceUrl,
      sourceDate: framework.sourceDate,
      exposure,
      coverage,
      coverageAssessed: coverageValue !== null,
      tone,
      decision: hasFrameworkEvidence
        ? `${recordCount} current-run record(s); ${validatedCount} validated and ${directCount} direct. Review linked evidence before deciding control treatment.`
        : "No active evidence",
      recordCount,
      validatedCount,
      directCount,
      axisMappings
    };
  });
}

function parseFrameworkAxisMapping(raw: Record<string, unknown>): FrameworkAxisMapping {
  const evidenceRows = Array.isArray(raw.evidence) ? raw.evidence.map((item) => objectMetric(item)) : [];
  return {
    axis: stringMetric(raw.axis, "unmapped"),
    controls: stringList(raw.controls),
    recordCount: Math.round(numberMetric(raw.record_count, evidenceRows.length)),
    validatedCount: Math.round(numberMetric(raw.validated_count, 0)),
    directCount: Math.round(numberMetric(raw.direct_count, 0)),
    relatedCount: Math.round(numberMetric(raw.related_count, 0)),
    findingCount: Math.round(numberMetric(raw.finding_count, 0)),
    domains: stringList(raw.domains),
    evidence: evidenceRows.map((item) => ({
      evidenceId: stringMetric(item.evidence_id, stringMetric(item.url, "evidence")),
      title: stringMetric(item.title, stringMetric(item.url, "Evidence")),
      url: stringMetric(item.url, ""),
      source: stringMetric(item.source, ""),
      status: stringMetric(item.evidence_status, "raw"),
      relationship: stringMetric(item.relationship, "unassessed"),
      domain: stringMetric(item.domain, ""),
      observedAt: stringMetric(item.observed_at, "")
    }))
  };
}

function deriveFrameworkAxisMappings(
  framework: (typeof frameworkCatalog)[number],
  events: ThreatEvent[],
  findings: Finding[]
): FrameworkAxisMapping[] {
  const axes = [
    { axis: "governance", terms: ["govern", "risk", "legal", "regulat", "policy", "audit"] },
    { axis: "identity", terms: ["identity", "credential", "account", "login", "password", "mfa", "session", "bec"] },
    { axis: "protect", terms: ["protect", "hardening", "configuration", "encryption", "backup", "recover"] },
    { axis: "detect", terms: ["detect", "monitor", "logging", "telemetry", "alert", "indicator"] },
    { axis: "response", terms: ["incident", "respond", "response", "contain", "recover", "takedown"] },
    { axis: "privacy", terms: ["privacy", "personal data", "pii", "confidential", "breach", "gdpr"] },
    { axis: "vulnerability", terms: ["vulnerab", "cve-", "kev", "exploit", "patch", "exposure", "surface"] },
    { axis: "fraud", terms: ["fraud", "phish", "scam", "estafa", "suplant", "imperson", "fake job", "empleo falso"] },
    { axis: "ai", terms: ["artificial intelligence", "machine learning", "llm", "prompt", "model", "agent", "atlas"] },
    { axis: "adversary", terms: ["attack", "ransom", "malware", "campaign", "campaña", "actor", "apt", "ttp"] }
  ];
  const frameworkText = normalizeDashboardText([framework.name, framework.family, ...framework.domains, ...framework.focus, ...framework.considerations].join(" "));
  return axes.flatMap(({ axis, terms }) => {
    if (!terms.some((term) => frameworkText.includes(term))) return [];
    const related = events.filter((event) => event.evidence_url && terms.some((term) => eventText(event).toLowerCase().includes(term)));
    if (!related.length) return [];
    const evidence = related.map((event) => ({
      evidenceId: event.canonical_id || event.id,
      title: event.title,
      url: event.evidence_url || "",
      source: event.source,
      status: event.evidence_status || "raw",
      relationship: event.relationship_to_scope || "unassessed",
      domain: event.host || event.asset || "",
      observedAt: event.observed_at
    }));
    return [{
      axis,
      controls: framework.domains.filter((domain) => terms.some((term) => normalizeDashboardText(domain).includes(term))).slice(0, 5),
      recordCount: evidence.length,
      validatedCount: evidence.filter((item) => ["validated", "confirmed"].includes(item.status)).length,
      directCount: evidence.filter((item) => item.status === "direct").length,
      relatedCount: evidence.filter((item) => !["direct", "validated", "confirmed"].includes(item.status)).length,
      findingCount: findings.filter((finding) => terms.some((term) => `${finding.title} ${finding.category}`.toLowerCase().includes(term))).length,
      domains: [...new Set(evidence.map((item) => item.domain).filter(Boolean))],
      evidence: evidence.slice(0, 12)
    }];
  });
}

function buildPosturePoints(metrics: Record<string, unknown> | undefined): PosturePoint[] {
  const controlScores = objectMetric(metrics?.control_scores);
  return Object.entries(controlScores).map(([name, rawValue]) => {
    const value = Math.round(numberMetric(rawValue, 0) * 100);
    return { name, value, tone: toneForExposure(100 - value) };
  });
}

function buildStrategyLens(title: string, raw: unknown, fallback: StrategyLens, snapshotsRaw: unknown[] = []): StrategyLens {
  const data = objectMetric(raw);
  const dimensionsRaw = Array.isArray(data.dimensions) ? data.dimensions : [];
  const dimensions = dimensionsRaw
    .map((item) => objectMetric(item))
    .map((item) => {
      const eventRows = [...(Array.isArray(item.drivers) ? item.drivers : []), ...(Array.isArray(item.reducers) ? item.reducers : [])]
        .map((event) => objectMetric(event))
        .map((event) => ({
          id: stringMetric(event.cluster_id, stringMetric(event.what_happened, "strategic-event")),
          title: stringMetric(event.what_happened, ""),
          relationship: stringMetric(event.relationship, "unassessed"),
          direction: stringMetric(event.direction, "indeterminate"),
          magnitude: stringMetric(event.magnitude, "unassessed"),
          mappingReason: stringMetric(event.mapping_reason, ""),
          evidenceUrls: Array.isArray(event.evidence_urls) ? event.evidence_urls.filter((value): value is string => typeof value === "string") : []
        }));
      const calculation = objectMetric(item.calculation);
      return {
        name: stringMetric(item.displayName, stringMetric(item.name, "Dimension")),
        shortName: stringMetric(item.shortName, stringMetric(item.name, "Dimension")),
        key: stringMetric(item.key, "unknown"),
        score: typeof item.score === "number" && Number.isFinite(item.score) ? Math.round(item.score) : null,
        signalScore: typeof item.signalScore === "number" && Number.isFinite(item.signalScore) ? Math.round(item.signalScore * 10) / 10 : typeof item.signal_score === "number" && Number.isFinite(item.signal_score) ? Math.round(item.signal_score * 10) / 10 : null,
        validatedPressure: typeof item.validatedPressure === "number" && Number.isFinite(item.validatedPressure) ? Math.round(item.validatedPressure * 10) / 10 : null,
        confidence: Math.round(numberMetric(item.confidence, 0)),
        evidenceCoverage: Math.round(numberMetric(item.evidence_coverage_percent, 0) * 100) / 100,
        status: stringMetric(item.status, "insufficient_evidence"),
        delta: typeof item.delta === "number" && Number.isFinite(item.delta) ? Math.round(item.delta * 10) / 10 : null,
        clusterCount: Math.round(numberMetric(item.cluster_count, 0)),
        independentSourceCount: Math.round(numberMetric(item.independent_source_count, 0)),
        directCount: Math.round(numberMetric(item.direct_count, 0)),
        groupCount: Math.round(numberMetric(item.group_count, 0)),
        sectorCount: Math.round(numberMetric(item.sector_count, 0)),
        why: stringMetric(item.why, ""),
        decision: stringMetric(item.decision, ""),
        whatChanged: stringMetric(item.what_changed, ""),
        evidenceUrls: Array.isArray(item.evidence_urls) ? item.evidence_urls.filter((value): value is string => typeof value === "string") : [],
        events: eventRows,
        calculation: {
          evidenceMass: numberMetric(calculation.evidence_mass, 0),
          directionIndex: typeof calculation.direction_index === "number" && Number.isFinite(calculation.direction_index) ? calculation.direction_index : null,
          sourceDiversity: numberMetric(calculation.source_diversity, 0),
          weightedDirectness: numberMetric(calculation.weighted_directness, 0),
          directionAgreement: numberMetric(calculation.direction_agreement, 0),
          extractionQuality: numberMetric(calculation.extraction_quality, 0),
          contributionCount: Math.round(numberMetric(calculation.contribution_count, 0)),
          publicationGatePassed: Boolean(calculation.publication_gate_passed)
        }
      };
    })
    .filter((item) => item.name);
  if (!dimensions.length) return fallback;
  const modelKey = title.toLowerCase();
  const analysisBasisRaw = objectMetric(data.analysisBasis);
  const analysisContextRaw = objectMetric(analysisBasisRaw.context);
  const analysisContext = Object.fromEntries(
    Object.entries(analysisContextRaw).map(([key, value]) => [
      key,
      Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())) : []
    ])
  );
  const snapshots = snapshotsRaw
    .map((item) => objectMetric(item))
    .filter((item) => stringMetric(item.model, "").toLowerCase() === modelKey && stringMetric(item.period, "current") === "current")
    .map((item) => ({
      windowDays: Math.round(numberMetric(item.window_days, 0)),
      score: typeof item.score === "number" && Number.isFinite(item.score) ? Math.round(item.score * 10) / 10 : null,
      confidence: Math.round(numberMetric(item.confidence, 0)),
      coverageRatio: numberMetric(item.coverage_ratio, 0),
      status: stringMetric(item.assessment_status, "insufficient_evidence")
    }))
    .filter((item) => item.windowDays > 0)
    .sort((left, right) => left.windowDays - right.windowDays);
  return {
    title,
    index: typeof data.signalScore === "number" && Number.isFinite(data.signalScore) ? Math.round(data.signalScore * 10) / 10 : typeof data.signal_score === "number" && Number.isFinite(data.signal_score) ? Math.round(data.signal_score * 10) / 10 : null,
    overallConfidence: Math.round(numberMetric(data.overall_confidence, 0)),
    coverageRatio: numberMetric(data.coverage_ratio, 0),
    evidenceCoverageRatio: numberMetric(data.evidence_coverage_ratio, numberMetric(data.coverage_ratio, 0)),
    clusterCount: Math.round(numberMetric(data.cluster_count, 0)),
    articleCount: Math.round(numberMetric(data.article_count, 0)),
    meaning: stringMetric(data.interpretation, fallback.meaning),
    dimensions,
    assessmentStatus: stringMetric(data.assessment_status, "unassessed"),
    isRiskScore: Boolean(data.is_risk_score),
    signalCount: Math.round(numberMetric(data.signal_count, 0)),
    snapshots,
    analysisBasis: {
      declaredContextCoverage: numberMetric(analysisBasisRaw.declared_context_coverage, 0),
      historicalEvidenceReused: Boolean(analysisBasisRaw.historical_evidence_reused),
      context: analysisContext
    }
  };
}

function buildRiskHeatRows(raw: unknown, findings: Finding[], events: ThreatEvent[]): RiskHeatRow[] {
  const data = objectMetric(raw);
  const rowsRaw = Array.isArray(data.rows) ? data.rows : [];
  const rows = rowsRaw
    .map((item) => objectMetric(item))
    .map((item) => ({
      index: Math.round(numberMetric(item.index, 0)),
      name: stringMetric(item.name, "Risk"),
      score: numberMetric(item.score, 0),
      heat: heatTone(stringMetric(item.heat, "low")),
      evidenceCount: Math.round(numberMetric(item.evidence_count, 0)),
      maxResidualRisk: numberMetric(item.max_residual_risk, 0),
      decision: stringMetric(item.decision, "")
    }));
  if (rows.length) return rows;

  return findings.slice(0, 8).map((finding, index) => ({
    index: index + 1,
    name: finding.category,
    score: clamp(finding.residual_risk / 40, 0, 1),
    heat: toneForExposure(finding.residual_risk * 3),
    evidenceCount: events.filter((event) => event.category === finding.category).length,
    maxResidualRisk: finding.residual_risk,
    decision: finding.recommendations[0] ?? "Prioritize validation"
  }));
}

function buildAttackPrediction(run: RunRecord | undefined, events: ThreatEvent[], findings: Finding[]): AttackPredictionModel {
  const metrics = objectMetric(run?.summary.metrics);
  const prospective = objectMetric(metrics.prospective_attack_risk);
  if (String(prospective.model_type ?? "") === "prospective_signal_pressure") {
    return buildProspectiveAttackPrediction(run, prospective, events);
  }
  const forecast30 = numberMetric(objectMetric(objectMetric(metrics.forecast)["30"]).signal_pressure_index, NaN);
  const analyticEvents = events.filter((event) =>
    !event.evidence_status || ["direct", "validated", "confirmed"].includes(event.evidence_status)
  );
  const weightedEvents = recencyWeightedEvents(analyticEvents);
  const frequency = clamp(weightedEvents / 24, 0, 1);
  const recent = clamp(analyticEvents.filter((event) => eventAgeDays(event) <= 7).length / Math.max(1, analyticEvents.length), 0, 1);
  const applicableVulnerabilities = analyticEvents.filter((event) =>
    ["cve_applicable", "confirmed", "kev_applicable"].includes(event.vulnerability_status ?? "")
  );
  const kev = clamp(applicableVulnerabilities.length / 18, 0, 1);
  const inferredSector = run?.request?.sector || inferEconomicSectors(analyticEvents, findings)[0]?.name;
  const sector = sectorWeight(inferredSector);
  const socmint = clamp(analyticEvents.filter(isSocmintEvent).length / 12, 0, 1);
  const darkweb = clamp(analyticEvents.filter(isDarkwebEvent).length / 6, 0, 1);
  const riskHeat = Math.max(...buildRiskHeatRows(metrics.risk_heat_radar, findings, analyticEvents).map((row) => row.score), 0);
  const w = predictionModelWeights;
  const signalRateDaily = Math.max(
    0,
    w.alpha * w.previousDailyLambda +
      (1 - w.alpha) * w.baselineDailyLambda +
      w.frequency * frequency +
      w.recency * recent +
      w.kev * kev +
      w.sector * sector +
      w.socmint * socmint +
      w.darkweb * darkweb +
      w.riskHeat * riskHeat
  );
  const pressure7d = pressureIndex(signalRateDaily, 7);
  const pressure14d = pressureIndex(signalRateDaily, 14);
  const pressure30d = Number.isFinite(forecast30) ? clamp(forecast30, 0, 1) : pressureIndex(signalRateDaily, 30);
  const scenarios = buildPredictionScenarios(run, analyticEvents, pressure30d, inferredSector);
  const evidenceConfidence = analyticEvents.length
    ? clamp(Math.round((0.25 + Math.min(0.45, analyticEvents.length / 180) + Math.min(0.2, weightedEvents / 80) + Math.min(0.1, findings.length / 20)) * 100), 0, 95)
    : 0;
  return {
    status: analyticEvents.length ? "legacy_fallback" : "insufficient_evidence",
    pressure7d,
    pressure14d,
    pressure30d,
    pressure90d: pressureIndex(signalRateDaily, 90),
    signalRateDaily,
    evidenceConfidence,
    calibrated: false,
    probabilityValue: null,
    probabilityStatus: "not_calibrated",
    trendDirection: "insufficient_evidence",
    trendChangeRatio: null,
    modelVersion: "legacy-frontend-fallback",
    leadingScenario: scenarios[0],
    drivers: [
      { name: "Frequency", value: Math.round(frequency * 100), explanation: `${analyticEvents.length} direct or validated signals, recency weighted ${weightedEvents.toFixed(1)}` },
      { name: "Last days", value: Math.round(recent * 100), explanation: "Share of signals observed during the last 7 days" },
      { name: "KEV / CVE", value: Math.round(kev * 100), explanation: "Exploit, vulnerability, KEV or CVE evidence density" },
      { name: "Sector", value: Math.round(sector * 100), explanation: inferredSector ?? "Current analysis sector not declared or inferred" },
      { name: "SOCMINT", value: Math.round(socmint * 100), explanation: "Public social signal pressure" },
      { name: "Dark Web", value: Math.round(darkweb * 100), explanation: "Authorized dark web or ransomware-index signal pressure" },
      { name: "Risk heat", value: Math.round(riskHeat * 100), explanation: "Highest risk heat row from the report" },
    ],
    scenarios,
    methodology: "Non-calibrated signal-pressure index based on direct or validated evidence, recency, applicable vulnerabilities, declared sector context, SOCMINT, Dark Web and calculated risk. It is not an attack probability."
  };
}

function buildProspectiveAttackPrediction(
  run: RunRecord | undefined,
  prospective: Record<string, unknown>,
  events: ThreatEvent[]
): AttackPredictionModel {
  const horizons = objectMetric(prospective.horizons);
  const horizonValue = (days: string) =>
    clamp(numberMetric(objectMetric(horizons[days]).signal_pressure_index, 0), 0, 1);
  const eventById = new Map<string, ThreatEvent>();
  events.forEach((event) => {
    eventById.set(event.id, event);
    if (event.canonical_id) eventById.set(event.canonical_id, event);
  });
  const rawDrivers = Array.isArray(prospective.drivers) ? prospective.drivers : [];
  const drivers = rawDrivers.map((raw) => {
    const driver = objectMetric(raw);
    return {
      name: String(driver.name ?? ""),
      value: Math.round(clamp(numberMetric(driver.value, 0), 0, 1) * 100),
      explanation: String(driver.explanation ?? "")
    };
  }).filter((driver) => driver.name);
  const rawScenarios = Array.isArray(prospective.scenarios) ? prospective.scenarios : [];
  const scenarios = rawScenarios.map((raw) => {
    const scenario = objectMetric(raw);
    const evidenceIds = Array.isArray(scenario.evidence_ids)
      ? scenario.evidence_ids.map((value) => String(value))
      : [];
    const evidence = evidenceIds
      .map((id) => eventById.get(id))
      .filter((event): event is ThreatEvent => Boolean(event));
    const explicitActors = evidence
      .map((event) => event.actor)
      .filter((actor): actor is string => Boolean(actor && !["unknown", "unattributed"].includes(actor.toLowerCase())));
    const explicitTechniques = evidence
      .map((event) => event.technique)
      .filter((technique): technique is string => Boolean(technique));
    return {
      id: String(scenario.id ?? ""),
      modality: String(scenario.modality ?? ""),
      technique: explicitTechniques[0] ?? "N/D",
      group: explicitActors[0] ?? "N/D",
      sector: run?.request?.sector || "N/D",
      supportScore: clamp(numberMetric(scenario.support_score, 0), 0, 1),
      evidenceCount: Math.max(0, Math.round(numberMetric(scenario.evidence_count, evidence.length))),
      sourceCount: Math.max(0, Math.round(numberMetric(scenario.source_count, 0))),
      decision: String(scenario.decision ?? ""),
      evidence,
      status: String(scenario.status ?? "candidate")
    };
  }).filter((scenario) => scenario.modality && scenario.evidenceCount > 0);
  const trend = objectMetric(prospective.trend);
  const trendDirection = String(trend.direction ?? "insufficient_evidence");
  const probability = objectMetric(prospective.attack_probability);
  const status = String(prospective.status ?? "insufficient_evidence") === "assessed"
    ? "assessed"
    : "insufficient_evidence";
  return {
    status,
    pressure7d: horizonValue("7"),
    pressure14d: horizonValue("14"),
    pressure30d: horizonValue("30"),
    pressure90d: horizonValue("90"),
    signalRateDaily: Math.max(0, numberMetric(prospective.daily_signal_rate, 0)),
    evidenceConfidence: clamp(numberMetric(prospective.evidence_confidence, 0), 0, 100),
    calibrated: false,
    probabilityValue: typeof probability.value === "number" ? probability.value : null,
    probabilityStatus: String(probability.status ?? "not_calibrated"),
    trendDirection: ["rising", "stable", "falling"].includes(trendDirection)
      ? trendDirection as "rising" | "stable" | "falling"
      : "insufficient_evidence",
    trendChangeRatio: typeof trend.change_ratio === "number" ? trend.change_ratio : null,
    modelVersion: String(prospective.model_version ?? "unknown"),
    leadingScenario: scenarios[0],
    drivers,
    scenarios,
    methodology: "Índice prospectivo de presión de señales sustentado exclusivamente en evidencia directa, validada o confirmada. No representa una probabilidad calibrada de ataque."
  };
}

function buildPredictionScenarios(run: RunRecord | undefined, events: ThreatEvent[], pressure30d: number, inferredSector?: string): PredictionScenario[] {
  if (!events.length) return [];
  const sector = run?.request?.sector || inferredSector || "current sector";
  const scored = predictionModes.map((mode) => {
    const evidence = events.filter((event) => {
      const text = eventText(event);
      return mode.keywords.some((keyword) => keywordMatches(text, keyword)) || text.includes(mode.technique.toLowerCase().split(" ")[0]);
    });
    const weighted = recencyWeightedEvents(evidence);
    const actor = topCounts(evidence.map((event) => explicitActor(event.actor)).filter(Boolean))[0]?.name ?? "unattributed";
    const score = weighted * 0.62 + evidence.length * 0.22 + mode.baseWeight * 10 + sectorWeight(sector) * 2;
    return { mode, evidence, actor, score };
  });
  const maxScore = Math.max(...scored.map((item) => item.score), 1);
  return scored
    .map(({ mode, evidence, actor, score }) => ({
      modality: mode.label,
      technique: mode.technique,
      group: actor,
      sector,
      supportScore: evidence.length ? clamp(pressure30d * (score / maxScore), 0, 0.95) : 0,
      evidenceCount: evidence.length,
      decision: mode.decision,
      evidence: evidence.slice(0, 3)
    }))
    .filter((scenario) => scenario.evidenceCount > 0)
    .sort((left, right) => right.supportScore - left.supportScore)
    .slice(0, 6);
}

function pressureIndex(signalRateDaily: number, days: number): number {
  return clamp(1 - Math.exp(-Math.max(0, signalRateDaily) * Math.max(0, days)), 0, 1);
}

function recencyWeightedEvents(events: ThreatEvent[]): number {
  return events.reduce((sum, event) => sum + Math.exp(-eventAgeDays(event) / 14), 0);
}

function eventAgeDays(event: ThreatEvent): number {
  const observed = Date.parse(event.observed_at);
  if (!Number.isFinite(observed)) return 30;
  const latest = Date.now();
  return Math.max(0, (latest - observed) / (24 * 60 * 60 * 1000));
}

function sectorWeight(value: string | undefined): number {
  const key = (value ?? "default").toLowerCase();
  return sectorPredictionWeights[key] ?? sectorPredictionWeights.default;
}

function inferEconomicSectors(events: ThreatEvent[], findings: Finding[]): RankedItem[] {
  const text = [
    ...events.map(eventText),
    ...findings.map((finding) => `${finding.title} ${finding.category} ${finding.evidence.join(" ")} ${finding.recommendations.join(" ")}`)
  ].join(" ").toLowerCase();
  const catalog: Array<{ name: string; keywords: string[] }> = [
    { name: "Financial and insurance activities", keywords: ["bank", "financial", "fintech", "payment", "wallet", "insurance", "fraud", "transaction"] },
    { name: "Information and communication", keywords: ["api", "cloud", "saas", "telecom", "software", "platform", "app", "hosting"] },
    { name: "Wholesale and retail trade; repair of motor vehicles and motorcycles", keywords: ["retail", "commerce", "store", "ecommerce", "customer", "merchant"] },
    { name: "Manufacturing", keywords: ["manufacturing", "factory", "industrial", "supply chain", "ot", "iot"] },
    { name: "Transportation and storage", keywords: ["transport", "logistics", "shipping", "fleet", "port"] },
    { name: "Human health and social work activities", keywords: ["health", "hospital", "patient", "medical", "clinic"] },
    { name: "Public administration and defence; compulsory social security", keywords: ["government", "public", "defence", "ministry", "municipal"] },
    { name: "Education", keywords: ["education", "university", "student", "school"] },
    { name: "Electricity, gas, steam and air conditioning supply", keywords: ["energy", "electric", "gas", "utility", "grid"] },
    { name: "Professional, scientific and technical activities", keywords: ["consulting", "legal", "research", "professional", "technical"] }
  ];
  return catalog
    .map((sector) => ({
      name: sector.name,
      value: sector.keywords.reduce((sum, keyword) => sum + (text.includes(keyword) ? 1 : 0), 0),
      tone: "medium" as const
    }))
    .filter((item) => item.value > 0)
    .sort((left, right) => right.value - left.value);
}

function noDataLens(title: string, meaning: string): StrategyLens {
  return {
    title,
    index: null,
    overallConfidence: 0,
    coverageRatio: 0,
    evidenceCoverageRatio: 0,
    clusterCount: 0,
    articleCount: 0,
    meaning,
    dimensions: [],
    assessmentStatus: "unassessed",
    isRiskScore: false,
    signalCount: 0,
    snapshots: []
  };
}

function affectedAspectsFor(frameworkName: string, focus: string[], signalText: string): string[] {
  const base: Record<string, string[]> = {
    "NIST CSF": ["Governance", "Asset visibility", "Detection", "Response", "Recovery"],
    "ISO 27001": ["Risk treatment", "Supplier control", "Access control", "Evidence", "Improvement"],
    "PCI DSS": ["Cardholder data", "Access", "Monitoring", "Vulnerability management", "Testing"],
    "SOC 2": ["Security", "Availability", "Confidentiality", "Privacy", "Processing integrity"],
    GDPR: ["Personal data", "Lawful basis", "Breach notification", "Data subject rights", "Processor control"],
    "CIS Controls": ["Inventory", "Secure configuration", "Logging", "Malware defenses", "Incident response"],
    "MITRE ATT&CK": ["Initial access", "Execution", "Persistence", "Credential access", "Impact"],
    "MITRE D3FEND": ["Detection engineering", "Hardening", "Isolation", "Response playbooks", "Recovery controls"],
    "MITRE ATLAS": ["AI model exposure", "Prompt handling", "Training data", "Agent autonomy", "AI supply chain"],
    COBIT: ["Governance", "Risk ownership", "Performance", "Assurance", "Decision rights"]
  };
  const signals = focus.filter((keyword) => keywordMatches(signalText, keyword)).map(formatAspectSignal);
  return [...signals, ...(base[frameworkName] ?? [])].slice(0, 6);
}

function formatAspectSignal(keyword: string): string {
  const label = keyword.replace(/_/g, " ");
  const acronyms: Record<string, string> = {
    ai: "AI",
    ml: "ML",
    llm: "LLM"
  };
  return acronyms[label] ?? label;
}

function frameworkEvidenceFor(
  name: string,
  hasEvidence: boolean,
  focusHits: number,
  mitre: Record<string, unknown>,
  d3fend: Record<string, unknown>,
  atlas: Record<string, unknown>
): boolean {
  if (!hasEvidence) return false;
  if (name === "MITRE ATT&CK") {
    const techniqueCounts = objectMetric(mitre.technique_counts);
    const mappedTechniques = Object.entries(techniqueCounts).filter(([technique, count]) => technique !== "unmapped" && numberMetric(count, 0) > 0);
    if (Object.keys(mitre).length) return numberMetric(mitre.coverage_count, 0) > 0 || mappedTechniques.length > 0;
    return focusHits > 0;
  }
  if (name === "MITRE D3FEND") {
    const rows = Array.isArray(d3fend.rows) ? d3fend.rows : [];
    if (Object.keys(d3fend).length) return rows.length > 0;
    return focusHits > 0;
  }
  if (name === "MITRE ATLAS") {
    const matchedSignals = Array.isArray(atlas.matched_signals) ? atlas.matched_signals : [];
    return matchedSignals.length > 0 || focusHits > 0;
  }
  return true;
}

function keywordMatches(text: string, keyword: string): boolean {
  const needle = keyword.toLowerCase();
  if (needle.includes("_")) return text.includes(needle);
  return new RegExp(`\\b${escapeRegex(needle)}\\b`, "i").test(text);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function buildDomainEvidence(run: RunRecord | undefined, events: ThreatEvent[] = run?.summary.events ?? []): DomainEvidenceItem[] {
  const domains = Array.from(new Set([...(run?.domains ?? []), ...(run?.request?.domains ?? [])])).filter(Boolean);
  return domains
    .map((domain) => {
      const matches = events.filter((event) => eventText(event).includes(domain.toLowerCase()));
      return {
        domain,
        signals: matches.length,
        sources: Array.from(new Set(matches.map((event) => event.source))).slice(0, 4),
        categories: topCounts(matches.map((event) => event.category)).map((item) => item.name).slice(0, 4),
        latest: matches[0]
      };
    })
    .filter((item) => item.signals > 0);
}

export function buildExposureAudit(
  run: RunRecord | undefined,
  events: ThreatEvent[] = run?.summary.events ?? [],
  channel: "osint" | "socmint" = "osint"
): ExposureAuditItem[] {
  const domains = Array.from(new Set([...(run?.domains ?? []), ...(run?.request?.domains ?? [])])).filter(Boolean);
  const templates = channel === "socmint" ? socmintAuditTemplates : osintAuditTemplates;
  return domains.flatMap((domain) =>
    templates.map((template) => {
      const matches = events.filter((event) => {
        const text = eventText(event);
        return text.includes(domain.toLowerCase()) && template.match.some((term) => keywordMatches(text, term));
      });
      return {
        domain,
        label: template.label,
        query: template.query.replace("{domain}", domain),
        intent: template.intent,
        resultCount: matches.length,
        urls: Array.from(new Set(matches.map((event) => event.evidence_url).filter(Boolean) as string[])).slice(0, 4),
        tone: matches.length >= 5 ? "high" : matches.length > 0 ? "medium" : "low"
      };
    })
  );
}

export function extractSearchQuery(event: ThreatEvent): string | null {
  const marker = " | query: ";
  const index = event.title.indexOf(marker);
  if (index < 0) return null;
  return event.title.slice(index + marker.length).trim();
}

export function sourceEvents(run: RunRecord | undefined, channel: "osint" | "darkweb" | "socmint"): ThreatEvent[] {
  const events = run?.summary.events ?? [];
  if (channel === "osint") return events.filter(isOsintEvent);
  if (channel === "darkweb") return events.filter(isDarkwebEvent);
  return events.filter(isSocmintEvent);
}

export function buildBrandRiskModel(run: RunRecord | undefined): BrandRiskModel {
  const events = run?.summary.events ?? [];
  const terms = buildBrandTerms(run);
  const domains = brandDomains(run);
  const metrics = objectMetric(run?.summary.metrics);
  const mentions = events
    .filter((event) => terms.some((term) => eventText(event).includes(term.toLowerCase())))
    .map((event) => {
      const text = eventText(event);
      const term = terms.find((item) => text.includes(item.toLowerCase())) ?? terms[0] ?? "brand";
      const tone = mentionTone(event);
      const sentiment = mentionSentiment(event);
      const domain = domainForMention(event, domains, term);
      return {
        id: event.id,
        title: readableTitle(event),
        source: event.source,
        category: event.category,
        observedAt: event.observed_at,
        url: event.evidence_url,
        term,
        domain,
        tone,
        sentiment,
        phrase: phraseForMention(event),
        driver: driverForMention(event, tone)
      };
    })
    .sort((left, right) => toneRank(right.tone) - toneRank(left.tone) || Date.parse(right.observedAt) - Date.parse(left.observedAt));
  const fraudEvents = events.filter((event) => /fraud|fraude|phishing|bec|account.takeover|suplantacion|scam|estafa|credential/i.test(eventText(event)));
  const darkWebSignals = mentions.filter((item) => sourceLooksDarkWeb(item.source) || item.category.toLowerCase().includes("ransom")).length;
  const socmintSignals = mentions.filter((item) => /social|socmint|facebook|instagram|tiktok|reddit|\bx\b/i.test(item.source)).length;
  const weightedTone = mentions.reduce((sum, item) => sum + toneRank(item.tone), 0);
  const negativeSignals = mentions.filter((item) => item.sentiment === "negative").length;
  const positiveSignals = mentions.filter((item) => item.sentiment === "positive").length;
  const reputationImpact = mentions.length
    ? clamp(
        Math.round(
          (negativeSignals / mentions.length) * 58 +
            mentions.filter((item) => item.tone === "critical").length * 9 +
            mentions.filter((item) => item.tone === "high").length * 6 +
            darkWebSignals * 8 +
            socmintSignals * 3
        ),
        0,
        100
      )
    : 0;
  const brandExposure = mentions.length ? clamp(Math.round(mentions.length * 6 + darkWebSignals * 12 + socmintSignals * 8 + weightedTone * 5), 0, 100) : 0;
  const fraudPressure = Math.round(numberMetric(metrics.fraud_pressure, fraudEvents.length ? clamp(fraudEvents.length / 20, 0, 1) : 0) * 100);
  return {
    terms,
    mentions: mentions.slice(0, 30),
    trend: buildTrend(mentions.map((item) => eventFromMention(item)), "30d"),
    sourceRanking: topCounts(mentions.map((item) => item.source)),
    categoryRanking: topCounts(mentions.map((item) => item.category)),
    toneMix: topCounts(mentions.map((item) => item.tone)).map((item) => ({ ...item, tone: item.name as RankedItem["tone"] })),
    sentimentMix: sentimentRanking(mentions),
    domainSentiment: buildDomainSentiment(domains, mentions),
    lookalikes: buildLookalikeSignals(events, domains),
    reputationImpact,
    negativeSignals,
    positiveSignals,
    fraudPressure,
    brandExposure,
    fraudSignals: fraudEvents.length,
    darkWebSignals,
    socmintSignals,
    recommendations: brandRecommendations(brandExposure, fraudPressure, darkWebSignals, socmintSignals)
  };
}

function brandDomains(run: RunRecord | undefined): string[] {
  return Array.from(new Set([...(run?.domains ?? []), ...(run?.request?.domains ?? [])]))
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);
}

function buildBrandTerms(run: RunRecord | undefined): string[] {
  const terms = [
    run?.request?.organization_name,
    ...(run?.domains ?? []),
    ...(run?.request?.domains ?? []),
    ...(run?.domains ?? []).map(domainLabel),
    ...(run?.request?.domains ?? []).map(domainLabel)
  ].filter((item): item is string => Boolean(item && item.trim().length >= 4));
  const seen = new Set<string>();
  return terms
    .map((item) => item.trim())
    .filter((item) => {
      const key = item.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 16);
}

function domainLabel(domain: string): string {
  return domain.split(".", 1)[0].replace(/[-_]+/g, " ");
}

function domainForMention(event: ThreatEvent, domains: string[], fallback: string): string {
  const text = eventText(event);
  const urlHost = hostFromUrl(event.evidence_url ?? "");
  const direct = domains.find((domain) => text.includes(domain) || urlHost === domain || urlHost.endsWith(`.${domain}`));
  if (direct) return direct;
  const labelMatch = domains.find((domain) => {
    const label = domainLabel(domain).toLowerCase();
    return label.length >= 4 && text.includes(label);
  });
  return labelMatch ?? fallback;
}

function readableTitle(event: ThreatEvent): string {
  const queryIndex = event.title.indexOf(" | query: ");
  return queryIndex >= 0 ? event.title.slice(0, queryIndex) : event.title;
}

function mentionTone(event: ThreatEvent): "low" | "medium" | "high" | "critical" {
  const text = eventText(event);
  if (/ransom|darkweb|dark web|leak|filtracion|data breach|credential|secret|password|kev|cve/i.test(text)) return "critical";
  if (/fraud|fraude|phishing|suplantacion|scam|estafa|bec|account takeover|malware/i.test(text)) return "high";
  if (/reclamo|queja|support|login|verificacion|security|seguridad|incidente/i.test(text)) return "medium";
  return "low";
}

function mentionSentiment(event: ThreatEvent): "positive" | "neutral" | "negative" {
  const text = eventText(event);
  const negative = scoreTerms(text, [
    "fraud",
    "fraude",
    "phishing",
    "smishing",
    "vishing",
    "suplantacion",
    "impersonation",
    "scam",
    "estafa",
    "farsa",
    "queja",
    "reclamo",
    "denuncia",
    "fake",
    "falso",
    "leak",
    "filtracion",
    "breach",
    "ransomware",
    "dark web",
    "credential",
    "password",
    "malware",
    "ciberataque",
    "hack"
  ]);
  const positive = scoreTerms(text, ["seguridad", "security", "certificacion", "reconocimiento", "alianza", "award", "innovation", "innovacion"]);
  if (negative > 0) return "negative";
  if (positive > 0) return "positive";
  return "neutral";
}

function scoreTerms(text: string, terms: string[]): number {
  return terms.reduce((sum, term) => sum + (text.includes(term) ? 1 : 0), 0);
}

function phraseForMention(event: ThreatEvent): string {
  const title = readableTitle(event).replace(/\s+/g, " ").trim();
  if (title.length <= 150) return title;
  return `${title.slice(0, 147)}...`;
}

function driverForMention(event: ThreatEvent, tone: "low" | "medium" | "high" | "critical"): string {
  if (tone === "critical") return "Validate exposure, takedown need and executive escalation.";
  if (tone === "high") return "Review fraud, phishing or impersonation response playbook.";
  if (tone === "medium") return "Monitor narrative and confirm whether it affects customer trust.";
  return `Track public mention from ${event.source}.`;
}

function toneRank(tone: string): number {
  if (tone === "critical") return 4;
  if (tone === "high") return 3;
  if (tone === "medium") return 2;
  return 1;
}

function sourceLooksDarkWeb(source: string): boolean {
  return /dark|tor|ransom|onion|leak/i.test(source);
}

function eventFromMention(item: BrandMentionItem): ThreatEvent {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    source: item.source,
    observed_at: item.observedAt,
    evidence_url: item.url,
    tags: [item.tone, item.term]
  };
}

function sentimentRanking(mentions: BrandMentionItem[]): RankedItem[] {
  const order: Array<BrandMentionItem["sentiment"]> = ["negative", "neutral", "positive"];
  return order
    .map((sentiment) => ({
      name: sentiment,
      value: mentions.filter((item) => item.sentiment === sentiment).length,
      tone: (sentiment === "negative" ? "high" : sentiment === "positive" ? "low" : "medium") as RankedItem["tone"]
    }))
    .filter((item) => item.value > 0);
}

function buildDomainSentiment(domains: string[], mentions: BrandMentionItem[]): BrandDomainSentiment[] {
  const scopedDomains = domains.length ? domains : Array.from(new Set(mentions.map((item) => item.domain))).filter(Boolean);
  return scopedDomains.map((domain) => {
    const rows = mentions.filter((item) => item.domain === domain);
    const positive = rows.filter((item) => item.sentiment === "positive").length;
    const neutral = rows.filter((item) => item.sentiment === "neutral").length;
    const negative = rows.filter((item) => item.sentiment === "negative").length;
    const critical = rows.filter((item) => item.tone === "critical").length;
    const high = rows.filter((item) => item.tone === "high").length;
    const reputationImpact = rows.length ? clamp(Math.round((negative / rows.length) * 62 + critical * 10 + high * 6), 0, 100) : 0;
    return { domain, positive, neutral, negative, reputationImpact, total: rows.length };
  });
}

function buildLookalikeSignals(events: ThreatEvent[], domains: string[]): BrandLookalikeSignal[] {
  const rows: BrandLookalikeSignal[] = [];
  const seen = new Set<string>();
  for (const event of events) {
    const url = event.evidence_url ?? "";
    const observedDomain = hostFromUrl(url);
    if (!observedDomain) continue;
    for (const targetDomain of domains) {
      const analysis = lookalikeReason(targetDomain, observedDomain);
      if (!analysis) continue;
      const key = `${targetDomain}|${observedDomain}|${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        targetDomain,
        observedDomain,
        url,
        source: event.source,
        reason: analysis.reason,
        similarity: analysis.similarity,
        tone: analysis.similarity >= 90 ? "critical" : analysis.similarity >= 82 ? "high" : "medium"
      });
    }
  }
  return rows.sort((left, right) => right.similarity - left.similarity).slice(0, 16);
}

function lookalikeReason(targetDomain: string, observedDomain: string): { reason: string; similarity: number } | null {
  const target = targetDomain.toLowerCase().replace(/^www\./, "");
  const observed = observedDomain.toLowerCase().replace(/^www\./, "");
  if (observed === target || observed.endsWith(`.${target}`)) return null;
  const targetLabel = target.split(".")[0] ?? target;
  const observedLabel = observed.split(".")[0] ?? observed;
  if (targetLabel.length < 4 || observedLabel.length < 4) return null;
  const compactTarget = targetLabel.replace(/[-_.]/g, "");
  const compactObserved = observedLabel.replace(/[-_.]/g, "");
  const confTarget = normalizeConfusables(compactTarget);
  const confObserved = normalizeConfusables(compactObserved);
  if (compactTarget === compactObserved) {
    return { reason: "Same brand label with different domain/TLD", similarity: 96 };
  }
  if (confTarget === confObserved && compactTarget !== compactObserved) {
    return { reason: "Possible homoglyph or 0/o, 1/l style substitution", similarity: 94 };
  }
  if (compactObserved.includes(compactTarget) && compactObserved.length <= compactTarget.length + 8) {
    return { reason: "Observed domain contains the protected brand label", similarity: 88 };
  }
  const distance = levenshtein(confTarget, confObserved);
  const similarity = Math.round((1 - distance / Math.max(confTarget.length, confObserved.length, 1)) * 100);
  if (similarity >= 82 || (distance <= 2 && Math.min(confTarget.length, confObserved.length) >= 5)) {
    return { reason: "High lexical similarity to protected domain", similarity };
  }
  return null;
}

function normalizeConfusables(value: string): string {
  return value
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b");
}

function levenshtein(left: string, right: string): number {
  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost);
    }
    previous.splice(0, previous.length, ...current);
  }
  return previous[right.length] ?? Math.max(left.length, right.length);
}

function hostFromUrl(value: string): string {
  if (!value) return "";
  try {
    const parsed = new URL(value.startsWith("http") ? value : `https://${value}`);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    const match = value.toLowerCase().match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:\/|$)/);
    return match?.[1]?.replace(/^www\./, "") ?? "";
  }
}

function brandRecommendations(brandExposure: number, fraudPressure: number, darkWebSignals: number, socmintSignals: number): string[] {
  const recommendations = [];
  if (brandExposure >= 65) recommendations.push("Activate brand protection triage: verify URLs, source credibility, takedown path and customer-impact messaging.");
  if (fraudPressure >= 45) recommendations.push("Prioritize fraud controls: phishing/BEC monitoring, ATO detection, customer warnings and transaction anomaly review.");
  if (darkWebSignals > 0) recommendations.push("Escalate authorized dark web findings through legal, threat intel and incident response before any direct interaction.");
  if (socmintSignals > 0) recommendations.push("Map public narratives and related accounts in SOCMINT to detect impersonation or coordinated abuse.");
  if (brandExposure === 0) recommendations.unshift("No current-run brand/domain mentions were found; do not infer brand impact without URL-level evidence.");
  if (!recommendations.length) recommendations.push("No active brand-risk evidence in the current run; keep scheduled OSINT/SOCMINT monitoring and source health checks.");
  return recommendations;
}

const osintAuditTemplates = [
  {
    label: "Brand impersonation and phishing",
    query: "\"{domain}\" phishing OR fraude OR suplantacion",
    intent: "Detect public mentions that could support impersonation, phishing or customer abuse.",
    match: ["phishing", "fraud", "fraude", "impersonation", "suplantacion"]
  },
  {
    label: "Indexed public documents",
    query: "site:{domain} filetype:pdf OR filetype:xls OR filetype:doc",
    intent: "Review whether public search results expose documents that require classification or removal.",
    match: ["filetype", "pdf", "xls", "doc", "document", "data breach"]
  },
  {
    label: "Directory listing exposure",
    query: "site:{domain} intitle:\"index of\"",
    intent: "Identify public indexing patterns that may indicate unintended directory browsing.",
    match: ["index of", "directory", "listing"]
  },
  {
    label: "Credential and secret mentions",
    query: "\"{domain}\" password OR token OR credential OR secret",
    intent: "Flag public references to credentials, tokens or secrets for validation and takedown.",
    match: ["password", "token", "credential", "secret", "leak"]
  }
];

const socmintAuditTemplates = [
  {
    label: "Public social mentions",
    query: "\"{domain}\" reddit OR X OR facebook OR instagram OR tiktok",
    intent: "Track public social mentions connected to the domain or brand surface.",
    match: ["reddit", "twitter", "facebook", "instagram", "tiktok", "socmint"]
  },
  {
    label: "Impersonation support accounts",
    query: "\"{domain}\" support OR ayuda OR login OR verificacion",
    intent: "Find social narratives that could support fake support, login or verification flows.",
    match: ["support", "ayuda", "login", "verification", "verificacion", "impersonation"]
  },
  {
    label: "Fraud narrative mentions",
    query: "\"{domain}\" scam OR fraude OR phishing",
    intent: "Surface public narratives that may indicate scams or phishing against users.",
    match: ["scam", "fraud", "fraude", "phishing"]
  }
];

function eventText(event: ThreatEvent): string {
  return `${event.source} ${event.title} ${event.category} ${event.actor ?? ""} ${event.evidence_url ?? ""} ${tagsFor(event).join(" ")}`.toLowerCase();
}

function tagsFor(event: ThreatEvent): string[] {
  return Array.isArray(event.tags) ? event.tags : [];
}

function isOsintEvent(event: ThreatEvent): boolean {
  const text = `${event.source} ${event.title} ${tagsFor(event).join(" ")}`.toLowerCase();
  return /cisa|kev|rss|news|google|public web|internet search|github|vulnerability|cve|osint/.test(text) && !isDarkwebEvent(event) && !isSocmintEvent(event);
}

function isDarkwebEvent(event: ThreatEvent): boolean {
  return /dark|onion|credential dump|breach forum|leak site|extortion site/.test(`${event.source} ${event.title} ${tagsFor(event).join(" ")}`.toLowerCase());
}

function frameworkCoverage(name: string, controlScores: Record<string, unknown>): number | null {
  const mapping: Record<string, string[]> = {
    "NIST CSF": ["NIST CSF 2.0"],
    "ISO 27001": ["ISO 27001:2022"],
    "SOC 2": ["SOC 2"],
    "MITRE ATT&CK": ["ATT&CK Detection"],
    "MITRE D3FEND": ["D3FEND"],
    "CIS Controls": ["NIST CSF 2.0", "Incident Response"],
    COBIT: ["NIST CSF 2.0", "ISO 27001:2022"],
    "PCI DSS": ["ISO 27001:2022", "SOC 2"],
    GDPR: ["ISO 27001:2022", "SOC 2"],
    "MITRE ATLAS": []
  };
  const keys = mapping[name] ?? [];
  const values = keys.map((key) => numberMetric(controlScores[key], NaN)).filter((value) => Number.isFinite(value));
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function extractLocations(event: ThreatEvent): string[] {
  return (event.tags ?? [])
    .filter((tag) => /^(geo|country|city|region|country_mention|country_operation_supported):/i.test(tag))
    .map((tag) => tag.split(":").slice(1).join(":").trim())
    .filter(Boolean);
}

function extractAffectedScopes(event: ThreatEvent): string[] {
  return (event.tags ?? [])
    .filter((tag) => /^(affected|asset|assets|domain|target|scope):/i.test(tag))
    .map((tag) => tag.split(":").slice(1).join(":").trim())
    .filter(Boolean);
}

function objectMetric(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function numberMetric(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function optionalNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringMetric(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())) : [];
}

function normalizeDashboardText(value: string): string {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function heatTone(value: string): "low" | "medium" | "high" | "critical" {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") return value;
  return "low";
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function toneForExposure(value: number): "low" | "medium" | "high" | "critical" {
  if (value >= 78) return "critical";
  if (value >= 62) return "high";
  if (value >= 44) return "medium";
  return "low";
}

function toneForCount(value: number): "low" | "medium" | "high" | "critical" {
  if (value >= 24) return "critical";
  if (value >= 12) return "high";
  if (value >= 4) return "medium";
  return "low";
}

function formatScopeName(value: string): string {
  return value
    .split(/[_-]+/)
    .filter(Boolean)
    .map((word) => (word.length <= 3 ? word.toUpperCase() : `${word.charAt(0).toUpperCase()}${word.slice(1)}`))
    .join(" ");
}

function decisionForTone(tone: "low" | "medium" | "high" | "critical"): string {
  if (tone === "critical") return "Immediate executive attention";
  if (tone === "high") return "Prioritize control uplift";
  if (tone === "medium") return "Track and validate";
  return "Monitor";
}

function buildPlatformMentions(events: ThreatEvent[]): RankedItem[] {
  if (!events.length) return [];
  const text = events.map((event) => `${event.source} ${event.title}`).join(" ").toLowerCase();
  return platformNames.map((name) => {
    const needle = name === "X" ? /\bx\b|twitter/ : new RegExp(name.toLowerCase().replace("public web", "web|news|google"));
    const value = events.filter((event) => needle.test(`${event.source} ${event.title}`.toLowerCase())).length;
    return { name, value };
  }).filter((item) => item.value > 0);
}

function buildSocmintNodes(events: ThreatEvent[]): SocmintNode[] {
  if (!events.length) return [];
  const topics = topCounts(events.flatMap((event) => [event.category, ...(event.tags ?? []).slice(0, 2)]));
  const nodes: SocmintNode[] = [
    { id: "Public web", label: "Public web", group: "platform", x: 50, y: 50, size: 18 },
    { id: "X", label: "X", group: "platform", x: 24, y: 32, size: 13 },
    { id: "TikTok", label: "TikTok", group: "platform", x: 76, y: 28, size: 12 },
    { id: "Instagram", label: "Instagram", group: "platform", x: 22, y: 76, size: 12 },
    { id: "Facebook", label: "Facebook", group: "platform", x: 78, y: 76, size: 12 }
  ];
  topics.slice(0, 8).forEach((topic, index) => {
    nodes.push({
      id: topic.name,
      label: topic.name,
      group: index % 3 === 0 ? "mention" : "topic",
      x: 33 + (index % 4) * 12,
      y: 24 + Math.floor(index / 4) * 45,
      size: Math.max(7, Math.min(16, topic.value + 6))
    });
  });
  return nodes;
}

function buildSocmintLinks(events: ThreatEvent[]): SocmintLink[] {
  if (!events.length) return [];
  const topics = topCounts(events.flatMap((event) => [event.category, ...(event.tags ?? []).slice(0, 2)]));
  return topics.slice(0, 8).flatMap((topic, index) => [
    { from: "Public web", to: topic.name },
    { from: platformNames[index % platformNames.length], to: topic.name }
  ]);
}

function buildTtpImpact(events: ThreatEvent[], findings: Finding[]): RankedItem[] {
  return topCounts([
    ...events.map((event) => event.technique || inferTechnique(event.title)),
    ...findings.flatMap((finding) => finding.recommendations.map(inferTechnique))
  ]);
}

function buildAttackActions(events: ThreatEvent[], findings: Finding[]): RankedItem[] {
  const observedEvents = events.filter((event) => {
    if (event.incident_confirmed) return true;
    if (!["direct", "validated", "confirmed"].includes(event.evidence_status ?? "")) return false;
    const validation = String(event.validation_result ?? "").toLowerCase();
    return validation === "validated" || validation === "confirmed" || event.attack_mapping_status === "observed";
  });
  return topCounts([
    ...observedEvents.map((event) => inferAction(`${event.title} ${event.category}`)),
    ...findings.map((finding) => inferAction(`${finding.title} ${finding.category}`))
  ]);
}

function dashboardCategory(event: ThreatEvent): string {
  if (!["vulnerability", "vulnerability_probability"].includes(event.category)) {
    return event.category || "uncategorized";
  }
  const status = event.vulnerability_status ?? "";
  if (["cve_applicable", "kev_applicable", "confirmed"].includes(status)) return "vulnerability";
  if (status === "candidate_product_match") return "vulnerability_candidate";
  return "vulnerability_context";
}

function buildAffectedStates(events: ThreatEvent[], run: RunRecord | undefined, findings: Finding[]): RankedItem[] {
  const domainScope = (run?.summary.domain_signals ?? [])
    .map((signal) => {
      const residualRisk = signal.max_residual_risk ?? 0;
      const value = signal.events + signal.findings || Math.round(residualRisk);
      return { name: signal.domain, value, tone: residualRisk > 0 ? toneForExposure(residualRisk * 3) : toneForCount(value) };
    })
    .filter((item) => item.value > 0)
    .sort((left, right) => right.value - left.value)
    .slice(0, 8);
  if (domainScope.length) return domainScope;

  const taggedScope = topCounts(events.flatMap(extractAffectedScopes));
  if (taggedScope.length) return taggedScope.map((item) => ({ ...item, tone: toneForCount(item.value) }));

  const findingScope = topCounts(findings.map((finding) => finding.category || finding.matrix_label || finding.owner));
  if (findingScope.length) return findingScope.map((item) => ({ ...item, tone: toneForCount(item.value) }));

  return topCounts(events.map((event) => event.source)).map((item) => ({ ...item, tone: toneForCount(item.value) }));
}

function buildGroupHeadlines(events: ThreatEvent[], filters: DashboardFilters, metrics?: Record<string, unknown>): ThreatEvent[] {
  const scoped = includesAll(filters.threatGroups, ALL_GROUPS)
    ? events
    : events.filter((event) => matchesAny(filters.threatGroups, ALL_GROUPS, `${event.title} ${event.actor ?? ""} ${(event.tags ?? []).join(" ")}`.toLowerCase()));
  const metric = objectMetric(metrics?.threat_news);
  const rows = Array.isArray(metric.rows) ? metric.rows.map((item) => objectMetric(item)) : [];
  if (rows.length) {
    return rows.slice(0, 10).map((row) => ({
      id: stringMetric(row.evidence_id, stringMetric(row.url, "news")),
      title: stringMetric(row.title, "Threat intelligence record"),
      category: stringMetric(row.classification, "threat_intelligence"),
      source: stringMetric(row.source, "public_source"),
      observed_at: stringMetric(row.observed_at, ""),
      actor: stringMetric(row.actor, "") || null,
      technique: stringMetric(row.technique, "") || null,
      evidence_url: stringMetric(row.url, ""),
      evidence_status: stringMetric(row.evidence_status, "raw"),
      relationship_to_scope: stringMetric(row.relationship, "unassessed"),
      incident_confirmed: Boolean(row.observed_attack)
    }));
  }
  return scoped
    .filter(isAttributedThreatHeadline)
    .sort((left, right) => Date.parse(right.observed_at || "") - Date.parse(left.observed_at || ""))
    .slice(0, 10);
}

function isAttributedThreatHeadline(event: ThreatEvent): boolean {
  if (!event.evidence_url || ["false_positive", "discarded"].includes(event.evidence_status ?? "")) return false;
  const text = eventText(event).toLowerCase();
  const cyberAction = /ransom|malware|breach|intrusion|exploit|vulnerab|cve-\d+|attack|ataque|extortion|filtraci|credential|suplant|imperson|fraud|estafa|scam|botnet|ddos/.test(text);
  const attributed =
    Boolean(
      event.actor &&
        !["unattributed", "unknown", "sin atribución", "no atribuido", "open_web", "public_web"].includes(
          event.actor.toLowerCase()
        )
    ) ||
    /apt[- ]?\d+|fin\d+|unc\d+|uat[- ]?\d+|ta\d+|lazarus|scattered spider|lockbit|cl0p|akira|black basta|ransomhouse|threat actor|grupo de ransomware/.test(text) ||
    (event.tags ?? []).some((tag) => ["threat_actor", "actor_attribution"].includes(tag.toLowerCase()));
  return cyberAction && attributed;
}

function buildThreatGraphNodes(events: ThreatEvent[], actors: RankedItem[], ttps: RankedItem[]): SocmintNode[] {
  if (!events.length) return [];
  const actorNodes = actors.slice(0, 5);
  const ttpNodes = ttps.slice(0, 5);
  const nodes: SocmintNode[] = [{ id: "Threat activity", label: "Threat activity", group: "platform", x: 50, y: 50, size: 18 }];
  actorNodes.forEach((actor, index) => {
    nodes.push({ id: `actor:${actor.name}`, label: actor.name, group: "mention", x: 22 + index * 14, y: index % 2 === 0 ? 24 : 34, size: Math.min(16, actor.value + 7) });
  });
  ttpNodes.forEach((ttp, index) => {
    nodes.push({ id: `ttp:${ttp.name}`, label: ttp.name, group: "topic", x: 26 + index * 12, y: index % 2 === 0 ? 78 : 68, size: Math.min(15, ttp.value + 6) });
  });
  return nodes;
}

function buildThreatGraphLinks(nodes: SocmintNode[], events: ThreatEvent[]): SocmintLink[] {
  const hub = nodes[0]?.id;
  if (!hub) return [];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const links = new Map<string, SocmintLink>();
  const connectedNodeIds = new Set<string>();
  events.forEach((event) => {
    const actorId = event.actor ? `actor:${event.actor}` : "";
    const techniqueId = event.technique ? `ttp:${event.technique}` : "";
    if (!nodeIds.has(actorId) || !nodeIds.has(techniqueId)) return;
    links.set(`${actorId}|${techniqueId}`, { from: actorId, to: techniqueId });
    connectedNodeIds.add(actorId);
    connectedNodeIds.add(techniqueId);
  });
  nodes.slice(1).forEach((node) => {
    if (!connectedNodeIds.has(node.id)) links.set(`${hub}|${node.id}`, { from: hub, to: node.id });
  });
  return [...links.values()];
}

function inferTechnique(text: string): string {
  const lower = text.toLowerCase();
  if (/phish|credential|login|account/.test(lower)) return "T1566 Phishing";
  if (/cve|exploit|vulnerab|kev|patch/.test(lower)) return "T1190 Exploit Public-Facing App";
  if (/ransom|encrypt|extortion/.test(lower)) return "T1486 Data Encrypted for Impact";
  if (/supply|third.party|dependency/.test(lower)) return "T1195 Supply Chain Compromise";
  if (/email|bec|invoice/.test(lower)) return "T1566.002 Spearphishing Link";
  if (/leak|privacy|data/.test(lower)) return "T1530 Data from Cloud Storage";
  return "";
}

function inferAction(text: string): string {
  const lower = text.toLowerCase();
  if (/cve|exploit|vulnerab|kev/.test(lower)) return "Exploit attempt";
  if (/phish|credential|account/.test(lower)) return "Credential targeting";
  if (/ransom|encrypt|extortion/.test(lower)) return "Impact / extortion";
  if (/fraud|brand|impersonation/.test(lower)) return "Brand abuse";
  if (/leak|privacy|data/.test(lower)) return "Data exposure";
  return "";
}

function matchesAny(values: string[], allValue: string, text: string): boolean {
  if (includesAll(values, allValue)) return true;
  return values.some((value) => text.includes(value.toLowerCase()));
}

function matchesSource(values: string[], text: string): boolean {
  if (includesAll(values, ALL_SOURCES)) return true;
  return values.some((source) => {
    if (source === "Real only") return !text.includes("demo");
    if (source === "SOCMINT") return /socmint|reddit|facebook|instagram|tiktok|\bx\b|twitter/.test(text);
    if (source === "News/RSS") return /rss|news|internet search|google|public web/.test(text);
    if (source === "Vulnerability") return /cve|kev|vulnerability|github/.test(text);
    if (source === "Dark web authorized") return /dark|ransomware|extortion/.test(text);
    return true;
  });
}

function isSocmintEvent(event: ThreatEvent): boolean {
  return /socmint|reddit|facebook|instagram|tiktok|\bx\b|twitter/.test(`${event.source} ${event.title} ${tagsFor(event).join(" ")}`.toLowerCase());
}
