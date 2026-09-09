import type {
  AnalysisDomain,
  DecisionIntelligenceSnapshot,
  Finding,
  MultidomainIntelligence,
  RunRecord,
  TechnologyDomain,
  ThreatEvent
} from "../types";

export const technologyDomainOptions: TechnologyDomain[] = ["it", "iot", "iiot", "ot", "unknown"];
export const analysisDomainOptions: AnalysisDomain[] = ["cyber", "fraud", "brand", "disinformation", "ai_security"];

export interface IntelligenceFilters {
  technologyDomains: TechnologyDomain[];
  analysisDomains: AnalysisDomain[];
}

export const defaultIntelligenceFilters: IntelligenceFilters = {
  technologyDomains: [...technologyDomainOptions],
  analysisDomains: [...analysisDomainOptions]
};

function eventTechnology(event: ThreatEvent): TechnologyDomain[] {
  if (event.technology_domains?.length) return event.technology_domains;
  return [event.primary_technology_domain ?? "unknown"];
}

function eventAnalysis(event: ThreatEvent): AnalysisDomain[] {
  return event.analysis_domains?.length ? event.analysis_domains : ["cyber"];
}

function findingTechnology(finding: Finding): TechnologyDomain[] {
  if (finding.technology_domains?.length) return finding.technology_domains;
  return [finding.primary_technology_domain ?? "unknown"];
}

function findingAnalysis(finding: Finding): AnalysisDomain[] {
  return finding.analysis_domains?.length ? finding.analysis_domains : ["cyber"];
}

function intersects<T extends string>(values: T[], selected: T[]): boolean {
  return values.some((value) => selected.includes(value));
}

function matchesEvent(event: ThreatEvent, filters: IntelligenceFilters): boolean {
  return intersects(eventTechnology(event), filters.technologyDomains)
    && intersects(eventAnalysis(event), filters.analysisDomains);
}

function matchesFinding(finding: Finding, filters: IntelligenceFilters): boolean {
  return intersects(findingTechnology(finding), filters.technologyDomains)
    && intersects(findingAnalysis(finding), filters.analysisDomains);
}

function eventTouchesDomain(event: ThreatEvent, domain: string): boolean {
  const needle = domain.toLowerCase();
  return [event.host, event.asset, event.indicator, event.evidence_url, event.title, ...(event.tags ?? [])]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(needle));
}

function findingTouchesDomain(finding: Finding, domain: string): boolean {
  const needle = domain.toLowerCase();
  return [finding.title, ...finding.evidence]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(needle));
}

function projectedMultidomain(
  source: MultidomainIntelligence | undefined,
  events: ThreatEvent[],
  filters: IntelligenceFilters
): MultidomainIntelligence | undefined {
  if (!source) return undefined;
  const selectedEvidenceIds = new Set(events.flatMap((event) => [event.id, event.canonical_id, event.public_evidence_id].filter(Boolean) as string[]));
  const rows = (source.technology_footprint?.rows ?? [])
    .filter((row) => filters.technologyDomains.includes(row.domain))
    .map((row) => ({
      ...row,
      evidence_ids: (row.evidence_ids ?? []).filter((id) => selectedEvidenceIds.has(id))
    }))
    .filter((row) => row.evidence_ids.length > 0);
  const scenarioCandidates = (source.scenario_candidates ?? []).filter((scenario) => {
    const evidenceIds = Array.isArray(scenario.evidence_ids) ? scenario.evidence_ids.map(String) : [];
    return evidenceIds.some((id) => selectedEvidenceIds.has(id));
  });
  const relationships = (source.relationships ?? []).filter((relationship) => {
    const evidenceIds = Array.isArray(relationship.evidence_ids) ? relationship.evidence_ids.map(String) : [];
    return evidenceIds.some((id) => selectedEvidenceIds.has(id));
  });
  const domainCounts = Object.fromEntries(
    technologyDomainOptions.map((domain) => [domain, events.filter((event) => event.primary_technology_domain === domain).length])
  ) as Partial<Record<TechnologyDomain, number>>;
  const analysisDimensions = Object.fromEntries(
    analysisDomainOptions.map((domain) => [domain, events.filter((event) => eventAnalysis(event).includes(domain)).length])
  ) as Partial<Record<AnalysisDomain, number>>;
  const assured = events.filter((event) => ["direct", "validated", "confirmed"].includes(event.evidence_status ?? "")).length;
  const attributed = events.filter((event) => ["related", "observed_public", "corroborated_public"].includes(event.public_attribution_status ?? "")).length;
  return {
    ...source,
    technology_footprint: {
      ...source.technology_footprint,
      status: events.length ? "filtered_projection" : "no_data",
      total_records: events.length,
      assured_records: assured,
      attributed_records: attributed,
      domain_counts: domainCounts,
      rows
    },
    analysis_dimensions: analysisDimensions,
    relationships,
    scenario_candidates: scenarioCandidates
  };
}

function projectedSnapshot(
  source: DecisionIntelligenceSnapshot | undefined,
  multidomain: MultidomainIntelligence | undefined,
  selectedIds: Set<string>
): DecisionIntelligenceSnapshot | undefined {
  if (!source) return undefined;
  const keepsReferences = (row: { evidence_ids?: string[] }) => !row.evidence_ids?.length || row.evidence_ids.some((id) => selectedIds.has(id));
  const evidenceReferences = (source.evidence_references ?? []).filter((row) => {
    const evidenceId = String(row.evidence_id ?? row.event_id ?? row.id ?? "");
    return !evidenceId || selectedIds.has(evidenceId);
  });
  const supportedScenarios = (source.supported_scenarios ?? []).filter(keepsReferences);
  const decisions = (source.decisions ?? []).filter(keepsReferences);
  return {
    ...source,
    evidence_references: evidenceReferences,
    supported_scenarios: supportedScenarios,
    decisions,
    scenario_funnel: {
      ...source.scenario_funnel,
      supported: supportedScenarios.length,
      validated: supportedScenarios.filter((row) => row.status === "validated").length,
      confirmed: supportedScenarios.filter((row) => row.status === "materialized" || row.status === "confirmed").length
    },
    multidomain_intelligence: multidomain,
    public_technology_footprint: multidomain?.technology_footprint
  };
}

export function projectRunByIntelligenceFilters(run: RunRecord | undefined, filters: IntelligenceFilters): RunRecord | undefined {
  if (!run) return undefined;
  const events = (run.summary.events ?? []).filter((event) => matchesEvent(event, filters));
  const findings = (run.summary.findings ?? []).filter((finding) => matchesFinding(finding, filters));
  const selectedIds = new Set(events.flatMap((event) => [event.id, event.canonical_id, event.public_evidence_id].filter(Boolean) as string[]));
  const sourceMultidomain = run.summary.multidomain_intelligence ?? run.summary.decision_snapshot?.multidomain_intelligence;
  const multidomain = projectedMultidomain(sourceMultidomain, events, filters);
  const risks = findings.map((finding) => finding.residual_risk).filter(Number.isFinite);
  const domainSignals = (run.domains ?? []).map((domain) => {
    const domainEvents = events.filter((event) => eventTouchesDomain(event, domain));
    const domainFindings = findings.filter((finding) => findingTouchesDomain(finding, domain));
    const domainRisks = domainFindings.map((finding) => finding.residual_risk).filter(Number.isFinite);
    return {
      domain,
      events: domainEvents.length,
      findings: domainFindings.length,
      max_residual_risk: domainRisks.length ? Math.max(...domainRisks) : null,
      last_seen: domainEvents.map((event) => event.last_seen ?? event.observed_at).sort().slice(-1)[0] ?? null
    };
  });
  return {
    ...run,
    summary: {
      ...run.summary,
      events,
      records: events,
      findings,
      domain_signals: domainSignals,
      kpis: {
        ...run.summary.kpis,
        new_events: events.length,
        raw_records: events.length,
        unique_records: events.length,
        validated_evidence: events.filter((event) => ["direct", "validated", "confirmed"].includes(event.evidence_status ?? "")).length,
        validated_findings: findings.filter((finding) => ["validated", "confirmed"].includes(finding.evidence_status ?? "")).length,
        confirmed_findings: findings.filter((finding) => finding.evidence_status === "confirmed").length,
        confirmed_incidents: findings.filter((finding) => finding.incident_confirmed).length,
        max_residual_risk: risks.length ? Math.max(...risks) : null,
        avg_residual_risk: risks.length ? risks.reduce((sum, value) => sum + value, 0) / risks.length : null
      },
      metrics: {
        ...run.summary.metrics,
        intelligence_filter_projection: {
          technology_domains: filters.technologyDomains,
          analysis_domains: filters.analysisDomains,
          event_count: events.length,
          finding_count: findings.length,
          source_snapshot_hash: run.summary.decision_snapshot?.snapshot_hash ?? null
        },
        multidomain_intelligence: multidomain
      },
      multidomain_intelligence: multidomain,
      decision_snapshot: projectedSnapshot(run.summary.decision_snapshot, multidomain, selectedIds)
    }
  };
}
