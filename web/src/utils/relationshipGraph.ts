import type { RunRecord, ThreatEvent } from "../types";

export type RelationshipEntityType =
  | "organization"
  | "domain"
  | "ip"
  | "url"
  | "email"
  | "phone"
  | "person"
  | "country"
  | "document"
  | "hash"
  | "social_account"
  | "hashtag"
  | "technology"
  | "vulnerability"
  | "vulnerability_candidate"
  | "actor"
  | "technique"
  | "source"
  | "evidence";

export type RelationshipPerspectiveKey = "all" | "infrastructure" | "evidence" | "social" | "threats";

export interface RelationshipNode {
  id: string;
  label: string;
  type: RelationshipEntityType;
  status: "declared" | "collected" | "validated" | "inferred";
  confidence: number;
  degree: number;
  centrality: number;
  pageRank: number;
  betweenness: number;
  size: number;
  metadata: Record<string, string | number | boolean>;
  evidenceIds: string[];
  evidenceUrls: string[];
  isNew: boolean;
}

export interface RelationshipEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  weight: number;
  confidence: number;
  evidenceIds: string[];
  evidenceUrls: string[];
}

export interface RelationshipGraphStats {
  processedRecords: number;
  renderedRecords: number;
  totalNodes: number;
  totalEdges: number;
  density: number;
  connectedComponents: number;
  isolatedNodes: number;
  newNodes: number;
}

export interface RelationshipGraphModel {
  nodes: RelationshipNode[];
  edges: RelationshipEdge[];
  stats: RelationshipGraphStats;
}

export interface RelationshipPerspective {
  key: RelationshipPerspectiveKey;
  nodeTypes: RelationshipEntityType[];
}

const SOCIAL_HOSTS = new Set([
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "tiktok.com",
  "twitter.com",
  "x.com",
  "youtube.com"
]);

export const relationshipPerspectives: RelationshipPerspective[] = [
  {
    key: "all",
    nodeTypes: [
      "organization",
      "domain",
      "ip",
      "url",
      "email",
      "phone",
      "person",
      "country",
      "document",
      "hash",
      "social_account",
      "hashtag",
      "technology",
      "vulnerability",
      "vulnerability_candidate",
      "actor",
      "technique",
      "source",
      "evidence"
    ]
  },
  {
    key: "infrastructure",
    nodeTypes: ["organization", "domain", "ip", "url", "country", "hash", "technology", "vulnerability", "vulnerability_candidate", "source", "evidence"]
  },
  {
    key: "evidence",
    nodeTypes: ["organization", "domain", "url", "document", "hash", "source", "evidence"]
  },
  {
    key: "social",
    nodeTypes: ["organization", "domain", "url", "email", "phone", "person", "country", "social_account", "hashtag", "source", "evidence"]
  },
  {
    key: "threats",
    nodeTypes: ["organization", "domain", "url", "hash", "technology", "vulnerability", "vulnerability_candidate", "actor", "technique", "source", "evidence"]
  }
];

export function buildRelationshipGraph(run?: RunRecord, baselineRun?: RunRecord): RelationshipGraphModel {
  if (!run) return emptyGraph();

  const events = [...(run.summary.records ?? run.summary.events ?? [])];
  const nodeMap = new Map<string, RelationshipNode>();
  const edgeMap = new Map<string, RelationshipEdge>();
  const organizationName = cleanValue(run.request.organization_name || run.request.legal_name || "");
  const organizationId = organizationName ? nodeId("organization", organizationName) : "";
  const scopeDomains = unique([...run.domains, ...(run.request.domains ?? [])].map(normalizeDomain).filter(Boolean));

  if (organizationName) {
    upsertNode(nodeMap, {
      id: organizationId,
      label: organizationName,
      type: "organization",
      status: "declared",
      confidence: 1,
      metadata: { source: "declared_scope", runId: run.id },
      evidenceIds: [],
      evidenceUrls: [],
      isNew: false
    });
  }

  scopeDomains.forEach((domain) => {
    const domainId = nodeId("domain", domain);
    upsertNode(nodeMap, {
      id: domainId,
      label: domain,
      type: "domain",
      status: "declared",
      confidence: 1,
      metadata: { source: "declared_scope", runId: run.id },
      evidenceIds: [],
      evidenceUrls: [],
      isNew: false
    });
    if (organizationId) {
      upsertEdge(edgeMap, organizationId, domainId, "declared_domain", 1, [], []);
    }
  });

  const selectedEvidenceIds = new Set(events.map((event) => event.id));

  declaredCountries(run).forEach((country) => {
    const countryId = nodeId("country", country);
    upsertNode(nodeMap, {
      id: countryId,
      label: country,
      type: "country",
      status: "declared",
      confidence: 1,
      metadata: { source: "declared_scope", relationship: "declared_country" },
      evidenceIds: [],
      evidenceUrls: [],
      isNew: false
    });
    if (organizationId) upsertEdge(edgeMap, organizationId, countryId, "declared_geography", 1, [], []);
  });

  events.forEach((event) => {
    const evidenceUrl = canonicalHttpUrl(event.evidence_url);
    const evidenceIds = [event.id];
    const evidenceUrls = evidenceUrl ? [evidenceUrl] : [];
    const eventConfidence = normalizedConfidence(event);
    const eventStatus = evidenceStatus(event);
    const evidenceNodeId = nodeId("evidence", event.id);
    const eventText = searchableEventText(event);
    const explicitDomains = matchedScopeDomains(event, scopeDomains, eventText, evidenceUrl);
    const contextNodeIds = isContextOnlyVulnerability(event)
      ? []
      : explicitDomains.map((domain) => nodeId("domain", domain));

    if (
      !contextNodeIds.length &&
      organizationId &&
      isScopeRelated(event) &&
      !isContextOnlyVulnerability(event)
    ) {
      contextNodeIds.push(organizationId);
    }

    if (selectedEvidenceIds.has(event.id)) {
      const evidenceType = graphEvidenceType(event);
      upsertNode(nodeMap, {
        id: evidenceNodeId,
        label: event.title || event.category || event.id,
        type: evidenceType,
        status: eventStatus,
        confidence: eventConfidence,
        metadata: {
          category: event.category || "unclassified",
          source: event.source || "unclassified",
          observedAt: event.observed_at || "",
          relationship: event.relationship_to_scope || "unassessed",
          validation: event.validation_result || event.evidence_status || "collected"
        },
        evidenceIds,
        evidenceUrls,
        isNew: false
      });
      contextNodeIds.forEach((contextId) => {
        upsertEdge(edgeMap, contextId, evidenceNodeId, "supports_scope", eventConfidence, evidenceIds, evidenceUrls);
      });
    }

    const sourceName = cleanValue(event.source || "");
    if (sourceName) {
      const sourceId = nodeId("source", sourceName);
      upsertNode(nodeMap, {
        id: sourceId,
        label: sourceName,
        type: "source",
        status: "collected",
        confidence: eventConfidence,
        metadata: { records: 1 },
        evidenceIds,
        evidenceUrls,
        isNew: false
      });
      if (selectedEvidenceIds.has(event.id)) {
        upsertEdge(edgeMap, sourceId, evidenceNodeId, "collected", eventConfidence, evidenceIds, evidenceUrls);
      } else {
        contextNodeIds.forEach((contextId) => {
          upsertEdge(edgeMap, contextId, sourceId, "observed_by", eventConfidence, evidenceIds, evidenceUrls);
        });
      }
    }

    if (evidenceUrl) {
      const urlId = nodeId("url", evidenceUrl);
      upsertNode(nodeMap, {
        id: urlId,
        label: compactUrl(evidenceUrl),
        type: socialAccountType(evidenceUrl) ? "social_account" : "url",
        status: eventStatus,
        confidence: eventConfidence,
        metadata: { canonicalUrl: evidenceUrl, host: hostFromUrl(evidenceUrl) },
        evidenceIds,
        evidenceUrls,
        isNew: false
      });
      if (selectedEvidenceIds.has(event.id)) {
        upsertEdge(edgeMap, evidenceNodeId, urlId, "references", eventConfidence, evidenceIds, evidenceUrls);
      }
      const host = normalizeDomain(hostFromUrl(evidenceUrl));
      if (host) {
        const hostId = nodeId("domain", host);
        upsertNode(nodeMap, {
          id: hostId,
          label: host,
          type: "domain",
          status: "collected",
          confidence: eventConfidence,
          metadata: { role: scopeDomains.includes(host) ? "scope" : "evidence_host" },
          evidenceIds,
          evidenceUrls,
          isNew: false
        });
        upsertEdge(edgeMap, hostId, urlId, "hosts", eventConfidence, evidenceIds, evidenceUrls);
      }
    }

    const entityRows: Array<{ type: RelationshipEntityType; value: string; relation: string }> = [];
    extractTagValues(event, "email").forEach((value) => entityRows.push({ type: "email", value, relation: "mentions" }));
    extractPublicEntityValues(event, "email").forEach((value) => entityRows.push({ type: "email", value, relation: "mentions" }));
    extractTagValues(event, "phone").forEach((value) => entityRows.push({ type: "phone", value, relation: "mentions" }));
    extractPublicEntityValues(event, "phone").forEach((value) => entityRows.push({ type: "phone", value, relation: "mentions" }));
    extractTagValues(event, "person_candidate").forEach((value) => entityRows.push({ type: "person", value, relation: "public_profile_candidate" }));
    extractPublicEntityValues(event, "person").forEach((value) => entityRows.push({ type: "person", value, relation: "public_profile_candidate" }));
    extractIps(eventText).forEach((value) => entityRows.push({ type: "ip", value, relation: "mentions" }));
    extractHashtags(eventText).forEach((value) => entityRows.push({ type: "hashtag", value, relation: "mentions" }));
    extractCountryTags(event).forEach((value) => entityRows.push({ type: "country", value, relation: "mentions_geography" }));
    if (isApplicableVulnerability(event)) {
      extractCves(eventText).forEach((value) => entityRows.push({ type: "vulnerability", value, relation: "applies_to" }));
    } else if (isProductMatchedVulnerability(event)) {
      extractCves(eventText).forEach((value) => entityRows.push({ type: "vulnerability_candidate", value, relation: "product_match_pending_version" }));
    }
    explicitTechnologyTags(event).forEach((value) => entityRows.push({ type: "technology", value, relation: "observes" }));
    extractUnstructuredArtifactRows(event).forEach((row) => {
      if (row.type === "cve") {
        if (isApplicableVulnerability(event)) {
          entityRows.push({ type: "vulnerability", value: row.value, relation: "applies_to" });
        } else if (isProductMatchedVulnerability(event)) {
          entityRows.push({ type: "vulnerability_candidate", value: row.value, relation: "product_match_pending_version" });
        }
        return;
      }
      const graphType = artifactGraphType(row.type);
      if (graphType) entityRows.push({ type: graphType, value: row.value, relation: "extracts_artifact" });
    });
    if (explicitActor(event.actor)) entityRows.push({ type: "actor", value: cleanValue(event.actor || ""), relation: "attributes" });
    if (cleanValue(event.technique || "")) entityRows.push({ type: "technique", value: cleanValue(event.technique || ""), relation: "maps" });

    uniqueEntityRows(entityRows).forEach(({ type, value, relation }) => {
      const entityId = nodeId(type, value);
      upsertNode(nodeMap, {
        id: entityId,
        label: value,
        type,
        status: eventStatus,
        confidence: eventConfidence,
        metadata: entityMetadata(event, type),
        evidenceIds,
        evidenceUrls,
        isNew: false
      });
      if (selectedEvidenceIds.has(event.id)) {
        upsertEdge(edgeMap, evidenceNodeId, entityId, relation, eventConfidence, evidenceIds, evidenceUrls);
      } else {
        contextNodeIds.forEach((contextId) => {
          upsertEdge(edgeMap, contextId, entityId, relation, eventConfidence, evidenceIds, evidenceUrls);
        });
      }
    });
  });

  const nodes = [...nodeMap.values()];
  const edges = [...edgeMap.values()];
  const baselineIds = baselineRun
    ? new Set(buildRelationshipGraph(baselineRun).nodes.map((node) => node.id))
    : new Set<string>();
  const centralNodes = applyCentrality(nodes, edges).map((node) => ({
    ...node,
    isNew: Boolean(baselineRun) && !baselineIds.has(node.id)
  }));
  const stats = graphStats(centralNodes, edges, events.length, selectedEvidenceIds.size);
  return { nodes: centralNodes, edges, stats };
}

export function filterRelationshipGraph(
  model: RelationshipGraphModel,
  perspective: RelationshipPerspectiveKey
): RelationshipGraphModel {
  if (perspective === "all") return model;
  const allowed = new Set(relationshipPerspectives.find((item) => item.key === perspective)?.nodeTypes ?? []);
  const firstPass = new Set(model.nodes.filter((node) => allowed.has(node.type)).map((node) => node.id));
  const contextTypes = new Set<RelationshipEntityType>(["organization", "domain", "country", "source", "evidence"]);
  const nodeIndex = new Map(model.nodes.map((node) => [node.id, node]));
  model.edges.forEach((edge) => {
    if (!firstPass.has(edge.source) && !firstPass.has(edge.target)) return;
    const source = nodeIndex.get(edge.source);
    const target = nodeIndex.get(edge.target);
    if (source && contextTypes.has(source.type)) firstPass.add(source.id);
    if (target && contextTypes.has(target.type)) firstPass.add(target.id);
  });
  const nodes = model.nodes.filter((node) => firstPass.has(node.id));
  const edges = model.edges.filter((edge) => firstPass.has(edge.source) && firstPass.has(edge.target));
  return {
    nodes: applyCentrality(nodes, edges),
    edges,
    stats: graphStats(nodes, edges, model.stats.processedRecords, model.stats.renderedRecords)
  };
}

function upsertNode(
  nodes: Map<string, RelationshipNode>,
  row: Omit<RelationshipNode, "degree" | "centrality" | "pageRank" | "betweenness" | "size">
) {
  const current = nodes.get(row.id);
  if (!current) {
    nodes.set(row.id, { ...row, degree: 0, centrality: 0, pageRank: 0, betweenness: 0, size: 12 });
    return;
  }
  current.confidence = Math.max(current.confidence, row.confidence);
  current.evidenceIds = unique([...current.evidenceIds, ...row.evidenceIds]);
  current.evidenceUrls = unique([...current.evidenceUrls, ...row.evidenceUrls]);
  current.status = strongerStatus(current.status, row.status);
  current.metadata = mergeMetadata(current.metadata, row.metadata);
}

function upsertEdge(
  edges: Map<string, RelationshipEdge>,
  source: string,
  target: string,
  relation: string,
  confidence: number,
  evidenceIds: string[],
  evidenceUrls: string[]
) {
  if (!source || !target || source === target) return;
  const id = [source, target, relation].join("::");
  const current = edges.get(id);
  if (!current) {
    edges.set(id, { id, source, target, relation, weight: 1, confidence, evidenceIds: [...evidenceIds], evidenceUrls: [...evidenceUrls] });
    return;
  }
  current.weight += 1;
  current.confidence = Math.max(current.confidence, confidence);
  current.evidenceIds = unique([...current.evidenceIds, ...evidenceIds]);
  current.evidenceUrls = unique([...current.evidenceUrls, ...evidenceUrls]);
}

function applyCentrality(nodes: RelationshipNode[], edges: RelationshipEdge[]): RelationshipNode[] {
  const neighbors = new Map(nodes.map((node) => [node.id, new Set<string>()]));
  edges.forEach((edge) => {
    neighbors.get(edge.source)?.add(edge.target);
    neighbors.get(edge.target)?.add(edge.source);
  });
  const denominator = Math.max(1, nodes.length - 1);
  const pageRank = calculatePageRank(nodes, neighbors);
  const betweenness = calculateBetweenness(nodes, neighbors);
  return nodes.map((node) => {
    const degree = neighbors.get(node.id)?.size ?? 0;
    const centrality = degree / denominator;
    return {
      ...node,
      degree,
      centrality,
      pageRank: pageRank.get(node.id) ?? 0,
      betweenness: betweenness.get(node.id) ?? 0,
      size: Math.min(34, 10 + Math.sqrt(degree) * 4.6)
    };
  });
}

function calculatePageRank(
  nodes: RelationshipNode[],
  neighbors: Map<string, Set<string>>
): Map<string, number> {
  const count = Math.max(1, nodes.length);
  const damping = 0.85;
  let ranks = new Map(nodes.map((node) => [node.id, 1 / count]));
  for (let iteration = 0; iteration < 30; iteration += 1) {
    const next = new Map(nodes.map((node) => [node.id, (1 - damping) / count]));
    let danglingMass = 0;
    nodes.forEach((node) => {
      const adjacent = neighbors.get(node.id) ?? new Set<string>();
      const contribution = (ranks.get(node.id) ?? 0) / Math.max(1, adjacent.size);
      if (!adjacent.size) {
        danglingMass += ranks.get(node.id) ?? 0;
        return;
      }
      adjacent.forEach((targetId) => {
        next.set(targetId, (next.get(targetId) ?? 0) + damping * contribution);
      });
    });
    if (danglingMass) {
      const distributed = damping * danglingMass / count;
      nodes.forEach((target) => next.set(target.id, (next.get(target.id) ?? 0) + distributed));
    }
    ranks = next;
  }
  return ranks;
}

function calculateBetweenness(
  nodes: RelationshipNode[],
  neighbors: Map<string, Set<string>>
): Map<string, number> {
  const scores = new Map(nodes.map((node) => [node.id, 0]));
  const sources = sampledSources(nodes, 48);
  sources.forEach((source) => {
    const stack: string[] = [];
    const predecessors = new Map(nodes.map((node) => [node.id, [] as string[]]));
    const paths = new Map(nodes.map((node) => [node.id, 0]));
    const distance = new Map(nodes.map((node) => [node.id, -1]));
    paths.set(source.id, 1);
    distance.set(source.id, 0);
    const queue = [source.id];
    while (queue.length) {
      const current = queue.shift()!;
      stack.push(current);
      (neighbors.get(current) ?? []).forEach((target) => {
        if ((distance.get(target) ?? -1) < 0) {
          queue.push(target);
          distance.set(target, (distance.get(current) ?? 0) + 1);
        }
        if (distance.get(target) === (distance.get(current) ?? 0) + 1) {
          paths.set(target, (paths.get(target) ?? 0) + (paths.get(current) ?? 0));
          predecessors.get(target)?.push(current);
        }
      });
    }
    const dependency = new Map(nodes.map((node) => [node.id, 0]));
    while (stack.length) {
      const target = stack.pop()!;
      (predecessors.get(target) ?? []).forEach((predecessor) => {
        const targetPaths = paths.get(target) ?? 0;
        if (!targetPaths) return;
        const share =
          ((paths.get(predecessor) ?? 0) / targetPaths) * (1 + (dependency.get(target) ?? 0));
        dependency.set(predecessor, (dependency.get(predecessor) ?? 0) + share);
      });
      if (target !== source.id) {
        scores.set(target, (scores.get(target) ?? 0) + (dependency.get(target) ?? 0));
      }
    }
  });
  const sampleScale = sources.length ? nodes.length / sources.length : 1;
  const normalization = nodes.length > 2 ? sampleScale / ((nodes.length - 1) * (nodes.length - 2)) : 0;
  scores.forEach((value, key) => scores.set(key, value * normalization));
  return scores;
}

function graphStats(
  nodes: RelationshipNode[],
  edges: RelationshipEdge[],
  processedRecords: number,
  renderedRecords: number
): RelationshipGraphStats {
  const possibleEdges = nodes.length > 1 ? (nodes.length * (nodes.length - 1)) / 2 : 0;
  const neighborMap = new Map(nodes.map((node) => [node.id, [] as string[]]));
  edges.forEach((edge) => {
    neighborMap.get(edge.source)?.push(edge.target);
    neighborMap.get(edge.target)?.push(edge.source);
  });
  let connectedComponents = 0;
  const visited = new Set<string>();
  nodes.forEach((node) => {
    if (visited.has(node.id)) return;
    connectedComponents += 1;
    const queue = [node.id];
    while (queue.length) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      (neighborMap.get(current) ?? []).forEach((next) => {
        if (!visited.has(next)) queue.push(next);
      });
    }
  });
  return {
    processedRecords,
    renderedRecords,
    totalNodes: nodes.length,
    totalEdges: edges.length,
    density: possibleEdges ? edges.length / possibleEdges : 0,
    connectedComponents,
    isolatedNodes: nodes.filter((node) => (neighborMap.get(node.id)?.length ?? 0) === 0).length,
    newNodes: nodes.filter((node) => node.isNew).length
  };
}

function sampledSources(nodes: RelationshipNode[], maximum: number): RelationshipNode[] {
  if (nodes.length <= maximum) return nodes;
  const stride = nodes.length / maximum;
  return Array.from({ length: maximum }, (_, index) => nodes[Math.floor(index * stride)]);
}

function matchedScopeDomains(event: ThreatEvent, domains: string[], text: string, evidenceUrl: string): string[] {
  const tags = event.tags ?? [];
  const explicitTagDomains = tags
    .filter((tag) => /^(domain|asset|scope|target):/i.test(tag))
    .map((tag) => normalizeDomain(tag.split(":").slice(1).join(":")));
  const evidenceHost = normalizeDomain(hostFromUrl(evidenceUrl));
  return domains.filter(
    (domain) =>
      text.includes(domain) ||
      explicitTagDomains.some((value) => value === domain || value.endsWith(`.${domain}`)) ||
      evidenceHost === domain ||
      evidenceHost.endsWith(`.${domain}`)
  );
}

function graphEvidenceType(event: ThreatEvent): RelationshipEntityType {
  if (event.evidence_type === "document") return "document";
  return "evidence";
}

function evidenceStatus(event: ThreatEvent): RelationshipNode["status"] {
  const value = `${event.evidence_status ?? ""} ${event.validation_result ?? ""}`.toLowerCase();
  if (/validated|confirmed|validado|confirmado/.test(value)) return "validated";
  return "collected";
}

function normalizedConfidence(event: ThreatEvent): number {
  if (typeof event.confidence_score === "number" && Number.isFinite(event.confidence_score)) {
    return Math.max(0, Math.min(1, event.confidence_score > 1 ? event.confidence_score / 100 : event.confidence_score));
  }
  const label = (event.confidence_level ?? "").toLowerCase();
  if (/high|alta/.test(label)) return 0.82;
  if (/medium|media/.test(label)) return 0.62;
  if (/low|baja/.test(label)) return 0.38;
  return 0.5;
}

function searchableEventText(event: ThreatEvent): string {
  const validation = event.technical_validation ?? {};
  return [
    event.title,
    event.category,
    event.actor,
    event.technique,
    event.asset,
    event.host,
    event.indicator,
    event.evidence_url,
    validation.summary,
    validation.description,
    validation.original_response,
    ...(event.tags ?? [])
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function isScopeRelated(event: ThreatEvent): boolean {
  return /direct|related|validated|confirm|directa|relacionad|validado/.test(
    `${event.relationship_to_scope ?? ""} ${event.validation_result ?? ""}`.toLowerCase()
  );
}

function socialAccountType(url: string): boolean {
  const host = hostFromUrl(url).replace(/^www\./, "");
  return [...SOCIAL_HOSTS].some((socialHost) => host === socialHost || host.endsWith(`.${socialHost}`));
}

function explicitTechnologyTags(event: ThreatEvent): string[] {
  return (event.tags ?? [])
    .filter((tag) => /^(tech|technology|software|product):/i.test(tag))
    .map((tag) => cleanValue(tag.split(":").slice(1).join(":")))
    .filter(Boolean);
}

function declaredCountries(run: RunRecord): string[] {
  return unique(
    [
      ...(run.request.countries_of_operation ?? []),
      ...String(run.request.country || "")
        .split(",")
        .map((value) => value.trim())
    ].filter(Boolean)
  );
}

function extractTagValues(event: ThreatEvent, prefix: string): string[] {
  const marker = `${prefix.toLowerCase()}:`;
  return unique(
    (event.tags ?? [])
      .filter((tag) => tag.toLowerCase().startsWith(marker))
      .map((tag) => cleanValue(tag.slice(marker.length)))
      .filter(Boolean)
  );
}

function extractPublicEntityValues(event: ThreatEvent, type: "email" | "phone" | "person"): string[] {
  const rows = event.technical_validation?.public_entity_candidates;
  if (!Array.isArray(rows)) return [];
  return unique(
    rows
      .filter((row): row is Record<string, unknown> => Boolean(row) && typeof row === "object")
      .filter((row) => String(row.type || "").toLowerCase() === type)
      .map((row) => cleanValue(String(row.value || "")))
      .filter(Boolean)
  );
}

function extractUnstructuredArtifactRows(event: ThreatEvent): Array<{ type: string; value: string }> {
  const rows = event.technical_validation?.unstructured_artifacts;
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((row): row is Record<string, unknown> => Boolean(row) && typeof row === "object")
    .map((row) => ({
      type: String(row.type || "").toLowerCase(),
      value: cleanValue(String(row.value || ""))
    }))
    .filter((row) => Boolean(row.type && row.value))
    .slice(0, 160);
}

function artifactGraphType(type: string): RelationshipEntityType | null {
  if (type === "email") return "email";
  if (type === "phone") return "phone";
  if (type === "ip") return "ip";
  if (type === "domain") return "domain";
  if (type === "url") return "url";
  if (type === "file") return "document";
  if (type === "hash" || type === "secret_indicator") return "hash";
  return null;
}

function extractCountryTags(event: ThreatEvent): string[] {
  return unique([
    ...extractTagValues(event, "country_mention"),
    ...extractTagValues(event, "country_operation_supported")
  ]);
}

function isApplicableVulnerability(event: ThreatEvent): boolean {
  return ["cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"].includes(
    String(event.vulnerability_status || "").toLowerCase()
  );
}

function isProductMatchedVulnerability(event: ThreatEvent): boolean {
  return String(event.vulnerability_status || "").toLowerCase() === "candidate_product_match";
}

function isContextOnlyVulnerability(event: ThreatEvent): boolean {
  return String(event.vulnerability_status || "").toLowerCase() === "cve_context_only";
}

function entityMetadata(
  event: ThreatEvent,
  type: RelationshipEntityType
): Record<string, string | number | boolean> {
  const validation = event.technical_validation ?? {};
  const metadata: Record<string, string | number | boolean> = {
    records: 1,
    relationship: event.relationship_to_scope || "unassessed",
    validation: event.validation_result || event.evidence_status || "collected"
  };
  if (type === "vulnerability" || type === "vulnerability_candidate") {
    metadata.product = String(validation.matched_product || "");
    metadata.observedVersion = String(validation.observed_version || "");
    metadata.affectedRange = String(validation.affected_range || "");
    metadata.applicabilityBasis = String(validation.validation_method || "");
    metadata.applicability = type === "vulnerability" ? "validated" : "pending_version";
  }
  if (type === "person") {
    metadata.identityStatus = "public_profile_candidate";
    metadata.limitations = "No demuestra empleo vigente sin corroboración oficial.";
  }
  if (type === "country") {
    metadata.geographicStatus = extractTagValues(event, "country_operation_supported").length
      ? "supported_operational_context"
      : "mention_only";
  }
  return metadata;
}

function explicitActor(value?: string | null): boolean {
  const normalized = cleanValue(value || "").toLowerCase();
  return Boolean(normalized) && !["unknown", "unattributed", "no atribuido", "sin atribución", "open_web", "public_web"].includes(normalized);
}

function extractIps(text: string): string[] {
  return unique(
    (text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []).filter((value) =>
      value.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255)
    )
  ).slice(0, 16);
}

function extractHashtags(text: string): string[] {
  return unique(text.match(/#[a-z0-9_]{2,64}/gi) ?? []).slice(0, 12);
}

function extractCves(text: string): string[] {
  return unique((text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((value) => value.toUpperCase())).slice(0, 16);
}

function uniqueEntityRows(
  rows: Array<{ type: RelationshipEntityType; value: string; relation: string }>
): Array<{ type: RelationshipEntityType; value: string; relation: string }> {
  const seen = new Set<string>();
  return rows.filter((row) => {
    const key = `${row.type}:${row.value.toLowerCase()}`;
    if (!row.value || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeMetadata(
  current: Record<string, string | number | boolean>,
  incoming: Record<string, string | number | boolean>
): Record<string, string | number | boolean> {
  const merged = { ...current, ...incoming };
  if (typeof current.records === "number" && typeof incoming.records === "number") {
    merged.records = current.records + incoming.records;
  }
  return merged;
}

function strongerStatus(
  left: RelationshipNode["status"],
  right: RelationshipNode["status"]
): RelationshipNode["status"] {
  const rank: Record<RelationshipNode["status"], number> = { inferred: 0, collected: 1, declared: 2, validated: 3 };
  return rank[right] > rank[left] ? right : left;
}

function nodeId(type: RelationshipEntityType, value: string): string {
  return `${type}:${cleanValue(value).toLowerCase()}`;
}

function cleanValue(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

function normalizeDomain(value: string): string {
  return cleanValue(value)
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split(/[/?#]/)[0]
    .replace(/\.$/, "");
}

function canonicalHttpUrl(value?: string | null): string {
  if (!value) return "";
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return "";
  }
}

function hostFromUrl(value: string): string {
  if (!value) return "";
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

function compactUrl(value: string): string {
  try {
    const parsed = new URL(value);
    const path = parsed.pathname === "/" ? "" : parsed.pathname;
    const label = `${parsed.hostname}${path}`;
    return label.length > 64 ? `${label.slice(0, 61)}...` : label;
  } catch {
    return value;
  }
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function emptyGraph(): RelationshipGraphModel {
  return {
    nodes: [],
    edges: [],
    stats: {
      processedRecords: 0,
      renderedRecords: 0,
      totalNodes: 0,
      totalEdges: 0,
      density: 0,
      connectedComponents: 0,
      isolatedNodes: 0,
      newNodes: 0
    }
  };
}
