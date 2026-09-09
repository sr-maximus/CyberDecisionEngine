import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import type { PointerEvent as ReactPointerEvent, WheelEvent as ReactWheelEvent } from "react";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum
} from "d3-force";
import {
  Activity,
  Boxes,
  ExternalLink,
  Filter,
  GitBranch,
  Network,
  Radar,
  Search,
  ShieldCheck,
  ShieldEllipsis,
  Target,
  Workflow,
  ZoomIn,
  ZoomOut,
  RotateCcw
} from "lucide-react";
import type { LanguageMode, RunRecord } from "../types";
import { FrameworkCatalogExplorer } from "./FrameworkCatalogExplorer";

type CTIState = "OBSERVED" | "INFERRED" | "RELATED" | "REFERENCE";
type CTITab = "overview" | "actors" | "campaigns" | "matrix" | "flows" | "coverage" | "evidence";

interface CTID3FEND {
  id: string;
  name?: string;
}

interface CTIActor {
  actor_id: string;
  name: string;
  state: CTIState;
  relevance_score: number;
  relevance_band: string;
  explanation: string;
  evidence_count: number;
  validated_evidence_count: number;
  observed_attack_count: number;
  source_count: number;
  relationships: string[];
  techniques: string[];
  run_techniques?: string[];
  documented_techniques?: string[];
  campaigns: string[];
  d3fend: CTID3FEND[];
  frameworks: string[];
  evidence_ids: string[];
  evidence_urls: string[];
  limitations: string[];
  entity_type?: string;
  attack_id?: string;
  aliases?: string[];
  profile_status?: string;
  knowledge_url?: string;
  knowledge_description?: string;
  knowledge_created?: string;
  knowledge_modified?: string;
  first_seen?: string;
  last_seen?: string;
  contributors?: string[];
  external_references?: CTIReference[];
}

interface CTIReference {
  source_name?: string;
  external_id?: string;
  url?: string;
}

interface CTICampaign {
  campaign_id: string;
  name: string;
  state: CTIState;
  record_count: number;
  actors: string[];
  techniques: string[];
  run_techniques?: string[];
  documented_techniques?: string[];
  frameworks: string[];
  evidence_ids: string[];
  evidence_urls: string[];
  entity_type?: string;
  attack_id?: string;
  aliases?: string[];
  profile_status?: string;
  knowledge_url?: string;
  knowledge_description?: string;
  knowledge_created?: string;
  knowledge_modified?: string;
  first_seen?: string;
  last_seen?: string;
  external_references?: CTIReference[];
}

interface CTITechnique {
  technique_id: string;
  name: string;
  family: string;
  tactics: string[];
  state: CTIState;
  record_count: number;
  actors: string[];
  campaigns: string[];
  run_actors?: string[];
  run_campaigns?: string[];
  reference_actors?: string[];
  reference_campaigns?: string[];
  run_supported?: boolean;
  reference_supported?: boolean;
  parent_technique_id?: string;
  description?: string;
  platforms?: string[];
  data_sources?: string[];
  knowledge_urls?: string[];
  relationship_description?: string;
  d3fend: CTID3FEND[];
  frameworks: string[];
  evidence_ids: string[];
  evidence_urls: string[];
}

interface CTIEvidence {
  evidence_id: string;
  title: string;
  url?: string;
  source?: string;
  observed_at?: string;
  evidence_status?: string;
  relationship?: string;
  actors?: string[];
  state?: CTIState;
  limitations?: string[];
}

interface CTINode {
  id: string;
  label: string;
  type: string;
  entity_type?: string;
  state: CTIState;
  size?: number;
  relevance_score?: number;
  group_key?: string;
  relationships?: string[];
  actors?: string[];
  campaigns?: string[];
  techniques?: string[];
  d3fend?: CTID3FEND[];
  evidence_ids?: string[];
  evidence_urls?: string[];
  run_techniques?: string[];
  documented_techniques?: string[];
  attack_id?: string;
  aliases?: string[];
  profile_status?: string;
  knowledge_url?: string;
  knowledge_references?: string[];
  knowledge_description?: string;
  knowledge_created?: string;
  knowledge_modified?: string;
  first_seen?: string;
  last_seen?: string;
  description?: string;
  platforms?: string[];
  data_sources?: string[];
}

interface CTIEdge {
  id?: string;
  source: string;
  target: string;
  type: string;
  state: CTIState;
  weight?: number;
  evidence_ids?: string[];
  knowledge_urls?: string[];
}

interface CTISimNode extends SimulationNodeDatum {
  id: string;
  model: CTINode;
}

interface CTISimLink extends SimulationLinkDatum<CTISimNode> {
  id: string;
  model: CTIEdge;
}

interface CTISnapshot {
  schema_version: string;
  model_version: string;
  generated_at: string;
  scope: {
    organization: string;
    domains: string[];
    sector?: string;
    country?: string;
    countries_of_operation?: string[];
  };
  overview: {
    actor_count: number;
    campaign_count: number;
    technique_count: number;
    run_technique_count?: number;
    reference_technique_count?: number;
    observed_count: number;
    inferred_count: number;
    related_count: number;
    reference_count: number;
    evidence_count: number;
    top_actor?: string;
    top_relevance_score?: number;
    highest_state?: CTIState;
  };
  actors: CTIActor[];
  campaigns: CTICampaign[];
  techniques: CTITechnique[];
  attack_matrix: {
    tactics: Array<{ tactic: string; technique_count: number; evidence_count: number; techniques: CTITechnique[] }>;
    unmapped: CTITechnique[];
    run_technique_count?: number;
    reference_technique_count?: number;
  };
  attack_flows: Array<{
    flow_id: string;
    name: string;
    state: CTIState;
    steps: Array<{ sequence: number; technique_id: string; name: string; tactics: string[] }>;
    limitations: string;
  }>;
  victimology: {
    sectors?: Array<{ name: string; count: number }>;
    countries?: Array<{ name: string; count: number }>;
    scope_sector?: string;
    scope_countries?: string[];
  };
  detection_coverage: {
    mapped_technique_count?: number;
    total_technique_count?: number;
    mapping_coverage_pct?: number;
    controls?: Array<{ id: string; name: string; techniques: string[] }>;
    run_technique_count?: number;
    reference_technique_count?: number;
  };
  graph: { nodes: CTINode[]; edges: CTIEdge[]; node_count: number; edge_count: number };
  evidence: CTIEvidence[];
  quality: { state_counts?: Record<CTIState, number>; source_count?: number; evidence_url_count?: number };
  limitations: string[];
}

const copyByLanguage = {
  es: {
    title: "CTI orientada por amenazas",
    subtitle: "Actores, campañas y TTP relacionados con la corrida, separados por estado analítico y evidencia trazable.",
    empty: "Esta corrida todavía no tiene un snapshot CTI versionado.",
    emptyHint: "Vuelve a procesar la corrida o genera el informe con el motor actual para construirlo desde la evidencia persistida.",
    tabs: ["Resumen", "Actores", "Campañas", "Matriz ATT&CK", "Flujos", "Cobertura", "Evidencia"],
    search: "Buscar actor",
    actors: "Actores",
    campaigns: "Campañas",
    techniques: "TTP",
    evidence: "Evidencias",
    relevance: "Relevancia contextual",
    state: "Filtrar por estado analítico",
    sources: "Fuentes",
    detail: "Lectura analítica",
    noRows: "No hay datos sustentados para esta vista.",
    graph: "Relaciones de inteligencia",
    graphHint: "Selecciona un nodo para revisar su relación. La posición es estable y no implica causalidad.",
    observed: "Observado",
    inferred: "Inferido",
    related: "Relacionado",
    reference: "Referencia",
    matrix: "TTP por táctica",
    flows: "Secuencias de campaña",
    victimology: "Contexto de victimología",
    detection: "Cobertura de detección y D3FEND",
    limitations: "Limitaciones",
    open: "Abrir evidencia"
  },
  en: {
    title: "Threat-informed CTI",
    subtitle: "Actors, campaigns and TTPs related to the run, separated by analytical state and traceable evidence.",
    empty: "This run does not yet contain a versioned CTI snapshot.",
    emptyHint: "Reprocess the run or generate its report with the current engine to build it from persisted evidence.",
    tabs: ["Overview", "Actors", "Campaigns", "ATT&CK matrix", "Flows", "Coverage", "Evidence"],
    search: "Search actor",
    actors: "Actors",
    campaigns: "Campaigns",
    techniques: "TTPs",
    evidence: "Evidence",
    relevance: "Contextual relevance",
    state: "Filter by analytical state",
    sources: "Sources",
    detail: "Analytical reading",
    noRows: "No supported data is available for this view.",
    graph: "Intelligence relationships",
    graphHint: "Select a node to inspect its relationship. Position is stable and does not imply causality.",
    observed: "Observed",
    inferred: "Inferred",
    related: "Related",
    reference: "Reference",
    matrix: "TTPs by tactic",
    flows: "Campaign sequences",
    victimology: "Victimology context",
    detection: "Detection and D3FEND coverage",
    limitations: "Limitations",
    open: "Open evidence"
  }
} as const;

const stateOrder: CTIState[] = ["OBSERVED", "INFERRED", "RELATED", "REFERENCE"];
const entityPalette = ["#0f8f83", "#246fa8", "#c06c0b", "#7b61a8", "#2f855a", "#b64f62", "#397f93", "#8b6d1d"];

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function colorForEntity(value: string): string {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0;
  return entityPalette[Math.abs(hash) % entityPalette.length];
}

function nodeColor(node: CTINode): string {
  if (node.type === "organization") return "#647889";
  if (node.type === "defense") return "#246fa8";
  if (isThreatEntityType(node.type) || node.type === "campaign") return colorForEntity(node.group_key || node.label);
  const owner = node.actors?.[0] || node.campaigns?.[0];
  return owner ? colorForEntity(owner) : "#0f9a9d";
}

function isThreatEntityType(type: string): boolean {
  return ["actor", "threat_actor", "threat_group", "intrusion_set", "threat"].includes(type);
}

function nodeSymbol(type: string): string {
  if (type === "organization") return "O";
  if (type === "campaign") return "C";
  if (type === "technique") return "T";
  if (type === "defense") return "D";
  if (type === "threat_group" || type === "intrusion_set") return "G";
  if (isThreatEntityType(type)) return "A";
  return "·";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function ctiFromRun(run?: RunRecord): CTISnapshot | null {
  const snapshotValue = run?.summary.decision_snapshot?.cti_snapshot;
  const metricValue = run?.summary.metrics?.cti;
  const value = isRecord(snapshotValue) && Object.keys(snapshotValue).length ? snapshotValue : metricValue;
  if (!isRecord(value) || !isRecord(value.overview) || !Array.isArray(value.actors)) return null;
  return value as unknown as CTISnapshot;
}

function stateLabel(state: CTIState, language: LanguageMode): string {
  const copy = copyByLanguage[language];
  return {
    OBSERVED: copy.observed,
    INFERRED: copy.inferred,
    RELATED: copy.related,
    REFERENCE: copy.reference
  }[state];
}

function entityTypeLabel(type: string, language: LanguageMode): string {
  const labels: Record<string, [string, string]> = {
    organization: ["Organización", "Organization"],
    actor: ["Actor", "Actor"],
    threat_actor: ["Actor de amenaza", "Threat actor"],
    threat_group: ["Grupo de amenaza", "Threat group"],
    intrusion_set: ["Conjunto de intrusión", "Intrusion set"],
    threat: ["Amenaza", "Threat"],
    campaign: ["Campaña", "Campaign"],
    technique: ["Técnica", "Technique"],
    defense: ["Defensa D3FEND", "D3FEND defense"]
  };
  return labels[type]?.[language === "es" ? 0 : 1] ?? type;
}

function relationLabel(type: string, language: LanguageMode): string {
  const labels: Record<string, [string, string]> = {
    contextually_relevant_to: ["Relevancia contextual", "Contextually relevant"],
    uses: ["Utiliza", "Uses"],
    associated_with: ["Asociado con", "Associated with"],
    countered_by: ["Contrarrestada por", "Countered by"]
  };
  return labels[type]?.[language === "es" ? 0 : 1] ?? type.replace(/_/g, " ");
}

function StateBadge({ state, language }: { state: CTIState; language: LanguageMode }) {
  return <span className={`cti-state cti-state-${state.toLowerCase()}`}>{stateLabel(state, language)}</span>;
}

function CTIMetric({ icon, label, value, detail }: { icon: ReactNode; label: string; value: string | number; detail?: string }) {
  return (
    <article className="cti-metric">
      <span className="cti-metric-icon">{icon}</span>
      <div><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</div>
    </article>
  );
}

function RelationshipMap({ graph, language }: { graph: CTISnapshot["graph"]; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  const nodes = graph.nodes;
  const nodeIds = useMemo(() => new Set(nodes.map((node) => node.id)), [nodes]);
  const edges = useMemo(() => graph.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)), [graph.edges, nodeIds]);
  const layoutScale = clamp(Math.sqrt(Math.max(1, nodes.length) / 46), 1, 2.4);
  const layoutWidth = 940 * layoutScale;
  const layoutHeight = 520 * layoutScale;
  const fitZoom = 1 / layoutScale;
  const svgRef = useRef<SVGSVGElement | null>(null);
  const simulationNodesRef = useRef<CTISimNode[]>([]);
  const initialPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [selectedId, setSelectedId] = useState(nodes[0]?.id ?? "");
  const [zoom, setZoom] = useState(fitZoom);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [panStart, setPanStart] = useState<{ clientX: number; clientY: number; x: number; y: number } | null>(null);
  const degree = useMemo(() => {
    const result = new Map<string, number>();
    edges.forEach((edge) => {
      result.set(edge.source, (result.get(edge.source) ?? 0) + 1);
      result.set(edge.target, (result.get(edge.target) ?? 0) + 1);
    });
    return result;
  }, [edges]);

  useEffect(() => {
    const simulationNodes: CTISimNode[] = nodes.map((node, index) => {
      const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
      const radius = Math.min(layoutWidth, layoutHeight) * (0.22 + (index % 5) * 0.055);
      return {
        id: node.id,
        model: node,
        x: layoutWidth / 2 + Math.cos(angle) * radius,
        y: layoutHeight / 2 + Math.sin(angle) * radius
      };
    });
    const byId = new Map(simulationNodes.map((node) => [node.id, node]));
    const simulationLinks: CTISimLink[] = edges.map((edge, index) => ({
      id: edge.id || `${edge.source}-${edge.target}-${index}`,
      source: edge.source,
      target: edge.target,
      model: edge
    })).filter((edge) => byId.has(String(edge.source)) && byId.has(String(edge.target)));
    simulationNodesRef.current = simulationNodes;
    const layout = forceSimulation<CTISimNode>(simulationNodes)
      .force("link", forceLink<CTISimNode, CTISimLink>(simulationLinks).id((node) => node.id).distance((link) => link.model.type === "contextually_relevant_to" ? 178 : Math.max(82, 138 - Math.min(38, Number(link.model.weight ?? 1) * 4))).strength((link) => link.model.type === "contextually_relevant_to" ? 0.2 : 0.3))
      .force("charge", forceManyBody<CTISimNode>().strength((node) => -154 - Math.sqrt(Math.max(1, degree.get(node.id) ?? 1)) * 30))
      .force("center", forceCenter<CTISimNode>(layoutWidth / 2, layoutHeight / 2))
      .force("collision", forceCollide<CTISimNode>().radius((node) => Math.max(Number(node.model.size ?? 12) + 13, Math.min(48, 22 + node.model.label.length * 1.1))).iterations(3))
      .alphaDecay(0.03)
      .velocityDecay(0.46)
      .stop();
    const iterations = nodes.length > 350 ? 135 : Math.min(240, Math.max(145, Math.round(nodes.length * 2.2)));
    for (let index = 0; index < iterations; index += 1) layout.tick();
    const settled = Object.fromEntries(simulationNodes.map((node) => [node.id, {
      x: clamp(Number(node.x ?? layoutWidth / 2), 34, layoutWidth - 34),
      y: clamp(Number(node.y ?? layoutHeight / 2), 34, layoutHeight - 34)
    }]));
    initialPositionsRef.current = settled;
    setPositions(settled);
    setPan({ x: 0, y: 0 });
    setZoom(fitZoom);
    return () => {
      layout.stop();
    };
  }, [degree, edges, fitZoom, layoutHeight, layoutWidth, nodes]);

  useEffect(() => {
    if (!nodes.some((node) => node.id === selectedId)) setSelectedId(nodes[0]?.id ?? "");
  }, [nodes, selectedId]);

  const selected = nodes.find((node) => node.id === selectedId) ?? nodes[0];
  const directEdges = selected ? edges.filter((edge) => edge.source === selected.id || edge.target === selected.id) : [];
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const owners = nodes.filter((node) => isThreatEntityType(node.type) || node.type === "campaign");

  function graphPoint(event: ReactPointerEvent<SVGSVGElement>) {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: layoutWidth / 2, y: layoutHeight / 2 };
    const rawX = ((event.clientX - rect.left) / rect.width) * 940;
    const rawY = ((event.clientY - rect.top) / rect.height) * 520;
    return { x: (rawX - pan.x) / zoom, y: (rawY - pan.y) / zoom };
  }

  function resetGraph() {
    setPan({ x: 0, y: 0 });
    setZoom(fitZoom);
    simulationNodesRef.current.forEach((node) => {
      const initial = initialPositionsRef.current[node.id];
      if (initial) {
        node.x = initial.x;
        node.y = initial.y;
        node.fx = null;
        node.fy = null;
      }
    });
    setPositions({ ...initialPositionsRef.current });
  }

  if (!nodes.length) return <div className="cti-empty-inline">{copy.noRows}</div>;
  return (
    <div className="cti-relationship-layout">
      <div className="cti-network" role="img" aria-label={copy.graph}>
        <div className="cti-network-tools">
          <button type="button" title={language === "es" ? "Acercar" : "Zoom in"} onClick={() => setZoom((value) => clamp(value + 0.18, 0.2, 2.6))}><ZoomIn size={15} /></button>
          <button type="button" title={language === "es" ? "Alejar" : "Zoom out"} onClick={() => setZoom((value) => clamp(value - 0.18, 0.2, 2.6))}><ZoomOut size={15} /></button>
          <button type="button" title={language === "es" ? "Restablecer" : "Reset"} onClick={resetGraph}><RotateCcw size={15} /></button>
        </div>
        <svg
          ref={svgRef}
          viewBox="0 0 940 520"
          preserveAspectRatio="xMidYMid meet"
          onWheel={(event: ReactWheelEvent<SVGSVGElement>) => {
            event.preventDefault();
            setZoom((value) => clamp(value + (event.deltaY < 0 ? 0.1 : -0.1), 0.2, 2.6));
          }}
          onPointerDown={(event) => {
            if (draggingNodeId) return;
            setPanStart({ clientX: event.clientX, clientY: event.clientY, x: pan.x, y: pan.y });
            event.currentTarget.setPointerCapture(event.pointerId);
          }}
          onPointerMove={(event) => {
            if (draggingNodeId) {
              const point = graphPoint(event);
              const node = simulationNodesRef.current.find((item) => item.id === draggingNodeId);
              if (node) {
                const x = clamp(point.x, 30, layoutWidth - 30);
                const y = clamp(point.y, 30, layoutHeight - 30);
                node.x = x;
                node.y = y;
                node.fx = x;
                node.fy = y;
                setPositions((current) => ({ ...current, [draggingNodeId]: { x, y } }));
              }
              return;
            }
            if (!panStart || !svgRef.current) return;
            const rect = svgRef.current.getBoundingClientRect();
            setPan({
              x: clamp(panStart.x + ((event.clientX - panStart.clientX) / rect.width) * 940, -420, 420),
              y: clamp(panStart.y + ((event.clientY - panStart.clientY) / rect.height) * 520, -260, 260)
            });
          }}
          onPointerUp={() => { setDraggingNodeId(null); setPanStart(null); }}
          onPointerLeave={() => { setDraggingNodeId(null); setPanStart(null); }}
        >
          <defs><pattern id="cti-grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M 32 0 L 0 0 0 32" className="cti-grid-line" /></pattern></defs>
          <rect width="940" height="520" fill="url(#cti-grid)" />
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {edges.map((edge, index) => {
              const source = positions[edge.source];
              const target = positions[edge.target];
              const sourceNode = nodeById.get(edge.source);
              if (!source || !target) return null;
              const active = selected?.id === edge.source || selected?.id === edge.target;
              return <line key={edge.id || `${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} className={`cti-edge cti-edge-${edge.state.toLowerCase()}${active ? " active" : ""}`} style={{ stroke: sourceNode ? nodeColor(sourceNode) : undefined, strokeWidth: Math.min(4, 0.9 + Math.log2(Number(edge.weight ?? 1) + 1) * 0.45) }} />;
            })}
            {nodes.map((node) => {
              const position = positions[node.id] ?? { x: layoutWidth / 2, y: layoutHeight / 2 };
              const radius = clamp(Number(node.size ?? 12), 10, 29);
              const isSelected = selected?.id === node.id;
              const showLabel = isSelected || node.type === "organization" || node.type === "campaign" || isThreatEntityType(node.type) || (degree.get(node.id) ?? 0) >= 4;
              return (
                <g key={node.id} className={isSelected ? "cti-node selected" : "cti-node"} transform={`translate(${position.x} ${position.y})`} onPointerDown={(event) => { event.stopPropagation(); setDraggingNodeId(node.id); setSelectedId(node.id); event.currentTarget.setPointerCapture(event.pointerId); }} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") setSelectedId(node.id); }}>
                  <circle r={radius} className={`cti-node-fill cti-node-${node.state.toLowerCase()}`} style={{ fill: nodeColor(node) }} />
                  <text className="cti-node-symbol" textAnchor="middle" dominantBaseline="central">{nodeSymbol(node.type)}</text>
                  {showLabel ? <text className="cti-node-label" y={radius + 14} textAnchor="middle">{node.label.length > 28 ? `${node.label.slice(0, 26)}…` : node.label}</text> : null}
                  <title>{node.label} · {degree.get(node.id) ?? 0}</title>
                </g>
              );
            })}
          </g>
        </svg>
        <div className="cti-entity-legend">
          {owners.map((node) => <span key={node.id}><i style={{ background: nodeColor(node) }} />{node.label}</span>)}
          <span><i className="technique" />TTP</span><span><i className="defense" />D3FEND</span>
        </div>
      </div>
      <aside className="cti-node-detail">
        <span>{copy.detail}</span>
        <strong>{selected?.label}</strong>
        {selected ? <StateBadge state={selected.state} language={language} /> : null}
        <dl>
          <div><dt>{copy.relevance}</dt><dd>{selected?.relevance_score ?? "N/D"}</dd></div>
          <div><dt>{language === "es" ? "Tipo" : "Type"}</dt><dd>{selected ? entityTypeLabel(selected.entity_type || selected.type, language) : "N/D"}</dd></div>
          <div><dt>{language === "es" ? "Conexiones" : "Links"}</dt><dd>{directEdges.length}</dd></div>
          {selected?.attack_id ? <div><dt>ATT&CK</dt><dd>{selected.attack_id}</dd></div> : null}
        </dl>
        {directEdges.length ? <div className="cti-node-connections">{directEdges.map((edge, index) => {
          const other = nodeById.get(edge.source === selected?.id ? edge.target : edge.source);
          const support = edge.evidence_ids?.length
            ? `${edge.evidence_ids.length} ${copy.evidence.toLocaleLowerCase()}`
            : edge.knowledge_urls?.length
              ? (language === "es" ? "Referencia ATT&CK" : "ATT&CK reference")
              : stateLabel(edge.state, language);
          return other ? <button type="button" key={edge.id || index} onClick={() => setSelectedId(other.id)}><i style={{ background: nodeColor(other) }} /><span><strong>{other.label}</strong><small>{relationLabel(edge.type, language)} · {support}</small></span></button> : null;
        })}</div> : null}
        {selected?.evidence_urls?.length ? <div className="cti-node-evidence">{selected.evidence_urls.map((url, index) => <a href={url} target="_blank" rel="noreferrer" key={url} title={url}><ExternalLink size={13} />{copy.evidence} {index + 1}</a>)}</div> : null}
        {selected?.knowledge_url ? <a className="cti-knowledge-link" href={selected.knowledge_url} target="_blank" rel="noreferrer"><ExternalLink size={13} />{language === "es" ? "Perfil oficial ATT&CK" : "Official ATT&CK profile"}</a> : null}
        {selected?.knowledge_description ? <details className="cti-knowledge-description"><summary>{language === "es" ? "Contexto documentado" : "Documented context"}</summary><p>{selected.knowledge_description}</p></details> : null}
        <p>{copy.graphHint}</p>
      </aside>
    </div>
  );
}

interface MatrixEntityOption {
  key: string;
  name: string;
  type: "actor" | "campaign";
  color: string;
}

const attackEnterpriseTactics = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Stealth",
  "Defense Impairment",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact"
] as const;

function AttackMatrixView({ cti, language }: { cti: CTISnapshot; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  const [selectedEntities, setSelectedEntities] = useState<string[]>([]);
  const [showAllTactics, setShowAllTactics] = useState(true);
  const options = useMemo<MatrixEntityOption[]>(() => [
    ...cti.actors.map((actor) => ({
      key: `actor:${actor.name}`,
      name: actor.name,
      type: "actor" as const,
      color: colorForEntity(actor.name)
    })),
    ...cti.campaigns.map((campaign) => ({
      key: `campaign:${campaign.name}`,
      name: campaign.name,
      type: "campaign" as const,
      color: colorForEntity(campaign.name)
    }))
  ], [cti.actors, cti.campaigns]);
  const validKeys = useMemo(() => new Set(options.map((option) => option.key)), [options]);

  useEffect(() => {
    setSelectedEntities((current) => current.filter((key) => validKeys.has(key)));
  }, [validKeys]);

  const selectedOptions = options.filter((option) => selectedEntities.includes(option.key));
  const sourceTactics = new Map(cti.attack_matrix.tactics.map((tactic) => [tactic.tactic, tactic]));
  const tacticNames = [
    ...attackEnterpriseTactics,
    ...cti.attack_matrix.tactics.map((tactic) => tactic.tactic).filter((tactic) => !attackEnterpriseTactics.includes(tactic as typeof attackEnterpriseTactics[number]))
  ];
  const visibleTactics = tacticNames.map((tacticName) => {
    const tactic = sourceTactics.get(tacticName);
    const techniques = (tactic?.techniques ?? []).filter((technique) => {
      if (!selectedOptions.length) return true;
      return selectedOptions.some((option) => (
        option.type === "actor"
          ? technique.actors.includes(option.name)
          : technique.campaigns.includes(option.name)
      ));
    });
    return {
      tactic: tacticName,
      technique_count: techniques.length,
      evidence_count: techniques.reduce((total, technique) => total + Math.max(technique.evidence_ids.length, technique.evidence_urls.length), 0),
      techniques
    };
  }).filter((tactic) => showAllTactics || tactic.techniques.length > 0);
  const visibleTechniqueIds = new Set(visibleTactics.flatMap((tactic) => tactic.techniques.map((technique) => technique.technique_id)));

  function toggleEntity(key: string) {
    setSelectedEntities((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]);
  }

  return (
    <>
      <div className="cti-matrix-filter" aria-label={language === "es" ? "Filtrar matriz por actor o campaña" : "Filter matrix by actor or campaign"}>
        <div className="cti-matrix-filter-heading">
          <div>
            <strong>{language === "es" ? "Trazabilidad por actor y campaña" : "Actor and campaign traceability"}</strong>
            <span>{language === "es" ? "Selecciona uno o varios. Sin selección se muestran todas las TTP relacionadas." : "Select one or more. With no selection, every related TTP is shown."}</span>
          </div>
          <small>{visibleTechniqueIds.size} TTP · {selectedOptions.length || (language === "es" ? "todos" : "all")}</small>
        </div>
        <div className="cti-matrix-view-toggle" aria-label={language === "es" ? "Vista de tácticas" : "Tactic view"}>
          <button type="button" aria-pressed={showAllTactics} className={showAllTactics ? "selected" : ""} onClick={() => setShowAllTactics(true)}>{language === "es" ? "Matriz Enterprise completa" : "Full Enterprise matrix"}</button>
          <button type="button" aria-pressed={!showAllTactics} className={!showAllTactics ? "selected" : ""} onClick={() => setShowAllTactics(false)}>{language === "es" ? "Solo tácticas relacionadas" : "Related tactics only"}</button>
        </div>
        <div className="cti-matrix-filter-options">
          <button type="button" aria-pressed={!selectedEntities.length} className={!selectedEntities.length ? "selected" : ""} onClick={() => setSelectedEntities([])}>
            {language === "es" ? "Todos" : "All"}
          </button>
          {options.map((option) => (
            <button
              type="button"
              key={option.key}
              aria-pressed={selectedEntities.includes(option.key)}
              className={selectedEntities.includes(option.key) ? "selected" : ""}
              onClick={() => toggleEntity(option.key)}
              style={{ "--entity-color": option.color } as CSSProperties}
            >
              <i />
              <span>{option.name}</span>
              <small>{option.type === "actor" ? (language === "es" ? "Actor" : "Actor") : (language === "es" ? "Campaña" : "Campaign")}</small>
            </button>
          ))}
        </div>
      </div>
      {visibleTactics.length ? (
        <div className="cti-attack-matrix-viewport" tabIndex={0} aria-label={copy.matrix}>
          <div className="cti-attack-matrix-board" style={{ "--tactic-count": visibleTactics.length } as CSSProperties}>
            {visibleTactics.map((tactic) => (
              <article key={tactic.tactic} className="cti-tactic-column">
                <header>
                  <strong>{tactic.tactic}</strong>
                  <span>{tactic.techniques.length} TTP</span>
                </header>
                <div className="cti-tactic-techniques">
                  {!tactic.techniques.length ? <span className="cti-tactic-empty">{language === "es" ? "Sin TTP relacionadas" : "No related TTPs"}</span> : null}
                  {tactic.techniques.map((technique) => {
                    const owners = options.filter((option) => (
                      option.type === "actor"
                        ? technique.actors.includes(option.name)
                        : technique.campaigns.includes(option.name)
                    ));
                    return (
                      <details className="cti-matrix-technique" key={`${tactic.tactic}-${technique.technique_id}`}>
                        <summary>
                          <span><strong>{technique.technique_id}</strong><small>{technique.name}</small></span>
                          <span className="cti-technique-owners" aria-label={language === "es" ? "Entidades relacionadas" : "Related entities"}>
                            {owners.slice(0, 6).map((owner) => <i key={owner.key} style={{ background: owner.color }} title={`${owner.name} · ${owner.type}`} />)}
                            {owners.length > 6 ? <b>+{owners.length - 6}</b> : null}
                          </span>
                        </summary>
                        <div className="cti-matrix-technique-detail">
                          <StateBadge state={technique.state} language={language} />
                          <div className="cti-support-flags">
                            {technique.run_supported ? <span className="run">{language === "es" ? "Sustentada por la corrida" : "Run-supported"}</span> : null}
                            {technique.reference_supported ? <span className="reference">{language === "es" ? "Documentada en ATT&CK" : "ATT&CK documented"}</span> : null}
                          </div>
                          <p><strong>{language === "es" ? "Actores/grupos en la corrida" : "Run actors/groups"}:</strong> {technique.run_actors?.join(", ") || "N/D"}</p>
                          <p><strong>{language === "es" ? "Actores/grupos de referencia" : "Reference actors/groups"}:</strong> {technique.reference_actors?.join(", ") || "N/D"}</p>
                          <p><strong>{language === "es" ? "Campañas" : "Campaigns"}:</strong> {[...(technique.run_campaigns ?? []), ...(technique.reference_campaigns ?? [])].filter((value, index, values) => values.indexOf(value) === index).join(", ") || "N/D"}</p>
                          {technique.parent_technique_id ? <p><strong>{language === "es" ? "Técnica padre" : "Parent technique"}:</strong> {technique.parent_technique_id}</p> : null}
                          {technique.platforms?.length ? <p><strong>{language === "es" ? "Plataformas" : "Platforms"}:</strong> {technique.platforms.join(", ")}</p> : null}
                          <p><strong>D3FEND:</strong> {technique.d3fend.map((item) => `${item.id}${item.name ? ` · ${item.name}` : ""}`).join(", ") || "N/D"}</p>
                          <p><strong>{copy.evidence}:</strong> {technique.evidence_urls.length || technique.evidence_ids.length}</p>
                          {technique.evidence_urls.length ? <div className="cti-matrix-evidence-links">{technique.evidence_urls.map((url, index) => <a href={url} target="_blank" rel="noreferrer" key={`${url}-${index}`} title={url}><ExternalLink size={12} />{copy.evidence} {index + 1}</a>)}</div> : null}
                          {technique.knowledge_urls?.length ? <div className="cti-matrix-evidence-links">{technique.knowledge_urls.map((url, index) => <a href={url} target="_blank" rel="noreferrer" key={`${url}-${index}`} title={url}><ExternalLink size={12} />ATT&CK {index + 1}</a>)}</div> : null}
                          {technique.relationship_description ? <details className="cti-knowledge-description"><summary>{language === "es" ? "Relación documentada" : "Documented relationship"}</summary><p>{technique.relationship_description}</p></details> : null}
                        </div>
                      </details>
                    );
                  })}
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : <div className="cti-empty-inline">{copy.noRows}</div>}
    </>
  );
}

function projectSnapshotByState(cti: CTISnapshot, state: CTIState | "ALL"): CTISnapshot {
  if (state === "ALL") return cti;
  const actors = cti.actors.filter((row) => row.state === state);
  const campaigns = cti.campaigns.filter((row) => row.state === state);
  const techniques = cti.techniques.filter((row) => row.state === state);
  const evidence = cti.evidence.filter((row) => (row.state ?? "REFERENCE") === state);
  const entityIds = new Set<string>([
    "scope:organization",
    ...actors.map((row) => row.actor_id),
    ...campaigns.map((row) => row.campaign_id),
    ...techniques.map((row) => `technique:${row.technique_id}`)
  ]);
  const graphEdges = cti.graph.edges.filter((edge) => edge.state === state);
  graphEdges.forEach((edge) => {
    entityIds.add(edge.source);
    entityIds.add(edge.target);
  });
  const graphNodes = cti.graph.nodes.filter((node) => entityIds.has(node.id));
  const tacticRows = cti.attack_matrix.tactics
    .map((row) => {
      const rows = row.techniques.filter((technique) => technique.state === state);
      return {
        ...row,
        technique_count: rows.length,
        evidence_count: rows.reduce((total, technique) => total + technique.record_count, 0),
        techniques: rows
      };
    })
    .filter((row) => row.techniques.length > 0);
  const techniqueIds = new Set(techniques.map((row) => row.technique_id));
  const controls = (cti.detection_coverage.controls ?? [])
    .map((control) => ({ ...control, techniques: control.techniques.filter((id) => techniqueIds.has(id)) }))
    .filter((control) => control.techniques.length > 0);
  const mappedTechniqueCount = new Set(controls.flatMap((control) => control.techniques)).size;

  return {
    ...cti,
    actors,
    campaigns,
    techniques,
    evidence,
    attack_matrix: {
      ...cti.attack_matrix,
      tactics: tacticRows,
      unmapped: cti.attack_matrix.unmapped.filter((row) => row.state === state)
    },
    attack_flows: cti.attack_flows.filter((row) => row.state === state),
    detection_coverage: {
      ...cti.detection_coverage,
      controls,
      mapped_technique_count: mappedTechniqueCount,
      total_technique_count: techniques.length,
      mapping_coverage_pct: techniques.length ? Math.round((mappedTechniqueCount / techniques.length) * 1000) / 10 : undefined
    },
    graph: {
      ...cti.graph,
      nodes: graphNodes,
      edges: graphEdges,
      node_count: graphNodes.length,
      edge_count: graphEdges.length
    }
  };
}

export function CTIView({ run, language, onOpenRelationshipGraph }: { run?: RunRecord; language: LanguageMode; onOpenRelationshipGraph?: () => void }) {
  const copy = copyByLanguage[language];
  const cti = ctiFromRun(run);
  const [tab, setTab] = useState<CTITab>("overview");
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<CTIState | "ALL">("ALL");
  const [selectedActorId, setSelectedActorId] = useState("");
  const tabs: CTITab[] = ["overview", "actors", "campaigns", "matrix", "flows", "coverage", "evidence"];

  const visibleCti = useMemo(
    () => cti ? projectSnapshotByState(cti, stateFilter) : null,
    [cti, stateFilter]
  );

  const filteredActors = useMemo(() => {
    if (!visibleCti) return [];
    const needle = query.trim().toLocaleLowerCase();
    return visibleCti.actors.filter((actor) => {
      const haystack = [actor.name, ...actor.techniques, ...actor.campaigns, ...actor.frameworks].join(" ").toLocaleLowerCase();
      return !needle || haystack.includes(needle);
    });
  }, [visibleCti, query]);

  if (!cti) {
    return (
      <section className="panel cti-empty-state">
        <ShieldEllipsis size={30} />
        <h2>{copy.empty}</h2>
        <p>{copy.emptyHint}</p>
      </section>
    );
  }

  const currentCti = visibleCti ?? cti;
  const selectedActor = visibleCti?.actors.find((actor) => actor.actor_id === selectedActorId) ?? filteredActors[0] ?? visibleCti?.actors[0];
  const stateCounts = cti.quality?.state_counts ?? {
    OBSERVED: cti.overview.observed_count,
    INFERRED: cti.overview.inferred_count,
    RELATED: cti.overview.related_count,
    REFERENCE: cti.overview.reference_count
  };
  const stateTotal = stateOrder.reduce((total, state) => total + Number(stateCounts[state] ?? 0), 0);

  return (
    <div className="view-stack product-workspace cti-workspace">
      <section className="panel workspace-hero cti-header">
        <div className="panel-title-row">
          <div><h2>{copy.title}</h2><p>{copy.subtitle}</p></div>
          <ShieldEllipsis size={24} />
        </div>
        <div className="cti-scope-line">
          <strong>{cti.scope.organization}</strong>
          <span>{cti.scope.domains.length} {language === "es" ? "dominios" : "domains"}</span>
          {cti.scope.sector ? <span>{cti.scope.sector}</span> : null}
        </div>
      </section>

      <section className="cti-metrics" aria-label={language === "es" ? "Resumen CTI" : "CTI summary"}>
        <CTIMetric icon={<Target size={18} />} label={copy.actors} value={cti.overview.actor_count} detail={cti.overview.top_actor} />
        <CTIMetric icon={<Radar size={18} />} label={copy.campaigns} value={cti.overview.campaign_count} />
        <CTIMetric icon={<Boxes size={18} />} label={copy.techniques} value={cti.overview.technique_count} detail={`${cti.overview.run_technique_count ?? 0} ${language === "es" ? "corrida" : "run"} · ${cti.overview.reference_technique_count ?? 0} ATT&CK`} />
        <CTIMetric icon={<ShieldCheck size={18} />} label={copy.evidence} value={cti.overview.evidence_count} detail={`${cti.quality?.source_count ?? 0} ${copy.sources.toLocaleLowerCase()}`} />
      </section>

      <section className="panel cti-state-filter" aria-label={copy.state}>
        <div className="cti-state-filter-heading"><Filter size={18} /><div><strong>{copy.state}</strong><span>{language === "es" ? "Aplica a entidades, grafo, matriz, flujos y evidencia." : "Applies to entities, graph, matrix, flows and evidence."}</span></div></div>
        <div className="cti-state-strip">
          <button type="button" className={stateFilter === "ALL" ? "selected" : ""} aria-pressed={stateFilter === "ALL"} onClick={() => setStateFilter("ALL")}>
            <span className="cti-state-dot cti-state-dot-all" />
            <span>{language === "es" ? "Todos" : "All"}</span>
            <strong>{stateTotal}</strong>
          </button>
          {stateOrder.map((state) => (
            <button type="button" key={state} aria-pressed={stateFilter === state} className={stateFilter === state ? "selected" : ""} onClick={() => setStateFilter(state)}>
              <span className={`cti-state-dot cti-state-dot-${state.toLowerCase()}`} />
              <span>{stateLabel(state, language)}</span>
              <strong>{stateCounts[state] ?? 0}</strong>
            </button>
          ))}
        </div>
      </section>

      <section className="panel cti-navigation">
        <div className="cti-tabs" role="tablist">
          {tabs.map((item, index) => <button key={item} type="button" role="tab" aria-selected={tab === item} className={tab === item ? "selected" : ""} onClick={() => setTab(item)}>{copy.tabs[index]}</button>)}
        </div>
        {(tab === "overview" || tab === "actors") ? (
          <label className="cti-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={copy.search} /></label>
        ) : null}
      </section>

      {tab === "overview" ? (
        <div className="cti-overview-grid">
          <article className="panel workspace-content-panel cti-tab-panel cti-graph-entry"><div className="panel-title-row compact"><div><h2>{copy.graph}</h2><p>{language === "es" ? "La trazabilidad CTI se integra en el grafo general para relacionar alcance, evidencia, actores, grupos, campañas, malware, herramientas y TTP sin duplicar lecturas." : "CTI traceability is integrated into the main graph to connect scope, evidence, actors, groups, campaigns, malware, tools and TTPs without duplicate readings."}</p></div><Network size={18} /></div><div className="cti-graph-entry-summary"><span><strong>{currentCti.graph.node_count}</strong>{language === "es" ? "nodos CTI" : "CTI nodes"}</span><span><strong>{currentCti.graph.edge_count}</strong>{language === "es" ? "relaciones" : "relationships"}</span><button type="button" onClick={onOpenRelationshipGraph}><Network size={16} />{language === "es" ? "Abrir grafo CTI y adversarios" : "Open CTI and adversary graph"}</button></div></article>
          <article className="panel workspace-content-panel cti-tab-panel cti-ranking-panel"><div className="panel-title-row compact"><div><h2>{copy.actors}</h2><p>{copy.relevance}</p></div><Target size={18} /></div><ActorList actors={filteredActors.slice(0, 8)} selectedId={selectedActor?.actor_id} onSelect={setSelectedActorId} language={language} /></article>
        </div>
      ) : null}

      {tab === "actors" ? (
        <section className="panel workspace-content-panel cti-tab-panel cti-actor-workbench"><ActorList actors={filteredActors} selectedId={selectedActor?.actor_id} onSelect={setSelectedActorId} language={language} /><ActorDetail actor={selectedActor} language={language} /></section>
      ) : null}

      {tab === "campaigns" ? (
        <section className="panel workspace-content-panel cti-tab-panel cti-table-panel"><div className="panel-title-row compact"><div><h2>{copy.campaigns}</h2><p>{language === "es" ? "Campañas sustentadas por la corrida o documentadas en ATT&CK, claramente diferenciadas." : "Campaigns supported by the run or documented in ATT&CK, clearly separated."}</p></div><Activity size={18} /></div><CampaignTable campaigns={currentCti.campaigns} language={language} /></section>
      ) : null}

      {tab === "matrix" ? (
        <section className="panel workspace-content-panel cti-tab-panel cti-matrix-panel"><div className="panel-title-row compact"><div><h2>{copy.matrix}</h2><p>{language === "es" ? "Cobertura completa y bidireccional de ATT&CK Enterprise, Mobile e ICS y de las demás familias CTI. La referencia documental nunca se presenta como actividad observada." : "Complete bidirectional coverage of ATT&CK Enterprise, Mobile and ICS plus the other CTI families. Reference knowledge is never presented as observed activity."}</p></div><Boxes size={18} /></div><FrameworkCatalogExplorer cti={currentCti} language={language} /></section>
      ) : null}

      {tab === "flows" ? (
        <section className="panel workspace-content-panel cti-tab-panel cti-flow-panel"><div className="panel-title-row compact"><div><h2>{copy.flows}</h2><p>{language === "es" ? "Orden táctico de técnicas relacionadas; no se presenta como cronología sin timestamps por paso." : "Tactical ordering of related techniques; it is not presented as a timeline without per-step timestamps."}</p></div><Workflow size={18} /></div>{currentCti.attack_flows.length ? currentCti.attack_flows.map((flow) => <article className="cti-flow" key={flow.flow_id}><header><strong>{flow.name}</strong><StateBadge state={flow.state} language={language} /></header><div>{flow.steps.map((step) => <div className="cti-flow-step" key={`${flow.flow_id}-${step.sequence}`}><span>{step.sequence}</span><strong>{step.technique_id}</strong><small>{step.name}</small></div>)}</div><p>{flow.limitations}</p></article>) : <div className="cti-empty-inline">{copy.noRows}</div>}</section>
      ) : null}

      {tab === "coverage" ? (
        <div className="cti-coverage-grid"><article className="panel workspace-content-panel cti-tab-panel"><div className="panel-title-row compact"><div><h2>{copy.victimology}</h2><p>{language === "es" ? "Sectores y países mencionados o relacionados, sin atribuir ubicación del atacante." : "Mentioned or related sectors and countries, without attributing attacker location."}</p></div><Radar size={18} /></div><CoverageRows rows={[...(cti.victimology.sectors ?? []), ...(cti.victimology.countries ?? [])]} language={language} /></article><article className="panel workspace-content-panel cti-tab-panel"><div className="panel-title-row compact"><div><h2>{copy.detection}</h2><p>{language === "es" ? "Mapeo defensivo aplicable a las TTP visibles; no equivale a control implementado." : "Defensive mapping applicable to visible TTPs; it does not mean a control is implemented."}</p></div><ShieldCheck size={18} /></div><div className="cti-coverage-score"><strong>{currentCti.detection_coverage.mapping_coverage_pct ?? 0}%</strong><span>{currentCti.detection_coverage.mapped_technique_count ?? 0}/{currentCti.detection_coverage.total_technique_count ?? 0} TTP</span></div><CoverageRows rows={(currentCti.detection_coverage.controls ?? []).map((item) => ({ name: `${item.id} · ${item.name}`, count: item.techniques.length }))} language={language} /></article></div>
      ) : null}

      {tab === "evidence" ? (
        <section className="panel workspace-content-panel cti-tab-panel cti-evidence-panel"><div className="panel-title-row compact"><div><h2>{copy.evidence}</h2><p>{language === "es" ? "Referencias que sustentan esta lectura CTI; abrir una URL no cambia su estado de validación." : "References supporting this CTI reading; opening a URL does not change its validation state."}</p></div><ExternalLink size={18} /></div><EvidenceTable rows={currentCti.evidence} language={language} /></section>
      ) : null}

      <details className="panel cti-limitations"><summary>{copy.limitations}</summary><ul>{cti.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details>
    </div>
  );
}

function ActorList({ actors, selectedId, onSelect, language }: { actors: CTIActor[]; selectedId?: string; onSelect: (id: string) => void; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  if (!actors.length) return <div className="cti-empty-inline">{copy.noRows}</div>;
  return <div className="cti-actor-list">{actors.map((actor) => <button type="button" key={actor.actor_id} className={actor.actor_id === selectedId ? "selected" : ""} onClick={() => onSelect(actor.actor_id)}><span><strong>{actor.name}</strong><small>{actor.evidence_count} {copy.evidence.toLocaleLowerCase()} · {actor.source_count} {copy.sources.toLocaleLowerCase()}</small></span><span className="cti-actor-score"><strong>{actor.relevance_score}</strong><StateBadge state={actor.state} language={language} /></span></button>)}</div>;
}

function ActorDetail({ actor, language }: { actor?: CTIActor; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  if (!actor) return <aside className="cti-actor-detail"><div className="cti-empty-inline">{copy.noRows}</div></aside>;
  return (
    <aside className="cti-actor-detail">
      <span className="eyebrow">{copy.detail}</span>
      <div className="cti-entity-title"><div><h3>{actor.name}</h3><small>{entityTypeLabel(actor.entity_type || "threat_actor", language)}{actor.attack_id ? ` · ${actor.attack_id}` : ""}</small></div><div className="cti-detail-status"><StateBadge state={actor.state} language={language} /><strong>{actor.relevance_score}/100</strong></div></div>
      <p>{actor.explanation}</p>
      <dl>
        <div><dt>{language === "es" ? "TTP sustentadas por la corrida" : "Run-supported TTPs"}</dt><dd><ValueChips values={actor.run_techniques ?? actor.techniques} /></dd></div>
        <div><dt>{language === "es" ? "Repertorio documentado ATT&CK" : "Documented ATT&CK repertoire"}</dt><dd><ValueChips values={actor.documented_techniques ?? []} /></dd></div>
        <div><dt>{copy.campaigns}</dt><dd><ValueChips values={actor.campaigns} /></dd></div>
        <div><dt>D3FEND</dt><dd><ValueChips values={actor.d3fend.map((item) => `${item.id}${item.name ? ` · ${item.name}` : ""}`)} /></dd></div>
        <div><dt>Frameworks</dt><dd><ValueChips values={actor.frameworks} /></dd></div>
      </dl>
      {actor.profile_status === "matched" ? (
        <details className="cti-profile-detail">
          <summary>{language === "es" ? "Ficha y fuentes ATT&CK" : "ATT&CK profile and sources"}</summary>
          {actor.aliases?.length ? <p><strong>{language === "es" ? "Alias" : "Aliases"}:</strong> {actor.aliases.join(", ")}</p> : null}
          {actor.knowledge_description ? <p className="cti-profile-description">{actor.knowledge_description}</p> : null}
          <div className="cti-profile-dates">
            {actor.first_seen ? <span>{language === "es" ? "Primera actividad" : "First seen"}: {shortDate(actor.first_seen)}</span> : null}
            {actor.last_seen ? <span>{language === "es" ? "Última actividad" : "Last seen"}: {shortDate(actor.last_seen)}</span> : null}
            {actor.knowledge_modified ? <span>{language === "es" ? "Actualizado" : "Updated"}: {shortDate(actor.knowledge_modified)}</span> : null}
          </div>
          {actor.contributors?.length ? <p><strong>{language === "es" ? "Contribuyentes" : "Contributors"}:</strong> {actor.contributors.join(", ")}</p> : null}
          <ReferenceLinks profileUrl={actor.knowledge_url} references={actor.external_references} language={language} />
        </details>
      ) : <p className="cti-profile-unmatched">{language === "es" ? "Sin coincidencia exacta en el catálogo ATT&CK local; no se asigna un repertorio por similitud de nombre." : "No exact match in the local ATT&CK catalog; no repertoire is assigned by name similarity."}</p>}
      {actor.evidence_urls.length ? <div className="cti-detail-links">{actor.evidence_urls.map((url, index) => <a href={url} target="_blank" rel="noreferrer" key={`${url}-${index}`} title={url}><ExternalLink size={14} />{copy.evidence} {index + 1}</a>)}</div> : null}
      {actor.limitations.length ? <ul>{actor.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : null}
    </aside>
  );
}

function ValueChips({ values }: { values: string[] }) {
  if (!values.length) return <>N/D</>;
  return <span className="cti-value-chips">{values.map((value, index) => <span key={`${value}-${index}`}>{value}</span>)}</span>;
}

function shortDate(value?: string): string {
  if (!value) return "N/D";
  return value.length >= 10 ? value.slice(0, 10) : value;
}

function ReferenceLinks({ profileUrl, references, language }: { profileUrl?: string; references?: CTIReference[]; language: LanguageMode }) {
  const urls = [
    ...(profileUrl ? [{ source_name: "MITRE ATT&CK", url: profileUrl }] : []),
    ...(references ?? [])
  ].filter((row, index, values) => row.url && values.findIndex((item) => item.url === row.url) === index);
  if (!urls.length) return null;
  return <div className="cti-reference-links">{urls.map((row, index) => <a href={row.url} target="_blank" rel="noreferrer" key={`${row.url}-${index}`}><ExternalLink size={13} />{row.external_id || row.source_name || (language === "es" ? "Fuente" : "Source")}</a>)}</div>;
}

function CampaignTable({ campaigns, language }: { campaigns: CTICampaign[]; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  if (!campaigns.length) return <div className="cti-empty-inline">{copy.noRows}</div>;
  return <div className="cti-campaign-list">{campaigns.map((campaign) => <details key={campaign.campaign_id}><summary><span><strong>{campaign.name}</strong><small>{campaign.attack_id ? `${campaign.attack_id} · ` : ""}{campaign.actors.join(", ") || (language === "es" ? "Actor no atribuido" : "Unattributed actor")}</small></span><span>{campaign.techniques.length} TTP · {campaign.record_count} {language === "es" ? "registros" : "records"}</span><StateBadge state={campaign.state} language={language} /></summary><div className="cti-campaign-detail"><p><strong>{language === "es" ? "TTP de la corrida" : "Run TTPs"}:</strong></p><ValueChips values={campaign.run_techniques ?? campaign.techniques} /><p><strong>{language === "es" ? "Repertorio ATT&CK" : "ATT&CK repertoire"}:</strong></p><ValueChips values={campaign.documented_techniques ?? []} /><p><strong>Frameworks:</strong></p><ValueChips values={campaign.frameworks} />{campaign.knowledge_description ? <details className="cti-profile-detail"><summary>{language === "es" ? "Contexto y fuentes oficiales" : "Official context and sources"}</summary><p className="cti-profile-description">{campaign.knowledge_description}</p><div className="cti-profile-dates">{campaign.first_seen ? <span>{language === "es" ? "Primera actividad" : "First seen"}: {shortDate(campaign.first_seen)}</span> : null}{campaign.last_seen ? <span>{language === "es" ? "Última actividad" : "Last seen"}: {shortDate(campaign.last_seen)}</span> : null}</div><ReferenceLinks profileUrl={campaign.knowledge_url} references={campaign.external_references} language={language} /></details> : null}{campaign.evidence_urls.length ? <div className="cti-campaign-evidence">{campaign.evidence_urls.map((url, index) => <a href={url} target="_blank" rel="noreferrer" key={`${url}-${index}`} title={url}><ExternalLink size={13} />{copy.evidence} {index + 1}</a>)}</div> : null}</div></details>)}</div>;
}

function CoverageRows({ rows, language }: { rows: Array<{ name: string; count: number }>; language: LanguageMode }) {
  const max = Math.max(1, ...rows.map((item) => item.count));
  if (!rows.length) return <div className="cti-empty-inline">{copyByLanguage[language].noRows}</div>;
  return <div className="cti-coverage-rows">{rows.map((item, index) => <div key={`${item.name}-${index}`}><header><span>{item.name}</span><strong>{item.count}</strong></header><span className="cti-bar"><i style={{ width: `${Math.max(4, (item.count / max) * 100)}%` }} /></span></div>)}</div>;
}

function EvidenceTable({ rows, language }: { rows: CTIEvidence[]; language: LanguageMode }) {
  const copy = copyByLanguage[language];
  if (!rows.length) return <div className="cti-empty-inline">{copy.noRows}</div>;
  return <div className="cti-evidence-list">{rows.map((row, index) => <article key={`${row.evidence_id}-${index}`}><b className="cti-evidence-number">{index + 1}</b><div><strong>{row.title}</strong><small>{row.source || "N/D"} · {row.relationship || "unclassified"}</small></div><StateBadge state={row.state ?? "REFERENCE"} language={language} />{row.url ? <a href={row.url} target="_blank" rel="noreferrer" title={row.url}><ExternalLink size={14} />{copy.open}</a> : <span>N/D</span>}</article>)}</div>;
}
