import {
  AtSign,
  Building2,
  Bug,
  Cpu,
  Crosshair,
  Database,
  ExternalLink,
  FileText,
  Globe2,
  Hash,
  Link2,
  Mail,
  MapPin,
  Network,
  Phone,
  Radio,
  RotateCcw,
  Search,
  ShieldAlert,
  UserRound,
  UserSearch,
  ZoomIn,
  ZoomOut
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
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
import { defaultDashboardFilters } from "../data/catalog";
import type { LanguageMode, RunRecord } from "../types";
import { buildDashboardModel } from "../utils/dashboard";
import {
  buildRelationshipGraph,
  filterRelationshipGraph,
  relationshipPerspectives,
  type RelationshipEdge,
  type RelationshipEntityType,
  type RelationshipNode,
  type RelationshipPerspectiveKey
} from "../utils/relationshipGraph";

interface SimNode extends SimulationNodeDatum {
  id: string;
  model: RelationshipNode;
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  id: string;
  model: RelationshipEdge;
}

const labels = {
  es: {
    title: "Grafo de análisis y relaciones",
    subtitle: "Conexiones trazables entre alcance, evidencias y entidades de la corrida seleccionada",
    records: "Registros procesados",
    entities: "Entidades visibles",
    relations: "Relaciones",
    components: "Componentes",
    newNodes: "Nodos nuevos",
    baseline: "Comparado con",
    noBaseline: "Primera corrida comparable",
    searchNodes: "Buscar entidad, URL, correo, teléfono o evidencia",
    onlyNew: "Solo nuevos",
    entityIndex: "Índice de nodos",
    entityIndexHint: "Todos los nodos de la vista; selecciona uno para centrar el análisis.",
    workbench: "Red de vínculos",
    workbenchSubtitle: "El tamaño representa centralidad de grado. La red se organiza una vez y queda fija para explorarla, acercarla o mover nodos manualmente.",
    perspectives: "Vistas del grafo",
    perspectivesSubtitle: "Selecciona una lectura para reducir la red sin modificar los datos.",
    detail: "Detalle de entidad",
    selectNode: "Selecciona un nodo para revisar sus metadatos, relaciones directas y evidencia.",
    directConnections: "Conexiones directas",
    metadata: "Metadatos",
    evidence: "Evidencias",
    noEvidence: "Sin URL de evidencia asociada.",
    noGraph: "La corrida seleccionada no contiene entidades ni relaciones trazables para representar.",
    centrality: "Centralidad de grado",
    pageRank: "PageRank",
    betweenness: "Intermediación",
    confidence: "Confianza",
    status: "Estado",
    degree: "Conexiones",
    processedNote: "Solo se muestran entidades y relaciones trazables de la corrida seleccionada. La disposición se calcula una vez; mover un nodo cambia únicamente su posición visual.",
    prospective: "Tendencia prospectiva de presión de señales",
    prospectiveSubtitle: "Lectura por horizonte basada en evidencia reciente, escenarios y contexto de la corrida.",
    prospectiveEmpty: "No hay evidencia suficiente para publicar una tendencia prospectiva.",
    prospectiveCaveat: "Índice heurístico de presión, no probabilidad calibrada de ataque. Debe leerse junto con evidencia y limitaciones.",
    scenario: "Escenario con mayor soporte",
    noScenario: "Sin escenario respaldado",
    legend: "Tipos de entidad",
    all: "Red completa",
    infrastructure: "Infraestructura",
    evidenceView: "Evidencia y fuentes",
    social: "Identidad y SOCMINT",
    threats: "Amenazas y TTP"
  },
  en: {
    title: "Relationship analysis graph",
    subtitle: "Traceable connections among scope, evidence and entities from the selected run",
    records: "Processed records",
    entities: "Visible entities",
    relations: "Relationships",
    components: "Components",
    newNodes: "New nodes",
    baseline: "Compared with",
    noBaseline: "First comparable run",
    searchNodes: "Search entity, URL, email, phone or evidence",
    onlyNew: "New only",
    entityIndex: "Node index",
    entityIndexHint: "Every node in this view; select one to focus the analysis.",
    workbench: "Link network",
    workbenchSubtitle: "Node size represents degree centrality. The network is laid out once and then remains fixed for zooming, inspection and manual node movement.",
    perspectives: "Graph views",
    perspectivesSubtitle: "Select a lens to reduce the network without changing the data.",
    detail: "Entity detail",
    selectNode: "Select a node to inspect metadata, direct relationships and evidence.",
    directConnections: "Direct connections",
    metadata: "Metadata",
    evidence: "Evidence",
    noEvidence: "No evidence URL is associated.",
    noGraph: "The selected run contains no traceable entities or relationships to display.",
    centrality: "Degree centrality",
    pageRank: "PageRank",
    betweenness: "Betweenness",
    confidence: "Confidence",
    status: "Status",
    degree: "Connections",
    processedNote: "Only traceable entities and relationships from the selected run are displayed. The layout is calculated once; moving a node changes only its visual position.",
    prospective: "Prospective signal-pressure trend",
    prospectiveSubtitle: "Horizon view based on recent evidence, scenarios and the current run context.",
    prospectiveEmpty: "There is not enough evidence to publish a prospective trend.",
    prospectiveCaveat: "Heuristic pressure index, not a calibrated attack probability. Read it with evidence and limitations.",
    scenario: "Best-supported scenario",
    noScenario: "No supported scenario",
    legend: "Entity types",
    all: "Complete network",
    infrastructure: "Infrastructure",
    evidenceView: "Evidence and sources",
    social: "Identity and SOCMINT",
    threats: "Threats and TTPs"
  }
};

const entityLabels: Record<LanguageMode, Record<RelationshipEntityType, string>> = {
  es: {
    organization: "Organización",
    domain: "Dominio",
    ip: "Dirección IP",
    url: "URL",
    email: "Correo",
    phone: "Teléfono",
    person: "Persona / perfil",
    country: "País",
    document: "Documento",
    hash: "Hash / indicador",
    social_account: "Cuenta social",
    hashtag: "Hashtag",
    technology: "Tecnología",
    vulnerability: "Vulnerabilidad",
    vulnerability_candidate: "CVE pendiente de versión",
    actor: "Actor",
    technique: "Técnica",
    source: "Fuente",
    evidence: "Registro"
  },
  en: {
    organization: "Organization",
    domain: "Domain",
    ip: "IP address",
    url: "URL",
    email: "Email",
    phone: "Phone",
    person: "Person / profile",
    country: "Country",
    document: "Document",
    hash: "Hash / indicator",
    social_account: "Social account",
    hashtag: "Hashtag",
    technology: "Technology",
    vulnerability: "Vulnerability",
    vulnerability_candidate: "CVE pending version",
    actor: "Actor",
    technique: "Technique",
    source: "Source",
    evidence: "Record"
  }
};

const legendTypes: RelationshipEntityType[] = [
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
];

export function RelationshipGraphView({
  run,
  runs = [],
  language
}: {
  run?: RunRecord;
  runs?: RunRecord[];
  language: LanguageMode;
}) {
  const copy = labels[language];
  const baselineRun = useMemo(() => comparableBaseline(run, runs), [run, runs]);
  const completeModel = useMemo(() => buildRelationshipGraph(run, baselineRun), [run, baselineRun]);
  const dashboardModel = useMemo(() => buildDashboardModel(run, defaultDashboardFilters), [run]);
  const [perspective, setPerspective] = useState<RelationshipPerspectiveKey>("all");
  const [nodeQuery, setNodeQuery] = useState("");
  const [onlyNew, setOnlyNew] = useState(false);
  const perspectiveModels = useMemo(
    () =>
      new Map(
        relationshipPerspectives.map((item) => [
          item.key,
          filterRelationshipGraph(completeModel, item.key)
        ])
      ),
    [completeModel]
  );
  const perspectiveGraph = perspectiveModels.get(perspective) ?? completeModel;
  const graph = useMemo(
    () => filterVisibleNodes(perspectiveGraph, nodeQuery, onlyNew),
    [perspectiveGraph, nodeQuery, onlyNew]
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId) ?? null;
  const connections = selectedNode
    ? graph.edges
        .filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
        .map((edge) => ({
          edge,
          node: graph.nodes.find((node) => node.id === (edge.source === selectedNode.id ? edge.target : edge.source))
        }))
        .filter((item): item is { edge: RelationshipEdge; node: RelationshipNode } => Boolean(item.node))
        .sort((left, right) => right.edge.weight - left.edge.weight)
    : [];

  useEffect(() => {
    if (selectedNodeId && !graph.nodes.some((node) => node.id === selectedNodeId)) setSelectedNodeId(null);
  }, [graph.nodes, selectedNodeId]);

  return (
    <div className="view-stack relationship-graph-view">
      <section className="panel relationship-overview">
        <div className="panel-title-row">
          <div>
            <h2>{copy.title}</h2>
            <p>{copy.subtitle}</p>
          </div>
          <Network size={20} />
        </div>
        <div className="relationship-kpis">
          <GraphKpi icon={<Database size={17} />} label={copy.records} value={completeModel.stats.processedRecords} />
          <GraphKpi icon={<Network size={17} />} label={copy.entities} value={graph.stats.totalNodes} />
          <GraphKpi icon={<Link2 size={17} />} label={copy.relations} value={graph.stats.totalEdges} />
          <GraphKpi icon={<Crosshair size={17} />} label={copy.components} value={graph.stats.connectedComponents} />
          <GraphKpi icon={<UserSearch size={17} />} label={copy.newNodes} value={graph.stats.newNodes} />
        </div>
        <div className="relationship-comparison-note">
          <span>{baselineRun ? `${copy.baseline} #${baselineRun.id}` : copy.noBaseline}</span>
          <strong>{completeModel.stats.renderedRecords}/{completeModel.stats.processedRecords}</strong>
        </div>
      </section>

      <section className="relationship-workbench">
        <article className="panel relationship-canvas-panel">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.workbench}</h2>
              <p>{copy.workbenchSubtitle}</p>
            </div>
            <span className="relationship-run-id">#{run?.id ?? "N/D"}</span>
          </div>
          <div className="relationship-filterbar">
            <label>
              <Search size={15} />
              <input
                value={nodeQuery}
                onChange={(event) => setNodeQuery(event.target.value)}
                placeholder={copy.searchNodes}
                type="search"
              />
            </label>
            <button
              className={onlyNew ? "active" : ""}
              disabled={!baselineRun}
              onClick={() => setOnlyNew((value) => !value)}
              type="button"
            >
              <UserSearch size={15} />
              {copy.onlyNew}
            </button>
          </div>
          {graph.nodes.length ? (
            <>
              <RelationshipNetwork
                nodes={graph.nodes}
                edges={graph.edges}
                selectedNodeId={selectedNodeId}
                onSelectNode={setSelectedNodeId}
                language={language}
              />
              <div className="relationship-legend" aria-label={copy.legend}>
                {legendTypes
                  .filter((type) => graph.nodes.some((node) => node.type === type))
                  .map((type) => (
                    <span className={`entity-legend entity-${type}`} key={type}>
                      <EntityIcon type={type} size={13} />
                      {entityLabels[language][type]}
                    </span>
                  ))}
              </div>
              <p className="relationship-method-note">{copy.processedNote}</p>
            </>
          ) : (
            <div className="chart-empty relationship-empty">{copy.noGraph}</div>
          )}
        </article>

        <aside className="panel relationship-side-panel">
          <div className="relationship-side-head">
            <strong>{copy.perspectives}</strong>
            <span>{copy.perspectivesSubtitle}</span>
          </div>
          <div className="relationship-perspective-list" role="tablist">
            {relationshipPerspectives.map((item) => {
              const itemGraph = perspectiveModels.get(item.key) ?? completeModel;
              return (
                <button
                  className={perspective === item.key ? "active" : ""}
                  key={item.key}
                  onClick={() => setPerspective(item.key)}
                  role="tab"
                  aria-selected={perspective === item.key}
                  type="button"
                >
                  <PerspectiveIcon perspective={item.key} />
                  <span>
                    <strong>{perspectiveLabel(item.key, copy)}</strong>
                    <em>{itemGraph.stats.totalNodes} · {itemGraph.stats.totalEdges}</em>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="relationship-node-index">
            <div className="relationship-side-head">
              <strong>{copy.entityIndex}</strong>
              <span>{copy.entityIndexHint}</span>
            </div>
            <div className="relationship-node-index-list">
              {[...graph.nodes]
                .sort((left, right) => Number(right.isNew) - Number(left.isNew) || right.degree - left.degree)
                .map((node) => (
                  <button
                    className={`${selectedNodeId === node.id ? "active" : ""}${node.isNew ? " is-new" : ""}`}
                    key={node.id}
                    onClick={() => setSelectedNodeId(node.id)}
                    type="button"
                  >
                    <EntityIcon type={node.type} size={15} />
                    <span><strong>{node.label}</strong><em>{entityLabels[language][node.type]} · {node.degree}</em></span>
                    {node.isNew ? <i>{language === "es" ? "Nuevo" : "New"}</i> : null}
                  </button>
                ))}
            </div>
          </div>

          <div className="relationship-node-detail">
            <div className="relationship-side-head">
              <strong>{copy.detail}</strong>
            </div>
            {selectedNode ? (
              <>
                <div className={`relationship-entity-head entity-${selectedNode.type}`}>
                  <span><EntityIcon type={selectedNode.type} size={19} /></span>
                  <div>
                    <strong>{selectedNode.label}</strong>
                    <em>{entityLabels[language][selectedNode.type]}</em>
                  </div>
                </div>
                <div className="relationship-detail-metrics">
                  <span><b>{copy.degree}</b><strong>{selectedNode.degree}</strong></span>
                  <span><b>{copy.centrality}</b><strong>{(selectedNode.centrality * 100).toFixed(1)}%</strong></span>
                  <span><b>{copy.pageRank}</b><strong>{(selectedNode.pageRank * 100).toFixed(2)}%</strong></span>
                  <span><b>{copy.betweenness}</b><strong>{(selectedNode.betweenness * 100).toFixed(2)}%</strong></span>
                  <span><b>{copy.confidence}</b><strong>{Math.round(selectedNode.confidence * 100)}%</strong></span>
                  <span><b>{copy.status}</b><strong>{selectedNode.status}</strong></span>
                </div>
                <DetailBlock title={copy.metadata}>
                  <dl className="relationship-metadata">
                    {Object.entries(selectedNode.metadata).map(([key, value]) => (
                      <div key={key}><dt>{humanizeKey(key)}</dt><dd>{String(value)}</dd></div>
                    ))}
                  </dl>
                </DetailBlock>
                <DetailBlock title={copy.directConnections}>
                  <div className="relationship-connections">
                    {connections.map(({ edge, node }) => (
                      <button type="button" key={edge.id} onClick={() => setSelectedNodeId(node.id)}>
                        <EntityIcon type={node.type} size={14} />
                        <span><strong>{node.label}</strong><em>{edge.relation} · {edge.weight}</em></span>
                      </button>
                    ))}
                  </div>
                </DetailBlock>
                <DetailBlock title={copy.evidence}>
                  <div className="relationship-evidence-links">
                    {selectedNode.evidenceUrls.slice(0, 10).map((url) => (
                      <a href={url} target="_blank" rel="noreferrer" key={url}>
                        <ExternalLink size={13} />
                        <span>{url}</span>
                      </a>
                    ))}
                    {!selectedNode.evidenceUrls.length ? <p>{copy.noEvidence}</p> : null}
                  </div>
                </DetailBlock>
              </>
            ) : (
              <div className="relationship-select-node">
                <Search size={24} />
                <p>{copy.selectNode}</p>
              </div>
            )}
          </div>
        </aside>
      </section>

      <ProspectivePressurePanel
        prediction={dashboardModel.attackPrediction}
        language={language}
      />
    </div>
  );
}

function RelationshipNetwork({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  language
}: {
  nodes: RelationshipNode[];
  edges: RelationshipEdge[];
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
  language: LanguageMode;
}) {
  const layoutScale = clamp(Math.sqrt(Math.max(1, nodes.length) / 170), 1, 2.8);
  const layoutWidth = 940 * layoutScale;
  const layoutHeight = 560 * layoutScale;
  const fitZoom = 1 / layoutScale;
  const svgRef = useRef<SVGSVGElement | null>(null);
  const simNodesRef = useRef<SimNode[]>([]);
  const initialPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [zoom, setZoom] = useState(fitZoom);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [panStart, setPanStart] = useState<{ clientX: number; clientY: number; x: number; y: number } | null>(null);

  useEffect(() => {
    const simNodes: SimNode[] = nodes.map((node, index) => {
      const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
      const radius = Math.min(layoutWidth, layoutHeight) * (0.22 + (index % 7) * 0.018);
      return {
        id: node.id,
        model: node,
        x: layoutWidth / 2 + Math.cos(angle) * radius,
        y: layoutHeight / 2 + Math.sin(angle) * radius
      };
    });
    const byId = new Map(simNodes.map((node) => [node.id, node]));
    const simLinks: SimLink[] = edges
      .filter((edge) => byId.has(edge.source) && byId.has(edge.target))
      .map((edge) => ({ id: edge.id, source: edge.source, target: edge.target, model: edge }));
    simNodesRef.current = simNodes;

    const layout = forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(simLinks)
          .id((node) => node.id)
          .distance((link) => Math.max(58, 112 - Math.min(42, link.model.weight * 7)))
          .strength((link) => Math.min(0.7, 0.14 + link.model.confidence * 0.35))
      )
      .force(
        "charge",
        forceManyBody<SimNode>().strength((node) => -86 - Math.sqrt(Math.max(1, node.model.degree)) * 21)
      )
      .force("center", forceCenter<SimNode>(layoutWidth / 2, layoutHeight / 2))
      .force("collision", forceCollide<SimNode>().radius((node) => node.model.size + 10).iterations(2))
      .alphaDecay(0.028)
      .velocityDecay(0.46)
      .stop();

    const iterations = nodes.length > 700 ? 142 : nodes.length > 350 ? 128 : Math.min(260, Math.max(140, nodes.length * 1.5));
    for (let index = 0; index < iterations; index += 1) layout.tick();
    const settledPositions = Object.fromEntries(
      simNodes.map((node) => [
        node.id,
        {
          x: clamp(Number(node.x ?? layoutWidth / 2), 34, layoutWidth - 34),
          y: clamp(Number(node.y ?? layoutHeight / 2), 34, layoutHeight - 34)
        }
      ])
    );
    initialPositionsRef.current = settledPositions;
    setPositions(settledPositions);
    setPan({ x: 0, y: 0 });
    setZoom(fitZoom);
    return () => {
      layout.stop();
    };
  }, [edges, fitZoom, layoutHeight, layoutWidth, nodes]);

  function graphPoint(event: ReactPointerEvent<SVGSVGElement>) {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: layoutWidth / 2, y: layoutHeight / 2 };
    const rawX = ((event.clientX - rect.left) / rect.width) * 940;
    const rawY = ((event.clientY - rect.top) / rect.height) * 560;
    return { x: (rawX - pan.x) / zoom, y: (rawY - pan.y) / zoom };
  }

  function reset() {
    setPan({ x: 0, y: 0 });
    setZoom(fitZoom);
    simNodesRef.current.forEach((node) => {
      node.fx = null;
      node.fy = null;
      const initial = initialPositionsRef.current[node.id];
      if (initial) {
        node.x = initial.x;
        node.y = initial.y;
      }
    });
    setPositions({ ...initialPositionsRef.current });
  }

  const visiblePositions = new Map(
    nodes.map((node) => [node.id, positions[node.id] ?? { x: layoutWidth / 2, y: layoutHeight / 2 }])
  );
  return (
    <div className="relationship-network">
      <div className="relationship-network-tools">
        <button type="button" title={language === "es" ? "Acercar" : "Zoom in"} onClick={() => setZoom((value) => clamp(value + 0.18, 0.22, 2.4))}><ZoomIn size={15} /></button>
        <button type="button" title={language === "es" ? "Alejar" : "Zoom out"} onClick={() => setZoom((value) => clamp(value - 0.18, 0.22, 2.4))}><ZoomOut size={15} /></button>
        <button type="button" title={language === "es" ? "Restablecer" : "Reset"} onClick={reset}><RotateCcw size={15} /></button>
      </div>
      <svg
        ref={svgRef}
        viewBox="0 0 940 560"
        role="img"
        aria-label={language === "es" ? "Grafo interactivo de relaciones" : "Interactive relationship graph"}
        onWheel={(event: ReactWheelEvent<SVGSVGElement>) => {
          event.preventDefault();
          setZoom((value) => clamp(value + (event.deltaY < 0 ? 0.1 : -0.1), 0.22, 2.4));
        }}
        onPointerDown={(event) => {
          if (draggingNodeId) return;
          setPanStart({ clientX: event.clientX, clientY: event.clientY, x: pan.x, y: pan.y });
          event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={(event) => {
          if (draggingNodeId) {
            const point = graphPoint(event);
            const node = simNodesRef.current.find((item) => item.id === draggingNodeId);
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
            x: clamp(panStart.x + ((event.clientX - panStart.clientX) / rect.width) * 940, -360, 360),
            y: clamp(panStart.y + ((event.clientY - panStart.clientY) / rect.height) * 560, -220, 220)
          });
        }}
        onPointerUp={() => {
          setDraggingNodeId(null);
          setPanStart(null);
        }}
        onPointerLeave={() => {
          setDraggingNodeId(null);
          setPanStart(null);
        }}
      >
        <defs>
          <pattern id="relationship-grid" width="32" height="32" patternUnits="userSpaceOnUse">
            <path d="M 32 0 L 0 0 0 32" className="relationship-grid-line" />
          </pattern>
          <marker id="relationship-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" className="relationship-arrow" />
          </marker>
        </defs>
        <rect width="940" height="560" fill="url(#relationship-grid)" />
        <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
          {edges.map((edge) => {
            const source = visiblePositions.get(edge.source);
            const target = visiblePositions.get(edge.target);
            if (!source || !target) return null;
            const active = selectedNodeId === edge.source || selectedNodeId === edge.target;
            return (
              <line
                className={active ? "relationship-edge active" : "relationship-edge"}
                key={edge.id}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                style={{ strokeWidth: Math.min(4, 0.8 + Math.log2(edge.weight + 1) * 0.55) }}
                markerEnd="url(#relationship-arrow)"
              />
            );
          })}
          {nodes.map((node) => {
            const point = visiblePositions.get(node.id)!;
            const selected = node.id === selectedNodeId;
            return (
              <g
                className={`relationship-node entity-${node.type}${selected ? " selected" : ""}${node.isNew ? " is-new" : ""}`}
                key={node.id}
                transform={`translate(${point.x} ${point.y})`}
                onPointerDown={(event) => {
                  event.stopPropagation();
                  setDraggingNodeId(node.id);
                  onSelectNode(node.id);
                  const simulationNode = simNodesRef.current.find((item) => item.id === node.id);
                  if (simulationNode) {
                    simulationNode.fx = point.x;
                    simulationNode.fy = point.y;
                  }
                  event.currentTarget.setPointerCapture(event.pointerId);
                }}
              >
                <title>{node.label} · {entityLabels[language][node.type]} · {node.degree}</title>
                <circle r={node.size} />
                <foreignObject x={-node.size * 0.58} y={-node.size * 0.58} width={node.size * 1.16} height={node.size * 1.16}>
                  <span className="relationship-node-icon"><EntityIcon type={node.type} size={Math.max(10, node.size * 0.78)} /></span>
                </foreignObject>
                {(selected || node.centrality >= (nodes.length > 350 ? 0.035 : 0.055)) ? (
                  <text y={node.size + 15} textAnchor="middle">{truncateLabel(node.label)}</text>
                ) : null}
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

function ProspectivePressurePanel({
  prediction,
  language
}: {
  prediction: ReturnType<typeof buildDashboardModel>["attackPrediction"];
  language: LanguageMode;
}) {
  const copy = labels[language];
  const points = [
    { label: "7d", value: prediction.pressure7d },
    { label: "14d", value: prediction.pressure14d },
    { label: "30d", value: prediction.pressure30d }
  ];
  const available = prediction.scenarios.length > 0 && points.some((point) => point.value > 0);
  const coordinates = points.map((point, index) => ({
    ...point,
    x: 60 + index * 350,
    y: 220 - clamp(point.value, 0, 1) * 165
  }));
  const path = coordinates.map((point, index) => `${index ? "L" : "M"} ${point.x} ${point.y}`).join(" ");
  return (
    <section className="panel prospective-pressure-panel">
      <div className="panel-title-row">
        <div>
          <h2>{copy.prospective}</h2>
          <p>{copy.prospectiveSubtitle}</p>
        </div>
        <ShieldAlert size={20} />
      </div>
      {available ? (
        <div className="prospective-pressure-layout">
          <div className="prospective-chart">
            <svg viewBox="0 0 820 270" role="img" aria-label={copy.prospective}>
              <path className="prospective-grid" d="M60 55 H760 M60 137 H760 M60 220 H760" />
              <path className="prospective-area" d={`${path} L 760 220 L 60 220 Z`} />
              <path className="prospective-line" d={path} />
              {coordinates.map((point) => (
                <g key={point.label}>
                  <circle cx={point.x} cy={point.y} r="7" />
                  <text x={point.x} y={point.y - 18} textAnchor="middle">{Math.round(point.value * 100)}/100</text>
                  <text className="prospective-axis-label" x={point.x} y="248" textAnchor="middle">{point.label}</text>
                </g>
              ))}
            </svg>
          </div>
          <div className="prospective-summary">
            <span>{copy.scenario}</span>
            <strong>{prediction.leadingScenario?.modality || copy.noScenario}</strong>
            <p>{prediction.leadingScenario?.technique || prediction.methodology}</p>
            <div>
              <b>{copy.confidence}</b>
              <strong>{prediction.evidenceConfidence}%</strong>
            </div>
          </div>
        </div>
      ) : (
        <div className="chart-empty prospective-empty">{copy.prospectiveEmpty}</div>
      )}
      <p className="prospective-caveat">{copy.prospectiveCaveat}</p>
    </section>
  );
}

function GraphKpi({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return <div>{icon}<span>{label}</span><strong>{value}</strong></div>;
}

function DetailBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="relationship-detail-block"><strong>{title}</strong>{children}</section>;
}

function PerspectiveIcon({ perspective }: { perspective: RelationshipPerspectiveKey }) {
  if (perspective === "infrastructure") return <Globe2 size={17} />;
  if (perspective === "evidence") return <FileText size={17} />;
  if (perspective === "social") return <AtSign size={17} />;
  if (perspective === "threats") return <ShieldAlert size={17} />;
  return <Network size={17} />;
}

function perspectiveLabel(
  key: RelationshipPerspectiveKey,
  copy: (typeof labels)[LanguageMode]
): string {
  if (key === "infrastructure") return copy.infrastructure;
  if (key === "evidence") return copy.evidenceView;
  if (key === "social") return copy.social;
  if (key === "threats") return copy.threats;
  return copy.all;
}

function EntityIcon({ type, size }: { type: RelationshipEntityType; size: number }) {
  if (type === "organization") return <Building2 size={size} />;
  if (type === "domain") return <Globe2 size={size} />;
  if (type === "ip") return <Network size={size} />;
  if (type === "url") return <Link2 size={size} />;
  if (type === "email") return <Mail size={size} />;
  if (type === "phone") return <Phone size={size} />;
  if (type === "person") return <UserRound size={size} />;
  if (type === "country") return <MapPin size={size} />;
  if (type === "document") return <FileText size={size} />;
  if (type === "hash") return <Hash size={size} />;
  if (type === "social_account") return <AtSign size={size} />;
  if (type === "hashtag") return <Hash size={size} />;
  if (type === "technology") return <Cpu size={size} />;
  if (type === "vulnerability" || type === "vulnerability_candidate") return <Bug size={size} />;
  if (type === "actor") return <UserRound size={size} />;
  if (type === "technique") return <Crosshair size={size} />;
  if (type === "source") return <Radio size={size} />;
  return <Database size={size} />;
}

function truncateLabel(value: string): string {
  return value.length > 28 ? `${value.slice(0, 26)}...` : value;
}

function humanizeKey(value: string): string {
  return value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/_/g, " ");
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function comparableBaseline(run: RunRecord | undefined, runs: RunRecord[]): RunRecord | undefined {
  if (!run) return undefined;
  const scope = [...run.domains].map(normalizeDomain).sort().join("|");
  return [...runs]
    .filter(
      (candidate) =>
        candidate.id !== run.id &&
        candidate.status === "completed" &&
        [...candidate.domains].map(normalizeDomain).sort().join("|") === scope &&
        Date.parse(candidate.created_at) < Date.parse(run.created_at)
    )
    .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];
}

function filterVisibleNodes(
  model: ReturnType<typeof buildRelationshipGraph>,
  query: string,
  onlyNew: boolean
): ReturnType<typeof buildRelationshipGraph> {
  const needle = query.trim().toLowerCase();
  if (!needle && !onlyNew) return model;
  const matching = new Set(
    model.nodes
      .filter((node) => {
        if (onlyNew && !node.isNew) return false;
        if (!needle) return true;
        return `${node.label} ${node.type} ${Object.values(node.metadata).join(" ")}`
          .toLowerCase()
          .includes(needle);
      })
      .map((node) => node.id)
  );
  const contextIds = new Set(matching);
  model.edges.forEach((edge) => {
    if (matching.has(edge.source)) contextIds.add(edge.target);
    if (matching.has(edge.target)) contextIds.add(edge.source);
  });
  const nodes = model.nodes.filter((node) => contextIds.has(node.id));
  const edges = model.edges.filter((edge) => contextIds.has(edge.source) && contextIds.has(edge.target));
  const newNodes = nodes.filter((node) => node.isNew).length;
  return {
    nodes,
    edges,
    stats: {
      ...model.stats,
      totalNodes: nodes.length,
      totalEdges: edges.length,
      connectedComponents: nodes.length ? 1 : 0,
      isolatedNodes: nodes.filter(
        (node) => !edges.some((edge) => edge.source === node.id || edge.target === node.id)
      ).length,
      newNodes
    }
  };
}

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split(/[/?#]/)[0];
}
