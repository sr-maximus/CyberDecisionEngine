import {
  AlertTriangle,
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
  Loader2,
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
import { getCTIFrameworkCatalog, getCTIFrameworkFamily } from "../api";
import type { CTIFrameworkFamily, CTIFrameworkFamilySummary, LanguageMode, RunRecord } from "../types";
import { buildDashboardModel } from "../utils/dashboard";
import {
  buildRelationshipGraph,
  buildCTIReferenceGraph,
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

type ConnectionDirection = "outgoing" | "incoming" | "bidirectional";
type GraphWorkspaceKey = "run" | "cti-reference";
type CTICatalogViewKey =
  | "attack-enterprise"
  | "attack-mobile"
  | "attack-ics"
  | "attack-all"
  | "d3fend"
  | "atlas"
  | "emb3d"
  | "f3"
  | "aadapt"
  | "disarm"
  | "capec"
  | "cwe"
  | "inform";

const ATTACK_FAMILY_IDS = ["attack-enterprise", "attack-mobile", "attack-ics"] as const;
const ctiCatalogViews: Array<{ key: CTICatalogViewKey; familyIds: string[] }> = [
  { key: "attack-enterprise", familyIds: ["attack-enterprise"] },
  { key: "attack-mobile", familyIds: ["attack-mobile"] },
  { key: "attack-ics", familyIds: ["attack-ics"] },
  { key: "attack-all", familyIds: [...ATTACK_FAMILY_IDS] },
  { key: "d3fend", familyIds: ["d3fend", "attack-enterprise"] },
  { key: "atlas", familyIds: ["atlas"] },
  { key: "emb3d", familyIds: ["emb3d"] },
  { key: "f3", familyIds: ["f3"] },
  { key: "aadapt", familyIds: ["aadapt"] },
  { key: "disarm", familyIds: ["disarm"] },
  { key: "capec", familyIds: ["capec"] },
  { key: "cwe", familyIds: ["cwe"] },
  { key: "inform", familyIds: ["inform"] }
];

const labels = {
  es: {
    title: "Grafo de análisis y relaciones",
    subtitle: "Conexiones trazables entre alcance, evidencias y entidades de la corrida seleccionada",
    catalogSubtitle: "Contexto CTI de referencia y su relación analítica con empresa, dominios, sector, países y tecnologías",
    runWorkspace: "Corrida seleccionada",
    runWorkspaceHint: "Evidencia y relaciones de este análisis",
    catalogWorkspace: "Contexto CTI general",
    catalogWorkspaceHint: "Marcos CTI, fraude, IA, IoT/OT, debilidades y defensa",
    referenceNotice: "Conocimiento de referencia de los marcos seleccionados. Su vínculo con el alcance expresa contexto analítico; no prueba actividad, explotación ni control implementado contra la organización.",
    loadingCatalog: "Cargando conocimiento de referencia verificado...",
    catalogLoadError: "No fue posible cargar todo el marco seleccionado.",
    retry: "Reintentar",
    records: "Registros procesados",
    referenceProfiles: "Entidades CTI",
    referenceTechniques: "Elementos visibles",
    officialSources: "Marcos cargados",
    entities: "Entidades visibles",
    relations: "Relaciones",
    components: "Componentes",
    newNodes: "Nodos nuevos",
    baseline: "Comparado con",
    noBaseline: "Primera corrida comparable",
    searchNodes: "Buscar entidad, URL, correo, teléfono o evidencia",
    searchReference: "Buscar marco, actor, táctica, técnica, control o debilidad",
    onlyNew: "Solo nuevos",
    ctiFilterHint: "Mostrar solo adversarios, campañas, software, TTP y defensas relacionadas",
    entityIndex: "Índice de nodos",
    entityIndexHint: "Todos los nodos de la vista; selecciona uno para centrar el análisis.",
    emptyIndex: "No hay nodos para esta vista y búsqueda.",
    linkedSources: "con enlace",
    workbench: "Red de vínculos",
    workbenchSubtitle: "El tamaño representa centralidad de grado. La red se organiza una vez y queda fija para explorarla, acercarla o mover nodos manualmente.",
    catalogWorkbench: "Red CTI de referencia",
    catalogWorkbenchSubtitle: "Marcos, actores, tácticas, técnicas, controles, debilidades y relaciones documentadas; el alcance se mantiene separado de la evidencia observada.",
    perspectives: "Vistas analíticas",
    perspectivesSubtitle: "Cada vista organiza la red para una pregunta de análisis distinta.",
    detail: "Detalle de entidad",
    selectNode: "Selecciona un nodo para revisar sus metadatos, relaciones directas y evidencia.",
    directConnections: "Conexiones directas",
    nodeScale: "Nodo: tamaño = conexiones",
    edgeScale: "Arista: grosor e intensidad = registros",
    oneWay: "Unidireccional",
    twoWay: "Bidireccional",
    outgoing: "Saliente",
    incoming: "Entrante",
    edgeRecords: "registros",
    edgeMatrices: "relaciones",
    catalogEdgeScale: "Arista: grosor e intensidad = relaciones coincidentes",
    metadata: "Metadatos",
    evidence: "Evidencias",
    referenceSources: "Fuentes oficiales",
    noEvidence: "Este nodo aporta contexto, pero no tiene una URL propia. Revisa sus conexiones para llegar al registro o fuente relacionada.",
    noReferenceSource: "Este nodo de contexto no tiene un enlace oficial propio.",
    noGraph: "La corrida seleccionada no contiene entidades ni relaciones trazables para representar.",
    noCatalogGraph: "No hay conocimiento de referencia disponible para esta vista.",
    centrality: "Centralidad de grado",
    pageRank: "PageRank",
    betweenness: "Intermediación",
    confidence: "Confianza",
    status: "Estado",
    degree: "Conexiones",
    processedNote: "Solo se muestran entidades y relaciones trazables de la corrida seleccionada. La disposición se calcula una vez; mover un nodo cambia únicamente su posición visual.",
    catalogProcessedNote: "La vista combina el marco seleccionado con el contexto del alcance. Referencia, inferencia y observación conservan estados separados.",
    prospective: "Tendencia prospectiva de presión de señales",
    prospectiveSubtitle: "Lectura por horizonte basada en evidencia reciente, escenarios y contexto de la corrida.",
    prospectiveEmpty: "No hay evidencia suficiente para publicar una tendencia prospectiva.",
    prospectiveCaveat: "Índice heurístico de presión, no probabilidad calibrada de ataque. Debe leerse junto con evidencia y limitaciones.",
    scenario: "Escenario con mayor soporte",
    noScenario: "Sin escenario respaldado",
    legend: "Tipos de entidad",
    all: "Red completa",
    infrastructure: "Infraestructura y exposición",
    evidenceView: "Trazabilidad de evidencia",
    social: "Identidad y SOCMINT",
    threats: "CTI de la corrida"
  },
  en: {
    title: "Relationship analysis graph",
    subtitle: "Traceable connections among scope, evidence and entities from the selected run",
    catalogSubtitle: "Reference CTI context and its analytical relationship with the organization, domains, sector, countries and technologies",
    runWorkspace: "Selected run",
    runWorkspaceHint: "Evidence and relationships from this analysis",
    catalogWorkspace: "General CTI context",
    catalogWorkspaceHint: "CTI, fraud, AI, IoT/OT, weakness and defense frameworks",
    referenceNotice: "Reference knowledge from the selected frameworks. Its scope link expresses analytical context and does not prove activity, exploitation or an implemented control against the organization.",
    loadingCatalog: "Loading verified reference knowledge...",
    catalogLoadError: "The complete selected framework could not be loaded.",
    retry: "Retry",
    records: "Processed records",
    referenceProfiles: "CTI entities",
    referenceTechniques: "Visible elements",
    officialSources: "Loaded frameworks",
    entities: "Visible entities",
    relations: "Relationships",
    components: "Components",
    newNodes: "New nodes",
    baseline: "Compared with",
    noBaseline: "First comparable run",
    searchNodes: "Search entity, URL, email, phone or evidence",
    searchReference: "Search framework, actor, tactic, technique, control or weakness",
    onlyNew: "New only",
    ctiFilterHint: "Show only related adversaries, campaigns, software, TTPs and defenses",
    entityIndex: "Node index",
    entityIndexHint: "Every node in this view; select one to focus the analysis.",
    emptyIndex: "There are no nodes for this view and search.",
    linkedSources: "with link",
    workbench: "Link network",
    workbenchSubtitle: "Node size represents degree centrality. The network is laid out once and then remains fixed for zooming, inspection and manual node movement.",
    catalogWorkbench: "Reference CTI network",
    catalogWorkbenchSubtitle: "Documented frameworks, actors, tactics, techniques, controls, weaknesses and relationships; scope context remains separate from observed evidence.",
    perspectives: "Analytical views",
    perspectivesSubtitle: "Each view organizes the network around a different analytical question.",
    detail: "Entity detail",
    selectNode: "Select a node to inspect metadata, direct relationships and evidence.",
    directConnections: "Direct connections",
    nodeScale: "Node: size = connections",
    edgeScale: "Edge: width and intensity = records",
    oneWay: "Unidirectional",
    twoWay: "Bidirectional",
    outgoing: "Outgoing",
    incoming: "Incoming",
    edgeRecords: "records",
    edgeMatrices: "relationships",
    catalogEdgeScale: "Edge: width and intensity = matching relationships",
    metadata: "Metadata",
    evidence: "Evidence",
    referenceSources: "Official sources",
    noEvidence: "This node provides context but has no URL of its own. Follow its connections to the related record or source.",
    noReferenceSource: "This context node has no official link of its own.",
    noGraph: "The selected run contains no traceable entities or relationships to display.",
    noCatalogGraph: "No reference knowledge is available for this view.",
    centrality: "Degree centrality",
    pageRank: "PageRank",
    betweenness: "Betweenness",
    confidence: "Confidence",
    status: "Status",
    degree: "Connections",
    processedNote: "Only traceable entities and relationships from the selected run are displayed. The layout is calculated once; moving a node changes only its visual position.",
    catalogProcessedNote: "This view combines the selected framework with scope context. Reference, inference and observation remain separate states.",
    prospective: "Prospective signal-pressure trend",
    prospectiveSubtitle: "Horizon view based on recent evidence, scenarios and the current run context.",
    prospectiveEmpty: "There is not enough evidence to publish a prospective trend.",
    prospectiveCaveat: "Heuristic pressure index, not a calibrated attack probability. Read it with evidence and limitations.",
    scenario: "Best-supported scenario",
    noScenario: "No supported scenario",
    legend: "Entity types",
    all: "Complete network",
    infrastructure: "Infrastructure and exposure",
    evidenceView: "Evidence traceability",
    social: "Identity and SOCMINT",
    threats: "Run CTI"
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
    sector: "Sector económico",
    document: "Documento",
    hash: "Hash / indicador",
    social_account: "Cuenta social",
    hashtag: "Hashtag",
    technology: "Tecnología",
    vulnerability: "Vulnerabilidad",
    vulnerability_candidate: "CVE pendiente de versión",
    actor: "Actor",
    threat_actor: "Actor de amenaza",
    threat_group: "Grupo de amenaza",
    campaign: "Campaña",
    malware: "Malware",
    tool: "Herramienta",
    framework: "Marco de referencia",
    tactic: "Táctica o dimensión",
    technique: "Técnica",
    control: "Control o nivel",
    defense: "Defensa D3FEND",
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
    sector: "Economic sector",
    document: "Document",
    hash: "Hash / indicator",
    social_account: "Social account",
    hashtag: "Hashtag",
    technology: "Technology",
    vulnerability: "Vulnerability",
    vulnerability_candidate: "CVE pending version",
    actor: "Actor",
    threat_actor: "Threat actor",
    threat_group: "Threat group",
    campaign: "Campaign",
    malware: "Malware",
    tool: "Tool",
    framework: "Reference framework",
    tactic: "Tactic or dimension",
    technique: "Technique",
    control: "Control or level",
    defense: "D3FEND defense",
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
  "sector",
  "document",
  "hash",
  "social_account",
  "hashtag",
  "technology",
  "vulnerability",
  "vulnerability_candidate",
  "actor",
  "threat_actor",
  "threat_group",
  "campaign",
  "malware",
  "tool",
  "framework",
  "tactic",
  "technique",
  "control",
  "defense",
  "source",
  "evidence"
];

export function RelationshipGraphView({
  run,
  runs = [],
  language,
  initialPerspective = "all"
}: {
  run?: RunRecord;
  runs?: RunRecord[];
  language: LanguageMode;
  initialPerspective?: RelationshipPerspectiveKey;
}) {
  const copy = labels[language];
  const baselineRun = useMemo(() => comparableBaseline(run, runs), [run, runs]);
  const completeModel = useMemo(() => buildRelationshipGraph(run, baselineRun), [run, baselineRun]);
  const dashboardModel = useMemo(() => buildDashboardModel(run, defaultDashboardFilters), [run]);
  const [workspace, setWorkspace] = useState<GraphWorkspaceKey>("run");
  const [perspective, setPerspective] = useState<RelationshipPerspectiveKey>(initialPerspective);
  const [catalogView, setCatalogView] = useState<CTICatalogViewKey>("attack-enterprise");
  const [catalogFamilies, setCatalogFamilies] = useState<Record<string, CTIFrameworkFamily>>({});
  const [catalogSummaries, setCatalogSummaries] = useState<Record<string, CTIFrameworkFamilySummary>>({});
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState("");
  const [catalogAttempt, setCatalogAttempt] = useState(0);
  const catalogRequestRef = useRef("");
  const catalogIndexRequestRef = useRef("");
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
  const selectedCatalogConfig = ctiCatalogViews.find((item) => item.key === catalogView) ?? ctiCatalogViews[0];
  const selectedCatalogFamilies = useMemo(
    () => selectedCatalogConfig.familyIds.flatMap((familyId) => catalogFamilies[familyId] ? [catalogFamilies[familyId]] : []),
    [catalogFamilies, selectedCatalogConfig]
  );
  const catalogModel = useMemo(
    () => buildCTIReferenceGraph(selectedCatalogFamilies, run),
    [selectedCatalogFamilies, run]
  );
  const activeModel = workspace === "run" ? perspectiveGraph : catalogModel;
  const graph = useMemo(
    () => filterVisibleNodes(activeModel, nodeQuery, workspace === "run" && onlyNew),
    [activeModel, nodeQuery, onlyNew, workspace]
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId) ?? null;
  const linkedNodeCount = graph.nodes.filter((node) => node.evidenceUrls.length > 0).length;
  const referenceProfileTypes = new Set<RelationshipEntityType>(["actor", "threat_actor", "threat_group", "campaign", "malware", "tool"]);
  const referenceItemTypes = new Set<RelationshipEntityType>(["tactic", "technique", "control", "defense", "vulnerability", "technology"]);
  const referenceProfileCount = graph.nodes.filter((node) => referenceProfileTypes.has(node.type)).length;
  const referenceTechniqueCount = graph.nodes.filter(
    (node) => referenceItemTypes.has(node.type) && node.metadata.knowledgeKind === "reference"
  ).length;
  const directionKeys = useMemo(
    () => new Set(graph.edges.map((edge) => edgeDirectionKey(edge.source, edge.target))),
    [graph.edges]
  );
  const connections = selectedNode
    ? graph.edges
        .filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
        .flatMap((edge) => {
          const node = graph.nodes.find((candidate) => candidate.id === (edge.source === selectedNode.id ? edge.target : edge.source));
          if (!node) return [];
          const direction: ConnectionDirection = directionKeys.has(edgeDirectionKey(edge.target, edge.source))
            ? "bidirectional"
            : edge.source === selectedNode.id ? "outgoing" : "incoming";
          return [{ edge, node, direction }];
        })
        .sort((left, right) => right.edge.weight - left.edge.weight)
    : [];

  useEffect(() => {
    if (workspace !== "cti-reference") return;
    const requestKey = `index-${catalogAttempt}`;
    if (catalogIndexRequestRef.current === requestKey) return;
    catalogIndexRequestRef.current = requestKey;
    let cancelled = false;
    getCTIFrameworkCatalog()
      .then((catalog) => {
        if (cancelled) return;
        setCatalogSummaries(Object.fromEntries(catalog.families.map((family) => [family.id, family])));
      })
      .catch(() => {
        if (!cancelled) setCatalogError(copy.catalogLoadError);
      });
    return () => {
      cancelled = true;
    };
  }, [catalogAttempt, copy.catalogLoadError, workspace]);

  useEffect(() => {
    if (workspace !== "cti-reference") return;
    const familyIds = selectedCatalogConfig.familyIds;
    const requestKey = `${familyIds.join(",")}-${catalogAttempt}`;
    if (catalogRequestRef.current === requestKey) return;
    catalogRequestRef.current = requestKey;
    let cancelled = false;
    setCatalogLoading(true);
    setCatalogError("");
    Promise.allSettled(familyIds.map((familyId) => getCTIFrameworkFamily(familyId)))
      .then((results) => {
        if (cancelled) return;
        const loaded: Record<string, CTIFrameworkFamily> = {};
        let failures = 0;
        results.forEach((result, index) => {
          if (result.status === "fulfilled") loaded[familyIds[index]] = result.value;
          else failures += 1;
        });
        setCatalogFamilies((current) => ({ ...current, ...loaded }));
        if (failures) setCatalogError(copy.catalogLoadError);
      })
      .finally(() => {
        if (!cancelled) setCatalogLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [catalogAttempt, copy.catalogLoadError, selectedCatalogConfig, workspace]);

  useEffect(() => {
    if (selectedNodeId && !graph.nodes.some((node) => node.id === selectedNodeId)) setSelectedNodeId(null);
  }, [graph.nodes, selectedNodeId]);

  useEffect(() => {
    setWorkspace("run");
    setPerspective(initialPerspective);
    setNodeQuery("");
    setOnlyNew(false);
    setSelectedNodeId(null);
  }, [initialPerspective]);

  function selectWorkspace(nextWorkspace: GraphWorkspaceKey) {
    setWorkspace(nextWorkspace);
    setNodeQuery("");
    setOnlyNew(false);
    setSelectedNodeId(null);
  }

  return (
    <div className="view-stack relationship-graph-view">
      <section className="panel relationship-overview">
        <div className="panel-title-row">
          <div>
            <h2>{copy.title}</h2>
            <p>{workspace === "run" ? copy.subtitle : copy.catalogSubtitle}</p>
          </div>
          <Network size={20} />
        </div>
        <div className="relationship-workspace-tabs" role="tablist" aria-label={copy.perspectives}>
          <button
            className={workspace === "run" ? "active" : ""}
            onClick={() => selectWorkspace("run")}
            role="tab"
            aria-selected={workspace === "run"}
            type="button"
          >
            <Database size={18} />
            <span><strong>{copy.runWorkspace}</strong><small>{copy.runWorkspaceHint}</small></span>
          </button>
          <button
            className={workspace === "cti-reference" ? "active" : ""}
            onClick={() => selectWorkspace("cti-reference")}
            role="tab"
            aria-selected={workspace === "cti-reference"}
            type="button"
          >
            <ShieldAlert size={18} />
            <span><strong>{copy.catalogWorkspace}</strong><small>{copy.catalogWorkspaceHint}</small></span>
          </button>
        </div>
        <div className="relationship-kpis">
          {workspace === "run" ? (
            <>
              <GraphKpi icon={<Database size={17} />} label={copy.records} value={completeModel.stats.processedRecords} />
              <GraphKpi icon={<Network size={17} />} label={copy.entities} value={graph.stats.totalNodes} />
              <GraphKpi icon={<Link2 size={17} />} label={copy.relations} value={graph.stats.totalEdges} />
              <GraphKpi icon={<Crosshair size={17} />} label={copy.components} value={graph.stats.connectedComponents} />
              <GraphKpi icon={<UserSearch size={17} />} label={copy.newNodes} value={graph.stats.newNodes} />
            </>
          ) : (
            <>
              <GraphKpi icon={<UserRound size={17} />} label={copy.referenceProfiles} value={referenceProfileCount} />
              <GraphKpi icon={<Crosshair size={17} />} label={copy.referenceTechniques} value={referenceTechniqueCount} />
              <GraphKpi icon={<Link2 size={17} />} label={copy.relations} value={graph.stats.totalEdges} />
              <GraphKpi icon={<Network size={17} />} label={copy.components} value={graph.stats.connectedComponents} />
              <GraphKpi icon={<Database size={17} />} label={copy.officialSources} value={selectedCatalogFamilies.length} />
            </>
          )}
        </div>
        {workspace === "run" ? (
          <div className="relationship-comparison-note">
            <span>{baselineRun ? `${copy.baseline} #${baselineRun.id}` : copy.noBaseline}</span>
            <strong>{completeModel.stats.renderedRecords}/{completeModel.stats.processedRecords}</strong>
          </div>
        ) : (
          <div className="relationship-reference-notice">
            <ShieldAlert size={18} />
            <span>{copy.referenceNotice}</span>
          </div>
        )}
      </section>

      <section className="relationship-workbench">
        <article className="panel relationship-canvas-panel">
          <div className="panel-title-row compact">
            <div>
              <h2>{workspace === "run" ? copy.workbench : copy.catalogWorkbench}</h2>
              <p>{workspace === "run" ? copy.workbenchSubtitle : copy.catalogWorkbenchSubtitle}</p>
            </div>
            <span className="relationship-run-id">
              {workspace === "run" ? `#${run?.id ?? "N/D"}` : catalogViewLabel(catalogView, language)}
            </span>
          </div>
          <div className="relationship-filterbar">
            <label>
              <Search size={15} />
              <input
                value={nodeQuery}
                onChange={(event) => setNodeQuery(event.target.value)}
                placeholder={workspace === "run" ? copy.searchNodes : copy.searchReference}
                type="search"
              />
            </label>
            {workspace === "run" ? (
              <button
                className={onlyNew ? "active" : ""}
                disabled={!baselineRun}
                onClick={() => setOnlyNew((value) => !value)}
                aria-pressed={onlyNew}
                type="button"
              >
                <UserSearch size={15} />
                {copy.onlyNew}
              </button>
            ) : null}
          </div>
          {workspace === "cti-reference" && catalogLoading && !selectedCatalogFamilies.length ? (
            <div className="relationship-loading"><Loader2 size={24} /><span>{copy.loadingCatalog}</span></div>
          ) : graph.nodes.length ? (
            <>
              <RelationshipNetwork
                nodes={graph.nodes}
                edges={graph.edges}
                selectedNodeId={selectedNodeId}
                onSelectNode={setSelectedNodeId}
                language={language}
                edgeKind={workspace === "run" ? "records" : "relationships"}
              />
              <div className="relationship-legends">
                <div className="relationship-visual-legend" aria-label={language === "es" ? "Lectura de nodos y aristas" : "Node and edge encoding"}>
                  <span><i className="relationship-node-scale"><b /><b /></i>{copy.nodeScale}</span>
                  <span><i className="relationship-edge-scale" />{workspace === "run" ? copy.edgeScale : copy.catalogEdgeScale}</span>
                  <span><b className="relationship-direction-symbol">→</b>{copy.oneWay}</span>
                  <span><b className="relationship-direction-symbol">↔</b>{copy.twoWay}</span>
                </div>
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
              </div>
              <p className="relationship-method-note">
                {workspace === "run" ? copy.processedNote : copy.catalogProcessedNote}
              </p>
            </>
          ) : (
            <div className="chart-empty relationship-empty">
              {workspace === "run" ? copy.noGraph : copy.noCatalogGraph}
            </div>
          )}
        </article>

        <aside className="panel relationship-side-panel">
          <div className="relationship-side-head">
            <strong>{copy.perspectives}</strong>
            <span>{copy.perspectivesSubtitle}</span>
          </div>
          <div className="relationship-perspective-list" role="tablist">
            {workspace === "run"
              ? relationshipPerspectives.map((item) => {
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
                        <small>{perspectiveDescription(item.key, language)}</small>
                        <em>{itemGraph.stats.totalNodes} · {itemGraph.stats.totalEdges}</em>
                      </span>
                    </button>
                  );
                })
              : ctiCatalogViews.map((item) => {
                  const counts = catalogViewCounts(item, catalogFamilies, catalogSummaries);
                  return (
                    <button
                      className={catalogView === item.key ? "active" : ""}
                      key={item.key}
                      onClick={() => {
                        setCatalogView(item.key);
                        setNodeQuery("");
                        setSelectedNodeId(null);
                      }}
                      role="tab"
                      aria-selected={catalogView === item.key}
                      type="button"
                    >
                      <CatalogPerspectiveIcon view={item.key} />
                      <span>
                        <strong>{catalogViewLabel(item.key, language)}</strong>
                        <small>{catalogViewDescription(item.key, language)}</small>
                        <em>{counts.nodes} · {counts.edges}</em>
                      </span>
                    </button>
                  );
                })}
            {workspace === "cti-reference" && catalogError ? (
              <div className="relationship-catalog-error" role="alert">
                <AlertTriangle size={16} />
                <span>{catalogError}</span>
                <button type="button" onClick={() => setCatalogAttempt((value) => value + 1)}>{copy.retry}</button>
              </div>
            ) : null}
          </div>

          <div className="relationship-node-index">
            <div className="relationship-side-head">
              <strong>{copy.entityIndex}</strong>
              <span>{copy.entityIndexHint}</span>
            </div>
            <div className="relationship-index-summary">
              <span>{graph.nodes.length} {copy.entities.toLowerCase()}</span>
              <span>{linkedNodeCount} {copy.linkedSources}</span>
            </div>
            <div className="relationship-node-index-list">
              {graph.nodes.length ? (
                [...graph.nodes]
                  .sort((left, right) => Number(right.isNew) - Number(left.isNew) || right.degree - left.degree)
                  .map((node) => (
                    <button
                      className={`${selectedNodeId === node.id ? "active" : ""}${node.isNew ? " is-new" : ""}`}
                      key={node.id}
                      onClick={() => setSelectedNodeId(node.id)}
                      type="button"
                    >
                      <EntityIcon type={node.type} size={15} />
                      <span>
                        <strong>{node.label}</strong>
                        <em>
                          {entityLabels[language][node.type]} · {node.degree} · {technologyDomainLabel(node.metadata.primaryTechnologyDomain, language)}
                        </em>
                      </span>
                      {node.isNew ? <i>{language === "es" ? "Nuevo" : "New"}</i> : null}
                    </button>
                  ))
              ) : (
                <div className="relationship-index-empty"><Search size={18} /><span>{copy.emptyIndex}</span></div>
              )}
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
                <div className="relationship-domain-badges">
                  {String(selectedNode.metadata.technologyDomains || "unknown")
                    .split(",")
                    .map((value) => value.trim())
                    .filter(Boolean)
                    .map((value) => (
                      <span className={`technology-domain-badge domain-${value}`} key={`technology-${value}`}>
                        {technologyDomainLabel(value, language)}
                      </span>
                    ))}
                  {String(selectedNode.metadata.analysisDomains || "cyber")
                    .split(",")
                    .map((value) => value.trim())
                    .filter((value) => value && value !== "cyber")
                    .map((value) => (
                      <span className="analysis-domain-badge" key={`analysis-${value}`}>{value}</span>
                    ))}
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
                    {connections.map(({ edge, node, direction }) => (
                      <button type="button" key={edge.id} onClick={() => setSelectedNodeId(node.id)}>
                        <EntityIcon type={node.type} size={14} />
                        <span>
                          <strong>{node.label}</strong>
                          <em>
                            {directionSymbol(direction)} {directionLabel(direction, copy)} · {relationshipLabel(edge.relation, language)} · {edgeWeightLabel(edge.weight, workspace, language)}
                          </em>
                        </span>
                      </button>
                    ))}
                  </div>
                </DetailBlock>
                <DetailBlock title={workspace === "run" ? copy.evidence : copy.referenceSources}>
                  <div className="relationship-evidence-links">
                    {selectedNode.evidenceUrls.slice(0, 10).map((url) => (
                      <a href={url} target="_blank" rel="noreferrer" key={url}>
                        <ExternalLink size={13} />
                        <span>{url}</span>
                      </a>
                    ))}
                    {!selectedNode.evidenceUrls.length ? <p>{workspace === "run" ? copy.noEvidence : copy.noReferenceSource}</p> : null}
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

      {workspace === "run" ? (
        <ProspectivePressurePanel
          prediction={dashboardModel.attackPrediction}
          language={language}
        />
      ) : null}
    </div>
  );
}

function RelationshipNetwork({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  language,
  edgeKind
}: {
  nodes: RelationshipNode[];
  edges: RelationshipEdge[];
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
  language: LanguageMode;
  edgeKind: "records" | "relationships";
}) {
  const layoutScale = clamp(Math.sqrt(Math.max(1, nodes.length) / 170), 1, 2.8);
  const layoutWidth = 940 * layoutScale;
  const layoutHeight = 680 * layoutScale;
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
    const rawY = ((event.clientY - rect.top) / rect.height) * 680;
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
  const visibleNodes = new Map(nodes.map((node) => [node.id, node]));
  const directionKeys = new Set(edges.map((edge) => edgeDirectionKey(edge.source, edge.target)));
  return (
    <div className="relationship-network">
      <div className="relationship-network-tools">
        <button type="button" title={language === "es" ? "Acercar" : "Zoom in"} onClick={() => setZoom((value) => clamp(value + 0.18, 0.22, 2.4))}><ZoomIn size={15} /></button>
        <button type="button" title={language === "es" ? "Alejar" : "Zoom out"} onClick={() => setZoom((value) => clamp(value - 0.18, 0.22, 2.4))}><ZoomOut size={15} /></button>
        <button type="button" title={language === "es" ? "Restablecer" : "Reset"} onClick={reset}><RotateCcw size={15} /></button>
      </div>
      <svg
        ref={svgRef}
        viewBox="0 0 940 680"
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
            y: clamp(panStart.y + ((event.clientY - panStart.clientY) / rect.height) * 680, -290, 290)
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
        <rect width="940" height="680" fill="url(#relationship-grid)" />
        <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
          {edges.map((edge) => {
            const source = visiblePositions.get(edge.source);
            const target = visiblePositions.get(edge.target);
            if (!source || !target) return null;
            const sourceNode = visibleNodes.get(edge.source);
            const targetNode = visibleNodes.get(edge.target);
            const endpoints = relationshipEdgeEndpoints(source, target, sourceNode?.size ?? 10, targetNode?.size ?? 10);
            const active = selectedNodeId === edge.source || selectedNodeId === edge.target;
            const bidirectional = directionKeys.has(edgeDirectionKey(edge.target, edge.source));
            return (
              <line
                className={`relationship-edge${active ? " active" : ""}${bidirectional ? " bidirectional" : ""}`}
                key={edge.id}
                x1={endpoints.x1}
                y1={endpoints.y1}
                x2={endpoints.x2}
                y2={endpoints.y2}
                style={{
                  strokeWidth: Math.min(5.5, 1 + Math.log2(edge.weight + 1) * 0.78),
                  opacity: active ? 0.98 : Math.min(0.9, 0.42 + Math.log2(edge.weight + 1) * 0.12)
                }}
                markerStart={bidirectional ? "url(#relationship-arrow)" : undefined}
                markerEnd="url(#relationship-arrow)"
              >
                <title>
                  {sourceNode?.label ?? edge.source} → {targetNode?.label ?? edge.target} · {relationshipLabel(edge.relation, language)} · {edgeWeightLabel(edge.weight, edgeKind === "records" ? "run" : "cti-reference", language)}{bidirectional ? ` · ${language === "es" ? "bidireccional" : "bidirectional"}` : ""}
                </title>
              </line>
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

function perspectiveDescription(key: RelationshipPerspectiveKey, language: LanguageMode): string {
  const descriptions: Record<LanguageMode, Record<RelationshipPerspectiveKey, string>> = {
    es: {
      all: "Alcance completo de la corrida",
      infrastructure: "Activos, exposición y tecnología",
      evidence: "Fuentes, registros y trazabilidad",
      social: "Identidades y señales sociales",
      threats: "Adversarios y TTP vinculadas a la corrida"
    },
    en: {
      all: "Complete selected-run scope",
      infrastructure: "Assets, exposure and technology",
      evidence: "Sources, records and traceability",
      social: "Identities and social signals",
      threats: "Adversaries and TTPs linked to the run"
    }
  };
  return descriptions[language][key];
}

function catalogViewLabel(view: CTICatalogViewKey, language: LanguageMode): string {
  const viewLabels: Record<LanguageMode, Record<CTICatalogViewKey, string>> = {
    es: {
      "attack-enterprise": "ATT&CK Enterprise",
      "attack-mobile": "ATT&CK Mobile",
      "attack-ics": "ATT&CK ICS / OT",
      "attack-all": "ATT&CK multiplataforma",
      d3fend: "D3FEND + ATT&CK",
      atlas: "ATLAS",
      emb3d: "EMB3D IoT / OT",
      f3: "F3 antifraude",
      aadapt: "AADAPT activos digitales",
      disarm: "DISARM desinformación",
      capec: "CAPEC patrones de ataque",
      cwe: "CWE debilidades",
      inform: "INFORM madurez"
    },
    en: {
      "attack-enterprise": "ATT&CK Enterprise",
      "attack-mobile": "ATT&CK Mobile",
      "attack-ics": "ATT&CK ICS / OT",
      "attack-all": "Cross-platform ATT&CK",
      d3fend: "D3FEND + ATT&CK",
      atlas: "ATLAS",
      emb3d: "EMB3D IoT / OT",
      f3: "F3 fraud",
      aadapt: "AADAPT digital assets",
      disarm: "DISARM disinformation",
      capec: "CAPEC attack patterns",
      cwe: "CWE weaknesses",
      inform: "INFORM maturity"
    }
  };
  return viewLabels[language][view];
}

function catalogViewDescription(view: CTICatalogViewKey, language: LanguageMode): string {
  const descriptions: Record<LanguageMode, Record<CTICatalogViewKey, string>> = {
    es: {
      "attack-enterprise": "Grupos, campañas, software y TTP empresariales",
      "attack-mobile": "Amenazas y TTP para plataformas móviles",
      "attack-ics": "Contexto industrial, ICS, IIoT y OT",
      "attack-all": "Relaciones consolidadas entre las tres matrices",
      d3fend: "Defensas y técnicas ATT&CK que contrarrestan",
      atlas: "Tácticas y técnicas contra sistemas de IA",
      emb3d: "Propiedades, amenazas y mitigaciones para IoT, IIoT y OT",
      f3: "Tácticas y conductas de fraude",
      aadapt: "Acciones adversarias en pagos y activos digitales",
      disarm: "Tácticas y técnicas de influencia y desinformación",
      capec: "Jerarquía y relaciones de patrones de ataque",
      cwe: "Jerarquía y relaciones de debilidades de software y hardware",
      inform: "Dimensiones, componentes y niveles de madurez threat-informed"
    },
    en: {
      "attack-enterprise": "Enterprise groups, campaigns, software and TTPs",
      "attack-mobile": "Threats and TTPs for mobile platforms",
      "attack-ics": "Industrial, ICS, IIoT and OT context",
      "attack-all": "Consolidated relationships across all three matrices",
      d3fend: "Defenses and the ATT&CK techniques they counter",
      atlas: "Tactics and techniques against AI systems",
      emb3d: "Properties, threats and mitigations for IoT, IIoT and OT",
      f3: "Fraud tactics and behaviors",
      aadapt: "Adversarial actions in payments and digital assets",
      disarm: "Influence and disinformation tactics and techniques",
      capec: "Attack-pattern hierarchy and relationships",
      cwe: "Software and hardware weakness hierarchy and relationships",
      inform: "Threat-informed maturity dimensions, components and levels"
    }
  };
  return descriptions[language][view];
}

function catalogViewCounts(
  view: { key: CTICatalogViewKey; familyIds: string[] },
  families: Record<string, CTIFrameworkFamily>,
  summaries: Record<string, CTIFrameworkFamilySummary>
) {
  return view.familyIds.reduce(
    (counts, familyId) => {
      const family = families[familyId];
      const summary = family ?? summaries[familyId];
      if (!summary) return counts;
      counts.nodes += summary.counts.items + summary.counts.entities + summary.counts.tactics + 1;
      counts.edges += summary.counts.relationships;
      return counts;
    },
    { nodes: 0, edges: 0 }
  );
}

function CatalogPerspectiveIcon({ view }: { view: CTICatalogViewKey }) {
  if (view === "attack-enterprise") return <Building2 size={17} />;
  if (view === "attack-mobile") return <Phone size={17} />;
  if (view === "attack-ics") return <Cpu size={17} />;
  if (view === "d3fend") return <ShieldAlert size={17} />;
  if (view === "atlas" || view === "emb3d") return <Cpu size={17} />;
  if (view === "f3" || view === "aadapt" || view === "disarm") return <Crosshair size={17} />;
  if (view === "capec" || view === "cwe") return <Bug size={17} />;
  if (view === "inform") return <Database size={17} />;
  return <Network size={17} />;
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
  if (type === "sector") return <Building2 size={size} />;
  if (type === "document") return <FileText size={size} />;
  if (type === "hash") return <Hash size={size} />;
  if (type === "social_account") return <AtSign size={size} />;
  if (type === "hashtag") return <Hash size={size} />;
  if (type === "technology") return <Cpu size={size} />;
  if (type === "vulnerability" || type === "vulnerability_candidate") return <Bug size={size} />;
  if (type === "actor" || type === "threat_actor" || type === "threat_group") return <UserRound size={size} />;
  if (type === "campaign") return <Crosshair size={size} />;
  if (type === "malware") return <Bug size={size} />;
  if (type === "tool") return <Cpu size={size} />;
  if (type === "framework") return <Network size={size} />;
  if (type === "tactic") return <Crosshair size={size} />;
  if (type === "technique") return <Crosshair size={size} />;
  if (type === "control") return <ShieldAlert size={size} />;
  if (type === "defense") return <ShieldAlert size={size} />;
  if (type === "source") return <Radio size={size} />;
  return <Database size={size} />;
}

function truncateLabel(value: string): string {
  return value.length > 28 ? `${value.slice(0, 26)}...` : value;
}

function edgeDirectionKey(source: string, target: string): string {
  return `${source}\u0000${target}`;
}

function directionSymbol(direction: ConnectionDirection): string {
  if (direction === "bidirectional") return "↔";
  return direction === "outgoing" ? "→" : "←";
}

function directionLabel(
  direction: ConnectionDirection,
  copy: (typeof labels)[LanguageMode]
): string {
  if (direction === "bidirectional") return copy.twoWay;
  return direction === "outgoing" ? copy.outgoing : copy.incoming;
}

function relationshipLabel(value: string, language: LanguageMode): string {
  const normalized = value.trim().toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
  if (language === "es") {
    const translated: Record<string, string> = {
      "applies to": "aplica a",
      attributes: "atribuye",
      "can precede": "puede preceder",
      "child of": "depende jerárquicamente de",
      "contains technology": "contiene tecnología",
      "contains component": "contiene componente",
      "contains dimension": "contiene dimensión",
      "contains item": "contiene elemento",
      "contains maturity level": "contiene nivel de madurez",
      "contains mitigation": "contiene mitigación",
      "contains property": "contiene propiedad",
      "contains tactic": "contiene táctica",
      "contains threat": "contiene amenaza",
      "contextually relevant to": "relevancia contextual para",
      counters: "contrarresta",
      "cti relationship": "relación CTI",
      "declared domain": "dominio declarado",
      "declared geography": "geografía declarada",
      "declared sector": "sector declarado",
      hosts: "aloja",
      maps: "mapea",
      mentions: "menciona",
      "mentions geography": "menciona ubicación",
      "mentions sector": "menciona sector",
      observes: "observa",
      "observes technology domain": "observa dominio tecnológico",
      "reference context for": "contexto de referencia para",
      "related to": "se relaciona con",
      "subtechnique of": "subtécnica de",
      uses: "utiliza"
    };
    return translated[normalized] ?? humanizeKey(value);
  }
  return humanizeKey(value);
}

function edgeWeightLabel(weight: number, workspace: GraphWorkspaceKey, language: LanguageMode): string {
  if (workspace === "run") {
    if (language === "es") return `${weight} ${weight === 1 ? "registro" : "registros"}`;
    return `${weight} ${weight === 1 ? "record" : "records"}`;
  }
  if (language === "es") return `${weight} ${weight === 1 ? "relación" : "relaciones"}`;
  return `${weight} ${weight === 1 ? "relationship" : "relationships"}`;
}

function technologyDomainLabel(value: unknown, language: LanguageMode): string {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized || normalized === "unknown" || normalized === "unclassified" || normalized === "sin clasificar") {
    return language === "es" ? "Sin clasificar" : "Unclassified";
  }
  const labelsByDomain: Record<string, string> = {
    ai: "IA",
    iiot: "IIoT",
    iot: "IoT",
    it: "IT",
    mobile: language === "es" ? "Móvil" : "Mobile",
    multidomain: language === "es" ? "Multidominio" : "Multidomain",
    ot: "OT"
  };
  return labelsByDomain[normalized] ?? humanizeKey(String(value));
}

function relationshipEdgeEndpoints(
  source: { x: number; y: number },
  target: { x: number; y: number },
  sourceRadius: number,
  targetRadius: number
) {
  const deltaX = target.x - source.x;
  const deltaY = target.y - source.y;
  const distance = Math.hypot(deltaX, deltaY) || 1;
  const unitX = deltaX / distance;
  const unitY = deltaY / distance;
  return {
    x1: source.x + unitX * (sourceRadius + 5),
    y1: source.y + unitY * (sourceRadius + 5),
    x2: target.x - unitX * (targetRadius + 7),
    y2: target.y - unitY * (targetRadius + 7)
  };
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
