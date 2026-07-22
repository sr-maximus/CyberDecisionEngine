import { useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent, WheelEvent } from "react";
import { GitBranch, Network, RotateCcw, ShieldCheck, ZoomIn, ZoomOut } from "lucide-react";
import type { LanguageMode } from "../types";
import type { FrameworkMappingItem, GraphMetric, SocmintLink, SocmintNode } from "../utils/dashboard";
import { localizeFrameworkList, localizeFrameworkText } from "../utils/frameworkLocalization";

const decisionCopy = {
  es: {
    noGraph: "Sin relaciones de grafo disponibles para la inteligencia seleccionada.",
    graphAria: "Vista previa de análisis de grafo",
    coverage: "Cobertura declarada",
    exposure: "Intensidad de evidencia",
    affectedAspects: "Aspectos relacionados",
    aspectsToReview: "Aspectos a revisar",
    evidenceUsed: "Evidencia usada",
    analysisUse: "Uso analítico",
    frameworkNavigator: "Navegación de frameworks",
    selectedFramework: "Framework seleccionado",
    frameworksVisible: "Frameworks visibles",
    noActiveEvidence: "Sin evidencia activa",
    notAssessed: "No evaluada",
    zoomIn: "Acercar grafo",
    zoomOut: "Alejar grafo",
    reset: "Restablecer grafo",
    nodeFocus: "Nodo en foco",
    nodeType: "Tipo",
    zoomLevel: "Zoom"
  },
  en: {
    noGraph: "No graph relationships available for the selected intelligence.",
    graphAria: "Graph analysis preview",
    coverage: "Declared coverage",
    exposure: "Evidence intensity",
    affectedAspects: "Related aspects",
    aspectsToReview: "Aspects to review",
    evidenceUsed: "Evidence used",
    analysisUse: "Analysis use",
    frameworkNavigator: "Framework navigation",
    selectedFramework: "Selected framework",
    frameworksVisible: "Visible frameworks",
    noActiveEvidence: "No active evidence",
    notAssessed: "Not assessed",
    zoomIn: "Zoom graph in",
    zoomOut: "Zoom graph out",
    reset: "Reset graph",
    nodeFocus: "Focused node",
    nodeType: "Type",
    zoomLevel: "Zoom"
  }
};

export function GraphInsight({
  metrics,
  nodes,
  links,
  language = "en"
}: {
  metrics: GraphMetric[];
  nodes: SocmintNode[];
  links: SocmintLink[];
  language?: LanguageMode;
}) {
  const copy = decisionCopy[language];
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [panStart, setPanStart] = useState<{ clientX: number; clientY: number; x: number; y: number } | null>(null);

  useEffect(() => {
    setPositions(Object.fromEntries(nodes.map((node) => [node.id, { x: node.x, y: node.y * 0.8 }])));
    setActiveNode(null);
    setPan({ x: 0, y: 0 });
    setZoom(1);
  }, [nodes]);

  useEffect(() => {
    if (!nodes.length || activeNode || panStart) return;
    const reducedMotion = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reducedMotion) return;
    let frame = 0;
    let lastTick = 0;
    const tick = (timestamp: number) => {
      if (timestamp - lastTick > 110) {
        setPositions((current) => simulateGraphLayout(nodes, links, current, timestamp));
        lastTick = timestamp;
      }
      frame = window.requestAnimationFrame(tick);
    };
    frame = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(frame);
  }, [activeNode, links, nodes, panStart]);

  const displayNodes = useMemo(
    () => nodes.map((node) => ({ ...node, ...(positions[node.id] ?? { x: node.x, y: node.y * 0.8 }) })),
    [nodes, positions]
  );
  const byId = new Map(displayNodes.map((node) => [node.id, node]));
  const focusedNode = byId.get(activeNode ?? hoveredNode ?? displayNodes[0]?.id);

  if (!nodes.length) {
    return <div className="chart-empty graph-empty">{copy.noGraph}</div>;
  }

  function graphPointFromEvent(event: PointerEvent<SVGSVGElement>): { x: number; y: number } {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: 50, y: 40 };
    const rawX = ((event.clientX - rect.left) / rect.width) * 100;
    const rawY = ((event.clientY - rect.top) / rect.height) * 80;
    return {
      x: clampGraph((rawX - pan.x) / zoom, 5, 95),
      y: clampGraph((rawY - pan.y) / zoom, 6, 74)
    };
  }

  function updateZoom(delta: number) {
    setZoom((current) => clampGraph(Number((current + delta).toFixed(2)), 0.75, 2.25));
  }

  function resetGraph() {
    setPositions(Object.fromEntries(nodes.map((node) => [node.id, { x: node.x, y: node.y * 0.8 }])));
    setPan({ x: 0, y: 0 });
    setZoom(1);
  }

  return (
    <div className="graph-insight">
      <div className="graph-insight-map" aria-label={copy.graphAria}>
        <div className="graph-tools">
          <button type="button" onClick={() => updateZoom(0.18)} aria-label={copy.zoomIn} title={copy.zoomIn}>
            <ZoomIn size={14} />
          </button>
          <button type="button" onClick={() => updateZoom(-0.18)} aria-label={copy.zoomOut} title={copy.zoomOut}>
            <ZoomOut size={14} />
          </button>
          <button type="button" onClick={resetGraph} aria-label={copy.reset} title={copy.reset}>
            <RotateCcw size={14} />
          </button>
        </div>
        {focusedNode ? (
          <div className="graph-focus-card">
            <span>{copy.nodeFocus}</span>
            <strong>{graphNodeDisplayLabel(focusedNode.label, language)}</strong>
            <em>
              {copy.nodeType}: {graphGroupLabel(focusedNode.group, language)} · {copy.zoomLevel} {Math.round(zoom * 100)}%
            </em>
          </div>
        ) : null}
        <svg
          ref={svgRef}
          viewBox="0 0 100 80"
          role="img"
          onWheel={(event: WheelEvent<SVGSVGElement>) => {
            event.preventDefault();
            updateZoom(event.deltaY < 0 ? 0.12 : -0.12);
          }}
          onPointerDown={(event) => {
            setPanStart({ clientX: event.clientX, clientY: event.clientY, x: pan.x, y: pan.y });
            event.currentTarget.setPointerCapture(event.pointerId);
          }}
          onPointerMove={(event) => {
            if (activeNode) {
              const point = graphPointFromEvent(event);
              setPositions((current) => ({ ...current, [activeNode]: point }));
              return;
            }
            if (!panStart || !svgRef.current) return;
            const rect = svgRef.current.getBoundingClientRect();
            setPan({
              x: clampGraph(panStart.x + ((event.clientX - panStart.clientX) / rect.width) * 100, -38, 38),
              y: clampGraph(panStart.y + ((event.clientY - panStart.clientY) / rect.height) * 80, -28, 28)
            });
          }}
          onPointerUp={() => {
            setActiveNode(null);
            setPanStart(null);
          }}
          onPointerLeave={() => {
            setActiveNode(null);
            setPanStart(null);
          }}
        >
          <path className="graph-grid" d="M10 10 H90 M10 25 H90 M10 40 H90 M10 55 H90 M10 70 H90 M10 10 V70 M30 10 V70 M50 10 V70 M70 10 V70 M90 10 V70" />
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {links.map((link) => {
              const from = byId.get(link.from);
              const to = byId.get(link.to);
              if (!from || !to) return null;
              return <line className="graph-link" key={`${link.from}-${link.to}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />;
            })}
            {displayNodes.map((node, index) => (
              <g
                className={`graph-node ${node.group} ${activeNode === node.id ? "dragging" : ""}`}
                key={node.id}
                onPointerEnter={() => setHoveredNode(node.id)}
                onPointerLeave={() => setHoveredNode((current) => (current === node.id ? null : current))}
                onPointerDown={(event) => {
                  event.stopPropagation();
                  setActiveNode(node.id);
                  event.currentTarget.setPointerCapture(event.pointerId);
                }}
              >
                <title>{graphNodeDisplayLabel(node.label, language)}</title>
                <circle cx={node.x} cy={node.y} r={Math.max(3.2, node.size / 2.6)} style={{ animationDelay: `${index * 120}ms` }} />
                {shouldShowGraphLabel(node, activeNode, hoveredNode) ? (
                  <text x={node.x} y={node.y + Math.max(6, node.size / 2.2)} textAnchor="middle">
                    {shortGraphLabel(graphNodeDisplayLabel(node.label, language))}
                  </text>
                ) : null}
              </g>
            ))}
          </g>
        </svg>
      </div>
      <div className="graph-metric-list">
        {metrics.map((metric) => {
          const visibleMetric = translateGraphMetric(metric, language);
          return (
            <div className={`graph-metric ${metric.tone ?? "medium"}`} key={metric.label}>
              <Network size={16} />
              <span>{visibleMetric.label}</span>
              <strong>{visibleMetric.value}</strong>
              <em>{visibleMetric.helper}</em>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function clampGraph(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function simulateGraphLayout(
  nodes: SocmintNode[],
  links: SocmintLink[],
  positions: Record<string, { x: number; y: number }>,
  timestamp: number
): Record<string, { x: number; y: number }> {
  const next = Object.fromEntries(nodes.map((node) => [node.id, positions[node.id] ?? initialGraphPosition(node)]));
  const vectors = Object.fromEntries(nodes.map((node) => [node.id, { x: 0, y: 0 }]));

  nodes.forEach((left, leftIndex) => {
    nodes.slice(leftIndex + 1).forEach((right) => {
      const leftPoint = next[left.id];
      const rightPoint = next[right.id];
      const dx = leftPoint.x - rightPoint.x;
      const dy = leftPoint.y - rightPoint.y;
      const distanceSq = Math.max(dx * dx + dy * dy, 18);
      const distance = Math.sqrt(distanceSq);
      const force = 30 / distanceSq;
      const pushX = (dx / distance) * force;
      const pushY = (dy / distance) * force;
      vectors[left.id].x += pushX;
      vectors[left.id].y += pushY;
      vectors[right.id].x -= pushX;
      vectors[right.id].y -= pushY;
    });
  });

  links.forEach((link) => {
    const from = next[link.from];
    const to = next[link.to];
    if (!from || !to) return;
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const distance = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
    const target = link.from === nodes[0]?.id || link.to === nodes[0]?.id ? 24 : 18;
    const force = (distance - target) * 0.018;
    const pullX = (dx / distance) * force;
    const pullY = (dy / distance) * force;
    vectors[link.from].x += pullX;
    vectors[link.from].y += pullY;
    vectors[link.to].x -= pullX;
    vectors[link.to].y -= pullY;
  });

  return Object.fromEntries(
    nodes.map((node, index) => {
      const point = next[node.id];
      const vector = vectors[node.id];
      const anchor = graphAnchor(node);
      const drift = node.group === "platform" ? 0 : 0.032;
      const phase = timestamp / 900 + index * 1.7;
      const nextX = point.x + vector.x + (anchor.x - point.x) * 0.006 + Math.sin(phase) * drift;
      const nextY = point.y + vector.y + (anchor.y - point.y) * 0.006 + Math.cos(phase) * drift;
      return [node.id, { x: clampGraph(nextX, 7, 93), y: clampGraph(nextY, 7, 73) }];
    })
  );
}

function initialGraphPosition(node: SocmintNode): { x: number; y: number } {
  return { x: node.x, y: node.y * 0.8 };
}

function graphAnchor(node: SocmintNode): { x: number; y: number } {
  if (node.group === "platform") return { x: 50, y: 40 };
  if (node.group === "topic") return { x: 54, y: 58 };
  if (node.group === "mention") return { x: 38, y: 27 };
  return { x: 64, y: 35 };
}

function shouldShowGraphLabel(node: SocmintNode, activeNode: string | null, hoveredNode: string | null): boolean {
  return node.group === "platform" || activeNode === node.id || hoveredNode === node.id || node.size >= 15.5;
}

function shortGraphLabel(label: string): string {
  return label.length > 18 ? `${label.slice(0, 16)}...` : label;
}

function graphGroupLabel(group: SocmintNode["group"], language: LanguageMode): string {
  const labels = {
    es: { platform: "núcleo", topic: "TTP", user: "usuario", mention: "actor/señal" },
    en: { platform: "hub", topic: "TTP", user: "user", mention: "actor/signal" }
  };
  return labels[language][group];
}

function graphNodeDisplayLabel(label: string, language: LanguageMode): string {
  if (language === "en") return label;
  const dictionary: Record<string, string> = {
    "Threat activity": "Actividad de amenaza",
    unknown: "Sin atribuir",
    unattributed: "No atribuido",
    pending: "pendiente"
  };
  return dictionary[label] ?? label;
}

function translateGraphMetric(metric: GraphMetric, language: LanguageMode): GraphMetric {
  if (language === "en") return metric;
  const labelMap: Record<string, string> = {
    "Connected signals": "Señales conectadas",
    "Narrative clusters": "Clusters narrativos",
    "Decision confidence": "Confianza de decisión"
  };
  let helper = metric.helper
    .replace("No relationships mapped", "Sin relaciones mapeadas")
    .replace("No active cluster", "Sin cluster activo")
    .replace("No graph density", "Sin densidad de grafo")
    .replace("relationships mapped", "relaciones mapeadas")
    .replace("graph density", "densidad del grafo")
    .replace("Strongest:", "Más fuerte:");
  helper = helper.replace(/unknown|unattributed|Threat activity|pending/g, (value) => graphNodeDisplayLabel(value, language));
  return { ...metric, label: labelMap[metric.label] ?? metric.label, helper };
}

export function FrameworkMapping({
  items,
  compact = false,
  language = "en"
}: {
  items: FrameworkMappingItem[];
  compact?: boolean;
  language?: LanguageMode;
}) {
  const copy = decisionCopy[language];
  const visibleItems = items;
  const [selectedFrameworkName, setSelectedFrameworkName] = useState<string | null>(null);
  const selectedFramework = useMemo(
    () => visibleItems.find((item) => item.name === selectedFrameworkName) ?? visibleItems[0],
    [selectedFrameworkName, visibleItems]
  );

  useEffect(() => {
    if (visibleItems.length && !visibleItems.some((item) => item.name === selectedFrameworkName)) {
      setSelectedFrameworkName(visibleItems[0].name);
    }
  }, [selectedFrameworkName, visibleItems]);

  if (compact) {
    return (
      <div className="framework-map compact framework-workbench">
        <aside className="framework-list-panel" aria-label={copy.frameworkNavigator}>
          <div className="framework-list-head">
            <span>{copy.frameworkNavigator}</span>
            <strong>{visibleItems.length}</strong>
          </div>
          <div className="framework-nav-list">
            {visibleItems.map((item, index) => (
              <button
                type="button"
                className={`${selectedFramework?.name === item.name ? "selected" : ""} ${item.tone}`}
                key={item.name}
                onClick={() => setSelectedFrameworkName(item.name)}
              >
                <span className="framework-rank">{index + 1}</span>
                <span className="framework-nav-copy">
                  <strong>{item.name}</strong>
                  <small>{localizeFrameworkText(item.family, language)}</small>
                </span>
                <em>{item.coverageAssessed ? `${item.coverage}%` : "—"}</em>
              </button>
            ))}
          </div>
        </aside>

        {selectedFramework ? (
          <article className={`framework-detail-panel ${selectedFramework.tone}`}>
            <div className="framework-detail-head">
              <div>
                <span>{copy.selectedFramework}</span>
                <h3>{selectedFramework.name}</h3>
                <p>{localizeFrameworkText(selectedFramework.family, language)}</p>
              </div>
              <ShieldCheck size={19} />
            </div>
            <div className="framework-detail-bars">
              <Progress label={selectedFramework.coverageAssessed ? copy.coverage : copy.notAssessed} value={selectedFramework.coverage} kind="coverage" />
              <Progress label={copy.exposure} value={selectedFramework.exposure} kind="exposure" />
            </div>
            <div className="framework-domains framework-detail-domains">
              {localizeFrameworkList(selectedFramework.domains, language).slice(0, 8).map((domain) => (
                <span key={domain}>{domain}</span>
              ))}
              {selectedFramework.domains.length > 8 ? <span>+{selectedFramework.domains.length - 8}</span> : null}
            </div>
            <div className="framework-summary-card">
              <span>{copy.affectedAspects}</span>
              <p>{localizeFrameworkList(selectedFramework.affectedAspects, language).join(" / ") || copy.noActiveEvidence}</p>
            </div>
            <div className="framework-insight-grid">
              <div>
                <strong>{copy.aspectsToReview}</strong>
                <ul>
                  {localizeFrameworkList(selectedFramework.considerations, language).slice(0, 5).map((value) => (
                    <li key={value}>{value}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>{copy.evidenceUsed}</strong>
                <ul>
                  {localizeFrameworkList(selectedFramework.evidenceFocus, language).slice(0, 5).map((value) => (
                    <li key={value}>{value}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>{copy.analysisUse}</strong>
                <p>{localizeFrameworkText(selectedFramework.analysisUse, language)}</p>
                <span>{localizeFrameworkText(selectedFramework.decision, language)}</span>
              </div>
            </div>
          </article>
        ) : null}
      </div>
    );
  }

  return (
    <div className="framework-map">
      {visibleItems.map((item, index) => {
        const domains = localizeFrameworkList(item.domains, language);
        const affectedAspects = localizeFrameworkList(item.affectedAspects, language);
        return (
          <details className={`framework-row ${item.tone}`} key={item.name} open={index < 3}>
            <summary>
              <div className="framework-name">
                <ShieldCheck size={17} />
                <div>
                  <strong>{item.name}</strong>
                  <span>{localizeFrameworkText(item.family, language)}</span>
                </div>
              </div>
              <div className="framework-bars">
                <Progress label={item.coverageAssessed ? copy.coverage : copy.notAssessed} value={item.coverage} kind="coverage" />
                <Progress label={copy.exposure} value={item.exposure} kind="exposure" />
              </div>
              <div className="framework-domains">
                {domains.map((domain) => (
                  <span key={domain}>{domain}</span>
                ))}
              </div>
              <div className="framework-aspects">
                <strong>{copy.affectedAspects}</strong>
                <span>{affectedAspects.join(" / ")}</span>
              </div>
              <div className="framework-decision">
                <GitBranch size={15} />
                <span>{localizeFrameworkText(item.decision, language)}</span>
              </div>
            </summary>
            <div className="framework-detail">
              <div>
                <strong>{copy.aspectsToReview}</strong>
                <ul>
                  {localizeFrameworkList(item.considerations, language).map((value) => (
                    <li key={value}>{value}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>{copy.evidenceUsed}</strong>
                <ul>
                  {localizeFrameworkList(item.evidenceFocus, language).map((value) => (
                    <li key={value}>{value}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>{copy.analysisUse}</strong>
                <p>{localizeFrameworkText(item.analysisUse, language)}</p>
                <span>{item.sourceLabel}</span>
              </div>
            </div>
          </details>
        );
      })}
    </div>
  );
}

function Progress({ label, value, kind }: { label: string; value: number; kind: "coverage" | "exposure" }) {
  return (
    <div className="framework-progress">
      <div>
        <span>{label}</span>
        <strong>{value}%</strong>
      </div>
      <i className={kind}>
        <b style={{ width: `${value}%` }} />
      </i>
    </div>
  );
}
