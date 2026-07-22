import { useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent } from "react";
import { localizedSectorLabel } from "../data/catalog";
import type { LanguageMode } from "../types";
import type { RankedItem, SocmintLink, SocmintNode, TrendPoint } from "../utils/dashboard";

interface LineChartProps {
  points: TrendPoint[];
  language?: LanguageMode;
}

const chartCopy = {
  es: {
    noTrend: "Sin senales de tendencia disponibles.",
    trendAria: "Grafica de tendencia de amenazas",
    noRanking: "Sin senales analizadas disponibles.",
    noSector: "Sin senales sectoriales disponibles.",
    freshness: "frescura de fuentes",
    freshnessAria: "Frescura de fuentes",
    socmintAria: "Grafo de inteligencia SOCMINT"
  },
  en: {
    noTrend: "No trend signals available.",
    trendAria: "Threat trend line chart",
    noRanking: "No analysed signals available.",
    noSector: "No sector-tagged signals available.",
    freshness: "source freshness",
    freshnessAria: "Source freshness",
    socmintAria: "SOCMINT intelligence graph"
  }
};

export function LineChart({ points, language = "en" }: LineChartProps) {
  const copy = chartCopy[language];
  if (!points.length) {
    return <div className="chart-empty">{copy.noTrend}</div>;
  }
  const max = Math.max(...points.map((point) => point.value), 1);
  const labelInterval = Math.max(1, Math.ceil(points.length / 6));
  const path = points
    .map((point, index) => {
      const x = points.length === 1 ? 0 : (index / (points.length - 1)) * 100;
      const y = 92 - (point.value / max) * 78;
      return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
  const areaPath = `${path} L 100 94 L 0 94 Z`;
  return (
    <div className="chart line-chart">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label={copy.trendAria}>
        <path className="chart-grid-line" d="M0 20 H100 M0 50 H100 M0 80 H100" />
        <path className="line-area" d={areaPath} />
        <path className="line-path" d={path} />
        {points.map((point, index) => {
          const x = points.length === 1 ? 0 : (index / (points.length - 1)) * 100;
          const y = 92 - (point.value / max) * 78;
          return <circle className="line-dot" key={`${point.label}-${index}`} cx={x} cy={y} r="1.4" />;
        })}
      </svg>
      <div className="axis-labels">
        {points.map((point, index) => (
          <span key={`${point.label}-${index}`}>
            {index === 0 || index === points.length - 1 || index % labelInterval === 0 ? point.label : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

export function BarRanking({ items, language = "en" }: { items: RankedItem[]; language?: LanguageMode }) {
  const copy = chartCopy[language];
  const max = Math.max(...items.map((item) => item.value), 1);
  if (!items.length) {
    return <div className="chart-empty">{copy.noRanking}</div>;
  }
  return (
    <div className="rank-list">
      {items.map((item) => (
        <div className="rank-row" key={item.name}>
          <span title={item.name}>{item.name}</span>
          <div className="rank-track">
            <i className={item.tone ?? ""} style={{ width: `${Math.max(6, (item.value / max) * 100)}%` }} />
          </div>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

export function SectorMatrix({ items, language = "en" }: { items: RankedItem[]; language?: LanguageMode }) {
  const copy = chartCopy[language];
  if (!items.length) {
    return <div className="chart-empty">{copy.noSector}</div>;
  }
  return (
    <div className="sector-matrix">
      {items.map((item) => (
        <div className={`sector-cell ${item.tone ?? "medium"}`} key={item.name}>
          <span>{localizedSectorLabel(item.name, language)}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

export function Gauge({ value, language = "en" }: { value: number; language?: LanguageMode }) {
  const copy = chartCopy[language];
  const normalized = Math.max(0, Math.min(100, value));
  return (
    <div className="gauge">
      <svg viewBox="0 0 120 70" aria-label={`${copy.freshnessAria} ${normalized}%`}>
        <path className="gauge-bg" d="M15 60 A45 45 0 0 1 105 60" />
        <path className="gauge-fg" pathLength="100" strokeDasharray={`${normalized} 100`} d="M15 60 A45 45 0 0 1 105 60" />
      </svg>
      <strong>{normalized}%</strong>
      <span>{copy.freshness}</span>
    </div>
  );
}

export function SocmintGraph({ nodes, links, language = "en" }: { nodes: SocmintNode[]; links: SocmintLink[]; language?: LanguageMode }) {
  const copy = chartCopy[language];
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});

  useEffect(() => {
    setPositions(Object.fromEntries(nodes.map((node) => [node.id, { x: node.x, y: node.y }])));
  }, [nodes]);

  const displayNodes = useMemo(
    () => nodes.map((node) => ({ ...node, ...(positions[node.id] ?? { x: node.x, y: node.y }) })),
    [nodes, positions]
  );
  const byId = new Map(displayNodes.map((node) => [node.id, node]));

  function pointFromEvent(event: PointerEvent<SVGSVGElement>): { x: number; y: number } {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: 50, y: 50 };
    return {
      x: Math.max(5, Math.min(95, ((event.clientX - rect.left) / rect.width) * 100)),
      y: Math.max(5, Math.min(95, ((event.clientY - rect.top) / rect.height) * 100))
    };
  }

  return (
    <div className="socmint-graph">
      <svg
        ref={svgRef}
        viewBox="0 0 100 100"
        role="img"
        aria-label={copy.socmintAria}
        onPointerMove={(event) => {
          if (!activeNode) return;
          const point = pointFromEvent(event);
          setPositions((current) => ({ ...current, [activeNode]: point }));
        }}
        onPointerUp={() => setActiveNode(null)}
        onPointerLeave={() => setActiveNode(null)}
      >
        {links.map((link) => {
          const from = byId.get(link.from);
          const to = byId.get(link.to);
          if (!from || !to) return null;
          return <line key={`${link.from}-${link.to}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />;
        })}
        {displayNodes.map((node) => (
          <g
            className={`node ${node.group} ${activeNode === node.id ? "dragging" : ""}`}
            key={node.id}
            onPointerDown={(event) => {
              setActiveNode(node.id);
              event.currentTarget.setPointerCapture(event.pointerId);
            }}
          >
            <title>{node.label}</title>
            <circle cx={node.x} cy={node.y} r={node.size / 2} />
            {node.group === "platform" && node.id !== "Public web" ? (
              <text x={node.x} y={node.y + node.size / 2 + 4} textAnchor="middle">
                {node.label}
              </text>
            ) : null}
          </g>
        ))}
      </svg>
    </div>
  );
}
