from __future__ import annotations

import base64
import math
from collections import Counter, defaultdict
from io import BytesIO
from textwrap import fill
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urlparse

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Circle, Rectangle, Wedge


# Paleta CTI consistente con el informe HTML.
CHART_BG = "#071321"
PANEL_BG = "#0c1d35"
GRID = "#203758"
TEXT = "#e6eefc"
MUTED = "#9fb2d1"
BLUE = "#38bdf8"
AQUA = "#67e8f9"
GREEN = "#22c55e"
YELLOW = "#f59e0b"
ORANGE = "#f97316"
RED = "#ef4444"
PURPLE = "#8b5cf6"
PINK = "#ec4899"

QUERY_TYPE_LABELS = {
    "identity_name": "Nombre exacto",
    "identity_name_org": "Nombre + organización",
    "identity_name_domain": "Nombre + dominio",
    "identity_name_site": "Nombre + sitio social/técnico",
    "identity_corporate_email": "Correo corporativo exacto",
    "identity_personal_email_authorized": "Correo personal autorizado",
    "manual_result": "Resultado manual/importado",
    "name_keyword": "Nombre + keyword",
    "name_org_keyword": "Nombre + organización + keyword",
    "corporate_email_keyword": "Correo corporativo + keyword",
    "name_domain_keyword": "Nombre + dominio + keyword",
    "personal_email_keyword_authorized": "Correo personal autorizado + keyword",
}


def _fig_to_base64(fig) -> str:
    buffer = BytesIO()
    # tight_layout puede fallar con anotaciones densas; bbox_inches conserva el margen útil.
    try:
        fig.tight_layout(pad=1.6)
    except Exception:
        pass
    fig.savefig(
        buffer,
        format="png",
        dpi=170,
        bbox_inches="tight",
        facecolor=fig.get_facecolor(),
        edgecolor=fig.get_edgecolor(),
    )
    plt.close(fig)
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("ascii")


def _new_fig(width: float = 10, height: float = 5.2):
    fig, ax = plt.subplots(figsize=(width, height))
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(PANEL_BG)
    _style_axis(ax)
    return fig, ax


def _style_axis(ax, grid_axis: str = "both") -> None:
    ax.tick_params(colors=MUTED, labelsize=8)
    ax.title.set_color(TEXT)
    ax.xaxis.label.set_color(MUTED)
    ax.yaxis.label.set_color(MUTED)
    for spine in ax.spines.values():
        spine.set_color(GRID)
        spine.set_alpha(0.7)
    if grid_axis:
        ax.grid(True, axis=grid_axis, color=GRID, alpha=0.35, linewidth=0.7)


def _wrap_labels(labels: Iterable[str], width: int = 22) -> List[str]:
    return [fill(str(label), width=width, break_long_words=False) for label in labels]


def _risk_color(value: float) -> str:
    value = float(value)
    if value <= 20:
        return GREEN
    if value <= 40:
        return YELLOW
    if value <= 60:
        return ORANGE
    if value <= 80:
        return RED
    return PURPLE


def _domain(url: str) -> str:
    try:
        host = urlparse(url or "").netloc.lower()
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host or "sin dominio"


def executive_risk_gauge(total_risk: float, risk_level: str) -> str:
    """Velocímetro semicircular para lectura ejecutiva del score total."""
    score = max(0.0, min(100.0, float(total_risk or 0)))
    fig = plt.figure(figsize=(8.6, 4.9))
    fig.patch.set_facecolor(CHART_BG)
    ax = fig.add_subplot(111)
    ax.set_facecolor(PANEL_BG)
    ax.axis("off")
    ax.set_aspect("equal")

    segments = [
        (0, 20, GREEN, "Bajo"),
        (20, 40, YELLOW, "Moderado"),
        (40, 60, ORANGE, "Alto"),
        (60, 80, RED, "Crítico"),
        (80, 100, PURPLE, "Extremo"),
    ]
    radius = 1.0
    width = 0.18
    for start, end, color, label in segments:
        theta1 = 180 - (end / 100) * 180
        theta2 = 180 - (start / 100) * 180
        ax.add_patch(Wedge((0, 0), radius, theta1, theta2, width=width, facecolor=color, alpha=0.85, edgecolor=CHART_BG, linewidth=2))
        mid = (start + end) / 2
        angle = math.radians(180 - (mid / 100) * 180)
        ax.text(0.78 * math.cos(angle), 0.78 * math.sin(angle) - 0.03, label, color=MUTED, fontsize=8, ha="center", va="center")

    needle_angle = math.radians(180 - (score / 100) * 180)
    ax.plot([0, 0.76 * math.cos(needle_angle)], [0, 0.76 * math.sin(needle_angle)], color=TEXT, linewidth=3.0, solid_capstyle="round")
    ax.add_patch(Circle((0, 0), 0.045, color=TEXT))
    ax.text(0, -0.20, f"{score:.1f}", color=TEXT, fontsize=31, fontweight="bold", ha="center")
    ax.text(0, -0.36, f"Riesgo total · {risk_level}", color=MUTED, fontsize=12, ha="center")
    ax.text(-1.0, -0.08, "0", color=MUTED, fontsize=9, ha="center")
    ax.text(1.0, -0.08, "100", color=MUTED, fontsize=9, ha="center")
    ax.set_xlim(-1.12, 1.12)
    ax.set_ylim(-0.48, 1.10)
    return _fig_to_base64(fig)


def risk_bar_chart(dimension_risks: Dict[str, float], dimension_labels: Dict[str, str]) -> str:
    """Lollipop chart: prioriza legibilidad y evita rótulos inclinados."""
    items = sorted(((dimension_labels.get(k, k), float(v)) for k, v in dimension_risks.items()), key=lambda x: x[1], reverse=True)
    if not items:
        items = [("Sin hallazgos", 0.0)]

    labels = _wrap_labels([i[0] for i in items], width=24)
    values = [i[1] for i in items]
    colors = [_risk_color(v) for v in values]
    fig_h = max(5.1, 0.55 * len(labels) + 1.5)
    fig, ax = _new_fig(10.8, fig_h)
    y = list(range(len(labels)))

    ax.hlines(y, 0, values, color=GRID, linewidth=6, alpha=0.65)
    ax.scatter(values, y, s=145, color=colors, edgecolor=TEXT, linewidth=0.7, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, color=TEXT)
    ax.invert_yaxis()
    ax.set_xlim(0, 106)
    ax.set_xlabel("Riesgo normalizado (0-100)")
    ax.set_title("Mapa de riesgo por dimensión")
    ax.grid(True, axis="x", color=GRID, alpha=0.35, linewidth=0.7)
    ax.grid(False, axis="y")
    for i, v in enumerate(values):
        ax.text(min(v + 2.0, 98), i, f"{v:.1f}", va="center", ha="left", color=TEXT, fontsize=8.5, fontweight="bold")
    for threshold in [20, 40, 60, 80]:
        ax.axvline(threshold, color=GRID, linewidth=0.8, linestyle="--", alpha=0.6)
    return _fig_to_base64(fig)


def risk_contribution_donut(dimension_risks: Dict[str, float], dimension_labels: Dict[str, str]) -> str:
    items = [(dimension_labels.get(k, k), max(0.0, float(v))) for k, v in dimension_risks.items() if float(v) > 0]
    if not items:
        items = [("Sin hallazgos", 1.0)]
    items = sorted(items, key=lambda x: x[1], reverse=True)
    top = items[:6]
    rest = sum(v for _, v in items[6:])
    if rest:
        top.append(("Otros", rest))
    labels = [fill(lbl, width=16, break_long_words=False) for lbl, _ in top]
    values = [v for _, v in top]
    colors = [_risk_color(v) if lbl != "Otros" else GRID for lbl, v in top]

    fig = plt.figure(figsize=(8.2, 5.6))
    fig.patch.set_facecolor(CHART_BG)
    ax = fig.add_subplot(111)
    ax.set_facecolor(PANEL_BG)
    ax.pie(values, labels=None, startangle=90, counterclock=False, colors=colors, wedgeprops=dict(width=0.36, edgecolor=CHART_BG, linewidth=2))
    total = sum(values)
    ax.text(0, 0.08, f"{total:.0f}", ha="center", va="center", color=TEXT, fontsize=28, fontweight="bold")
    ax.text(0, -0.11, "riesgo acumulado", ha="center", va="center", color=MUTED, fontsize=9)
    ax.legend(labels, loc="center left", bbox_to_anchor=(0.92, 0.5), frameon=False, labelcolor=MUTED, fontsize=8)
    ax.set_title("Contribución relativa del riesgo", color=TEXT, pad=12)
    return _fig_to_base64(fig)


def keyword_bar_chart(top_keywords: List[Dict]) -> str:
    if not top_keywords:
        top_keywords = [{"keyword": "Sin hallazgos", "frequency": 0, "risk": 0}]
    rows = sorted(top_keywords[:12], key=lambda r: (float(r.get("risk", 0)), float(r.get("frequency", 0))), reverse=True)
    labels = _wrap_labels([str(row.get("keyword", "")) for row in rows], width=20)
    values = [float(row.get("frequency", 0)) for row in rows]
    risks = [float(row.get("risk", 0)) for row in rows]
    max_risk = max(risks) if risks else 1.0
    colors = [_risk_color((r / max_risk) * 100 if max_risk else 0) for r in risks]

    fig_h = max(5.1, 0.45 * len(labels) + 1.5)
    fig, ax = _new_fig(10.8, fig_h)
    y = list(range(len(labels)))
    ax.barh(y, values, color=colors, height=0.62, alpha=0.92)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, color=TEXT)
    ax.invert_yaxis()
    ax.set_xlabel("Frecuencia")
    ax.set_title("Palabras clave con mayor señal")
    ax.grid(True, axis="x", color=GRID, alpha=0.35)
    ax.grid(False, axis="y")
    xpad = max(values) * 0.02 + 0.2 if values else 0.2
    for i, (v, r) in enumerate(zip(values, risks)):
        ax.text(v + xpad, i, f"{int(v)} · riesgo {r:.0f}", va="center", color=TEXT, fontsize=8)
    return _fig_to_base64(fig)


def probability_impact_chart(points: Dict[str, Dict[str, float]]) -> str:
    """Matriz CTI con identificadores numéricos para eliminar traslapes."""
    fig, ax = _new_fig(8.2, 6.4)
    ax.add_patch(Rectangle((0, 0), 0.5, 0.5, alpha=0.16, color=GREEN))
    ax.add_patch(Rectangle((0.5, 0), 0.5, 0.5, alpha=0.14, color=YELLOW))
    ax.add_patch(Rectangle((0, 0.5), 0.5, 0.5, alpha=0.14, color=ORANGE))
    ax.add_patch(Rectangle((0.5, 0.5), 0.5, 0.5, alpha=0.17, color=RED))
    ax.axhline(0.5, linestyle="--", linewidth=0.9, color=MUTED, alpha=0.7)
    ax.axvline(0.5, linestyle="--", linewidth=0.9, color=MUTED, alpha=0.7)

    sorted_points = sorted(points.values(), key=lambda p: (float(p.get("impact", 0)), float(p.get("probability", 0))), reverse=True)
    legend_rows = []
    occupied: Dict[Tuple[int, int], int] = defaultdict(int)
    for idx, point in enumerate(sorted_points, start=1):
        x = float(point.get("probability", 0))
        y = float(point.get("impact", 0))
        # Micro desplazamiento determinístico cuando varios puntos caen casi en el mismo lugar.
        # Se mantiene cerca del cuadrante real, pero se evita que los números se monten.
        bucket = (round(x, 1), round(y, 1))
        offset_idx = occupied[bucket]
        occupied[bucket] += 1
        jitter = [
            (0.000, 0.000),
            (-0.030, 0.028),
            (-0.030, -0.028),
            (-0.060, 0.000),
            (-0.060, 0.056),
            (-0.060, -0.056),
            (-0.090, 0.028),
            (-0.090, -0.028),
            (-0.120, 0.000),
        ][offset_idx % 9]
        x_plot = max(0.03, min(0.995, x + jitter[0]))
        y_plot = max(0.03, min(0.995, y + jitter[1]))

        magnitude = (x * y) * 100
        color = _risk_color(magnitude)
        size = 180 + magnitude * 2.4
        ax.scatter([x_plot], [y_plot], s=size, color=color, alpha=0.90, edgecolors=TEXT, linewidth=0.8, zorder=3)
        ax.text(x_plot, y_plot, str(idx), color=TEXT, ha="center", va="center", fontsize=8.2, fontweight="bold", zorder=4)
        label = str(point.get("label", ""))
        legend_rows.append(f"{idx}. {label[:38]}")

    ax.text(0.25, 0.05, "Baja prioridad", color=GREEN, fontsize=8, ha="center", fontweight="bold")
    ax.text(0.75, 0.05, "Probable / impacto bajo", color=YELLOW, fontsize=8, ha="center", fontweight="bold")
    ax.text(0.25, 0.95, "Impacto alto / poco probable", color=ORANGE, fontsize=8, ha="center", fontweight="bold")
    ax.text(0.75, 0.95, "Prioridad CTI", color=RED, fontsize=8, ha="center", fontweight="bold")
    ax.set_xlim(0, 1.03)
    ax.set_ylim(0, 1.03)
    ax.set_xlabel("Probabilidad estimada")
    ax.set_ylabel("Impacto potencial")
    ax.set_title("Matriz de priorización CTI")

    legend_text = "\n".join(legend_rows)
    ax.text(
        1.05,
        0.98,
        legend_text,
        transform=ax.transAxes,
        ha="left",
        va="top",
        color=MUTED,
        fontsize=7.3,
        bbox=dict(boxstyle="round,pad=0.45", fc=CHART_BG, ec=GRID, alpha=0.95),
    )
    return _fig_to_base64(fig)

def radar_chart(dimension_risks: Dict[str, float], dimension_labels: Dict[str, str]) -> str:
    # Mantener todas las dimensiones, pero compactar texto.
    labels = [dimension_labels.get(k, k) for k in dimension_risks.keys()]
    values = [float(v) for v in dimension_risks.values()]
    if not values:
        labels = ["Sin hallazgos"]
        values = [0.0]
    angles = [n / float(len(values)) * 2 * math.pi for n in range(len(values))]
    values_loop = values + values[:1]
    angles_loop = angles + angles[:1]

    fig = plt.figure(figsize=(7.4, 7.4))
    fig.patch.set_facecolor(CHART_BG)
    ax = fig.add_subplot(111, polar=True)
    ax.set_facecolor(PANEL_BG)
    ax.plot(angles_loop, values_loop, linewidth=2.2, color=AQUA)
    ax.fill(angles_loop, values_loop, alpha=0.20, color=AQUA)
    ax.scatter(angles, values, s=44, color=[_risk_color(v) for v in values], edgecolor=TEXT, linewidth=0.55, zorder=3)
    ax.set_xticks(angles)
    ax.set_xticklabels(_wrap_labels(labels, width=13), fontsize=7.5, color=TEXT)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20", "40", "60", "80", "100"], color=MUTED, fontsize=7)
    ax.set_ylim(0, 100)
    ax.grid(color=GRID, alpha=0.55, linewidth=0.7)
    ax.spines["polar"].set_color(GRID)
    ax.set_title("Radar de superficie de exposición", color=TEXT, pad=22)
    return _fig_to_base64(fig)


def query_basis_heatmap(evidence_rows: List[Dict[str, str]], dimension_labels: Dict[str, str]) -> str:
    basis_order = [
        "Nombre exacto",
        "Nombre + sitio social/técnico",
        "Nombre + keyword",
        "Nombre + organización",
        "Nombre + organización + keyword",
        "Correo corporativo exacto",
        "Correo corporativo + keyword",
        "Nombre + dominio",
        "Nombre + dominio + keyword",
        "Resultado manual/importado",
        "Correo personal autorizado",
        "Correo personal autorizado + keyword",
    ]
    dim_keys = list(dimension_labels.keys())
    dim_names = [dimension_labels.get(k, k) for k in dim_keys]
    matrix = []
    for dim_key in dim_keys:
        row = []
        for basis in basis_order:
            count = sum(
                1
                for e in evidence_rows
                if e.get("dimension_key") == dim_key
                and QUERY_TYPE_LABELS.get(e.get("query_type"), e.get("query_type")) == basis
            )
            row.append(count)
        matrix.append(row)
    if not matrix:
        matrix = [[0 for _ in basis_order]]
        dim_names = ["Sin hallazgos"]

    fig_h = max(5.3, 0.50 * len(dim_names) + 2.0)
    fig, ax = _new_fig(10.4, fig_h)
    cmap = LinearSegmentedColormap.from_list("cti_heat", [PANEL_BG, BLUE, YELLOW, RED, PURPLE])
    im = ax.imshow(matrix, aspect="auto", cmap=cmap)
    ax.set_xticks(range(len(basis_order)))
    ax.set_xticklabels(_wrap_labels(basis_order, width=13), fontsize=8, color=TEXT)
    ax.set_yticks(range(len(dim_names)))
    ax.set_yticklabels(_wrap_labels(dim_names, width=21), fontsize=8, color=TEXT)
    ax.set_title("Heatmap: dimensión vs dato usado en la búsqueda")
    cbar = fig.colorbar(im, ax=ax, fraction=0.032, pad=0.02)
    cbar.ax.yaxis.set_tick_params(color=MUTED, labelcolor=MUTED)
    cbar.outline.set_edgecolor(GRID)
    cbar.ax.set_ylabel("Hallazgos", color=MUTED, rotation=90)

    max_val = max(max(r) for r in matrix) if matrix else 0
    for i in range(len(matrix)):
        for j in range(len(basis_order)):
            val = matrix[i][j]
            color = TEXT if (max_val and val >= max_val * 0.45) else MUTED
            ax.text(j, i, str(val), ha="center", va="center", color=color, fontsize=8, fontweight="bold")
    ax.set_xticks([x - 0.5 for x in range(1, len(basis_order))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(dim_names))], minor=True)
    ax.grid(which="minor", color=GRID, linestyle="-", linewidth=0.8, alpha=0.55)
    ax.tick_params(which="minor", bottom=False, left=False)
    return _fig_to_base64(fig)


def field_source_bar_chart(source_counts: Dict[str, int]) -> str:
    if not source_counts:
        source_counts = {"Sin hallazgos": 0}
    items = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
    labels = _wrap_labels([k for k, _ in items], width=18)
    values = [int(v) for _, v in items]
    colors = [BLUE, AQUA, GREEN, YELLOW, PURPLE, ORANGE][: len(labels)]

    fig, ax = _new_fig(9.0, 4.9)
    ax.bar(range(len(values)), values, color=colors, alpha=0.88, width=0.62)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=8, color=TEXT)
    ax.set_ylabel("Evidencias")
    ax.set_title("Hallazgos por vector de búsqueda")
    ax.grid(True, axis="y", color=GRID, alpha=0.35)
    ax.grid(False, axis="x")
    ymax = max(values) if values else 0
    ax.set_ylim(0, ymax + max(1, ymax * 0.18))
    for i, v in enumerate(values):
        ax.text(i, v + max(0.08, ymax * 0.025 if ymax else 0.08), str(v), ha="center", color=TEXT, fontsize=9, fontweight="bold")
    return _fig_to_base64(fig)


def confidence_distribution_chart(evidence_rows: List[Dict[str, object]]) -> str:
    values = [float(e.get("confidence_score", 0)) for e in evidence_rows]
    if not values:
        values = [0]
    labels = ["0-0.25", "0.25-0.50", "0.50-0.75", "0.75-1.00"]
    counts = [0, 0, 0, 0]
    for value in values:
        idx = min(3, max(0, int(value / 0.25)))
        if value == 1.0:
            idx = 3
        counts[idx] += 1
    colors = [GREEN, YELLOW, ORANGE, RED]
    fig, ax = _new_fig(8.8, 4.9)
    ax.bar(labels, counts, color=colors, alpha=0.88, width=0.62)
    ax.set_title("Distribución de confianza de evidencias")
    ax.set_ylabel("Cantidad de evidencias")
    ax.set_xlabel("Rango de confianza")
    ax.grid(True, axis="y", color=GRID, alpha=0.35)
    ax.grid(False, axis="x")
    ymax = max(counts) if counts else 0
    ax.set_ylim(0, ymax + max(1, ymax * 0.18))
    for i, c in enumerate(counts):
        ax.text(i, c + max(0.08, ymax * 0.025 if ymax else 0.08), str(c), color=TEXT, ha="center", fontsize=9, fontweight="bold")
    return _fig_to_base64(fig)


def evidence_review_chart(evidence_rows: List[Dict[str, object]]) -> str:
    fp_counts = Counter(str(e.get("false_positive_risk", "Sin dato")) for e in evidence_rows)
    review_count = sum(1 for e in evidence_rows if bool(e.get("requires_human_review")))
    no_review = max(0, len(evidence_rows) - review_count)
    labels = ["Revisión humana", "Sin revisión inicial"] + [f"FP: {k}" for k in sorted(fp_counts.keys())]
    values = [review_count, no_review] + [fp_counts[k] for k in sorted(fp_counts.keys())]
    if not values or sum(values) == 0:
        labels, values = ["Sin evidencias"], [0]
    colors = [ORANGE, GREEN, BLUE, YELLOW, RED, PURPLE, AQUA][: len(values)]

    fig, ax = _new_fig(9.0, 4.9)
    y = list(range(len(labels)))
    ax.barh(y, values, color=colors, alpha=0.88, height=0.60)
    ax.set_yticks(y)
    ax.set_yticklabels(_wrap_labels(labels, width=22), color=TEXT)
    ax.invert_yaxis()
    ax.set_xlabel("Cantidad")
    ax.set_title("Calidad operativa de evidencias")
    ax.grid(True, axis="x", color=GRID, alpha=0.35)
    ax.grid(False, axis="y")
    xmax = max(values) if values else 0
    ax.set_xlim(0, xmax + max(1, xmax * 0.18))
    for i, v in enumerate(values):
        ax.text(v + max(0.08, xmax * 0.025 if xmax else 0.08), i, str(v), color=TEXT, va="center", fontsize=8.5, fontweight="bold")
    return _fig_to_base64(fig)


def domain_signal_chart(evidence_rows: List[Dict[str, object]]) -> str:
    """Ranking visual de dominios encontrados. Útil para contexto de superficies."""
    domain_counts = Counter(_domain(str(e.get("url", ""))) for e in evidence_rows)
    items = domain_counts.most_common(10)
    if not items:
        items = [("sin hallazgos", 0)]
    labels = _wrap_labels([d for d, _ in items], width=25)
    values = [c for _, c in items]
    fig_h = max(4.9, 0.40 * len(labels) + 1.5)
    fig, ax = _new_fig(9.8, fig_h)
    y = list(range(len(labels)))
    ax.barh(y, values, color=BLUE, alpha=0.86, height=0.58)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, color=TEXT)
    ax.invert_yaxis()
    ax.set_xlabel("Menciones")
    ax.set_title("Dominios con mayor cantidad de señales")
    ax.grid(True, axis="x", color=GRID, alpha=0.35)
    ax.grid(False, axis="y")
    xmax = max(values) if values else 0
    ax.set_xlim(0, xmax + max(1, xmax * 0.18))
    for i, v in enumerate(values):
        ax.text(v + max(0.08, xmax * 0.025 if xmax else 0.08), i, str(v), color=TEXT, va="center", fontsize=8.5, fontweight="bold")
    return _fig_to_base64(fig)
