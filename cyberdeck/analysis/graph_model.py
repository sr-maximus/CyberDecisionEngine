from __future__ import annotations


def digital_proximity(graph_distance: float) -> float:
    return 1 / (1 + max(0.0, graph_distance))
