from __future__ import annotations

import hashlib
import re
from typing import List

from app.models import SearchResult
from .base import SearchClient


class MockSearchClient(SearchClient):
    """Cliente determinístico para pruebas sin consultar internet."""

    name = "mock"

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        name = self._extract_first_phrase(query) or "Empleado Demo"
        lower = query.lower()
        candidates: List[SearchResult] = []

        if any(k in lower for k in ["linkedin", "profile", "perfil", "social media"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://www.linkedin.com/in/{self._slug(name)}-mock",
                title=f"{name} - Perfil profesional | LinkedIn",
                snippet=f"Perfil público de {name}. Experiencia, organización, cargo y publicaciones profesionales.",
                source=self.name,
                image_url=f"https://api.dicebear.com/9.x/initials/svg?seed={self._slug(name)}",
            ))
        if any(k in lower for k in ["github", "repository", "repo", "commit", ".env", "source code", "codigo fuente", "código fuente"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://github.com/mock-security/{self._slug(name)}-training-lab",
                title=f"Repositorio público de entrenamiento técnico asociado a {name}",
                snippet=f"Repositorio de laboratorio con referencias a Docker, Kubernetes y buenas prácticas. No contiene secretos reales. Nombre visible: {name}.",
                source=self.name,
            ))
        if any(k in lower for k in ["password", "contraseña", "credentials", "credenciales", "data leak", "breach"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.org/mock-breach-index/{self._slug(name)}",
                title=f"Índice de exposición pública relacionado con {name}",
                snippet=f"Resultado simulado: posible mención a credentials y corporate email. Requiere validación manual para descartar homónimo de {name}.",
                source=self.name,
            ))
        if any(k in lower for k in ["confidencial", "confidential", "internal use", "uso interno", "restricted"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.org/mock-document-reference/{self._slug(name)}",
                title=f"Referencia documental pública que menciona a {name}",
                snippet="Resultado simulado: aparece la palabra confidential en un contexto genérico. No prueba filtración; debe revisarse contexto.",
                source=self.name,
            ))
        if any(k in lower for k in ["speaker", "certificación", "certification", "conference", "conferencia", "mentor", "open source"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.org/mock-positive-signal/{self._slug(name)}",
                title=f"Señal positiva pública de {name}",
                snippet=f"{name} figura como speaker y mentor en una actividad pública de formación en ciberseguridad.",
                source=self.name,
            ))
        if any(k in lower for k in ["address", "dirección", "location", "ubicación", "office", "oficina"]):
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.org/mock-physical-exposure/{self._slug(name)}",
                title=f"Mención pública de ubicación laboral de {name}",
                snippet="Resultado simulado: publicación pública menciona oficina y ciudad. Revisar si la información ya es corporativa pública.",
                source=self.name,
            ))

        # Resultado informativo para búsquedas amplias por nombre exacto.
        if name != "Empleado Demo" and not candidates:
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.org/mock-public-profile/{self._slug(name)}",
                title=f"Resultado público general asociado a {name}",
                snippet=f"Resultado simulado para probar la etapa de descubrimiento inicial por nombre exacto de {name}. No representa evidencia negativa.",
                source=self.name,
                image_url=f"https://api.dicebear.com/9.x/initials/svg?seed={self._slug(name)}",
            ))

        # Ruido controlado para probar falsos positivos.
        if self._stable_int(query) % 17 == 0:
            candidates.append(SearchResult(
                query=query,
                url=f"https://example.net/mock-homonym/{self._stable_int(query)}",
                title="Resultado potencialmente homónimo",
                snippet="Mención genérica sin correo ni organización. Debe clasificarse como baja confianza.",
                source=self.name,
            ))

        return candidates[:count]

    @staticmethod
    def _extract_first_phrase(query: str) -> str:
        match = re.search(r'"([^"]+)"', query)
        return match.group(1) if match else ""

    @staticmethod
    def _slug(value: str) -> str:
        value = value.lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        return value.strip("-") or "empleado"

    @staticmethod
    def _stable_int(value: str) -> int:
        return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:8], 16)
