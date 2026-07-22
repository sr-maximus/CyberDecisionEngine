# Linea base de CyberDecisionEngine

**Fecha de corte:** 2026-07-19  
**Alcance:** codigo, contenedores, API, interfaz web, persistencia, informes y documentacion.  
**Regla:** los resultados historicos se conservaron; ninguna credencial fue escrita ni impresa.

## Estado reproducible

| Control | Resultado | Evidencia |
|---|---:|---|
| API | HTTP 200 | `GET /api/health` |
| Web | HTTP 200 | `http://localhost:8080/` |
| Manual HTML | HTTP 200 | `/docs/Manual_Plataforma_Ciberinteligencia.html` |
| Pruebas Python | 120 aprobadas | `.venv/bin/pytest -q` |
| Lint Python | aprobado | `.venv/bin/ruff check cyberdeck cyberdeck_api tests` |
| PostgreSQL | saludable | contenedor `cyberdecisionengine-postgres` |
| API | saludable | contenedor `cyberdecisionengine-api` |
| Sidecars | saludables | Tor, OSINT tools, SpiderFoot y superficie externa |

## Informes de regresion

Los seis HTML solicitados responden HTTP 200 y se conservan en `reports/web`. Los
artefactos actuales no contienen imagenes rotas: solo incorporan capturas
verificadas por el contrato `EvidenceCapture`. Cuando la corrida historica no
contiene una captura valida, el informe explica la ausencia y nunca sustituye la
evidencia por una imagen inferida.

## Hallazgos priorizados

| Severidad | Hallazgo | Causa | Impacto | Estado |
|---|---|---|---|---|
| Alta | El KPI `9/22` mezclaba conectores elegibles con registrados o no configurados | el denominador usaba el catalogo completo | lectura ejecutiva engañosa | corregido: registradas/elegibles/consultadas/productivas |
| Alta | La biblioteca de 1.500 elementos contenia plantillas preventivas, no 1.500 escenarios ejecutables | esquema combinatorio sin disparadores ni evidencia | inflaba capacidad analitica | corregido: referencias separadas de escenarios activos |
| Alta | Las formulas visibles se mantenian separadas del codigo ejecutable | no existia `MethodologyRegistry` | riesgo de divergencia entre UI, manual e informe | corregido: registro canonico versionado |
| Media | `/api/runs` devuelve contextos voluminosos sin paginacion de resumen | contrato unico para lista y detalle | trafico y render innecesarios | roadmap |
| Media | `country-state-city` produce un chunk diferido grande | catalogo geografico completo | latencia al abrir ciudad; no afecta carga inicial | aceptado y medido en auditoria 01 |
| Media | El modelo de evidencia no tenia un contrato de captura visual | solo existian URL y validacion tecnica | el informe no podia demostrar que una captura fue generada | corregido: `EvidenceCapture` y validacion de assets |
| Media | Los paquetes independientes conservaban un `run-summary.json` anterior | el regenerador copiaba informes y contexto, pero no reconstruia el resumen | dashboard/API y carpeta `outputs` podian diferir | corregido y cubierto por prueba |
| Baja | El host no expone Node en `PATH` por defecto | runtime encapsulado de Codex/Docker | el build local requiere ruta del runtime o Docker | documentado |
| Informativa | La copia no contiene `.git` | entrega sin metadatos Git | no es posible crear rama o commits | limitacion del workspace |

## Casos reales disponibles

| Organizacion | runId | Registros brutos | Unicos | Duplicados | Hallazgos validados |
|---|---|---:|---:|---:|---:|
| Grupo Aval | `2691ce2216b4` | 472 | 376 | 96 | 0 |
| NTT DATA | `d071615257a0` | 489 | 387 | 102 | 0 |

La ausencia de hallazgos validados no se interpreta como ausencia de riesgo. El
resultado significa que la cobertura disponible no supero el umbral de
validacion requerido para afirmar un hallazgo.

## Criterio de cierre

La linea base queda cerrada: los conteos usan denominadores elegibles, la
metodologia visible proviene del registro versionado, las plantillas no se
presentan como escenarios activos, las capturas tienen contrato trazable, los
seis informes se sirven sin assets rotos y los paquetes `outputs` se sincronizan
desde la misma fuente de verdad.
