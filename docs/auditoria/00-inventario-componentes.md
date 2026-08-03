# Inventario de componentes

| Componente | Implementacion | Responsabilidad | Persistencia o limite |
|---|---|---|---|
| Web | React 18, TypeScript, Vite, Nginx | navegacion, dashboards, administracion e informes | puerto 8080; consume `/api` |
| API | FastAPI, Pydantic | autenticacion local, ejecuciones, reportes, licencias, asistencia opcional y monitoreo | puerto 8000 |
| Motor | `cyberdeck` | recoleccion, normalizacion, deduplicacion, analisis y reportes | biblioteca Python |
| Ejecuciones | `cyberdeck_api.jobs.RunStore` | ciclo de vida, progreso, contexto e informe bajo demanda | PostgreSQL y `data/web_runs/<runId>` |
| Scheduler | `MonitoringStore` | perfiles periodicos, alertas deduplicadas y logs | `data/monitoring_state.json` |
| Base de datos | PostgreSQL 17 | ejecuciones, contextos, licencias y auditoria | volumen Docker |
| Fallback local | SQLite/JSON | operacion local y recuperacion controlada | `data/` |
| Informes | Jinja/HTML + JSON + CSV | artefactos ejecutivo y tecnico | `reports/web` |
| Tor | contenedor aislado | proxy opcional para fuentes autorizadas | red `tor_net`, sin puerto host |
| OSINT tools | sidecar de comandos acotados | utilidades pasivas y busqueda de identificadores autorizada | red `osint_net` |
| Superficie | sidecar Kali reducido | DNS, TLS, WHOIS y fingerprint pasivo autorizado | red `surface_net` |
| SpiderFoot | sidecar | recoleccion pasiva en segundo plano | red `osint_net` |
| OpenClaw | puerto opcional, deshabilitado | asistencia analitica gobernada | no es nucleo ni fuente de verdad |
| OpenCTI | `KnowledgeBackendPort`, opcional | interoperabilidad de conocimiento validado | `OPENCTI_MODE=disabled` por defecto |
| Registro semantico | `config/term_registry.json` | vocabulario comun y reglas de uso | versionado en repositorio |
| Registro metodologico | `config/methodologies.json` | formulas, reglas, versiones y pruebas | fuente canonica; implementacion en curso |

## Redes y aislamiento

- `default`: web, API y PostgreSQL.
- `osint_net`: API, OSINT tools y SpiderFoot.
- `surface_net`: API y superficie externa.
- `tor_net`: API, OSINT tools y proxy Tor.
- Los sidecars no publican puertos al host.
- Los contenedores de recoleccion eliminan capacidades Linux y aplican
  `no-new-privileges`; Tor y OSINT usan sistema de archivos de solo lectura.

## Propiedad de datos

| Objeto | Productor | Consumidores | Fuente de verdad |
|---|---|---|---|
| `SourceStatus` | recolectores | cobertura, dashboard, informe | contexto del `runId` |
| `ThreatEvent` | normalizacion | deduplicacion, entidades, riesgo | contexto del `runId` |
| evidencia original | recolector | validador e informe tecnico | referencia + hash inmutable |
| evidencia normalizada | pipeline | analitica y UI | contexto separado del original |
| `DecisionSnapshot` | motor de decision | dashboard e informes | contexto del `runId` |
| artefactos | generador | historial y descarga | `reports/web` + catalogo |
