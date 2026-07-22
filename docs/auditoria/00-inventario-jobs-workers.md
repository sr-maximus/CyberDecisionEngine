# Inventario de jobs y workers

| Proceso | Implementacion | Disparo | Estado y persistencia |
|---|---|---|---|
| Ejecucion principal | `RunStore` / `_execute` | `POST /api/analysis` | progreso por etapas y contexto atomico |
| Reejecucion | `RunStore.rerun` | usuario autorizado | nuevo `runId`; no sobrescribe historial |
| Informe | `generate_run_report` | boton del usuario | artefacto bajo demanda; no automatico |
| Monitoreo | `MonitoringStore._launch_due_profiles` | bucle periodico | perfiles, siguiente ejecucion y logs |
| Sincronizacion | `MonitoringStore._sync_completed_runs` | bucle periodico | alertas nuevas deduplicadas por fingerprint |
| OSINT general | sidecar `osint-tools` | etapa de recoleccion | limites de tiempo, objetivos y concurrencia |
| SpiderFoot | sidecar `spiderfoot` | etapa habilitada | salida estructurada; sin interfaz propia |
| Superficie | sidecar `kali-surface` | alcance autorizado | sondas pasivas/livianas permitidas |
| Tor | `tor-proxy` | fuente habilitada | proxy temporal aislado |
| OpenClaw | gateway de IA aislado | accion explicita | gateway activo; modelo `configured_unverified` sin credencial; no bloquea pipeline |

## Transiciones de una ejecucion

`queued -> running -> completed | failed`

Durante `running` se publican etapas y porcentaje. Una sesion web que expire no
cancela el worker. El informe es una accion posterior y separada del analisis.

## Controles

- presupuesto de tiempo por ejecucion;
- limites por sidecar;
- reintentos acotados en conectores;
- persistencia por `runId`;
- deduplicacion de alertas de monitoreo;
- los fallos opcionales degradan cobertura, no eliminan resultados validos de
  otros conectores.
