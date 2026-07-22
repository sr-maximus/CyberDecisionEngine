# Inventario de endpoints

Inventario obtenido de `GET /openapi.json` (31 rutas).

| Area | Metodo y ruta | Uso |
|---|---|---|
| Salud | `GET /api/health` | estado de API y almacenamiento |
| Analisis | `POST /api/analysis` | crea una ejecucion |
| Analisis | `GET /api/runs` | lista ejecuciones |
| Analisis | `GET /api/runs/{run_id}` | detalle y progreso |
| Analisis | `GET /api/runs/{run_id}/snapshot` | fuente de verdad del dashboard |
| Analisis | `POST /api/runs/{run_id}/rerun` | reejecucion autorizada |
| Informes | `GET /api/reports` | catalogo |
| Informes | `GET /api/reports/{report_path}` | metadatos/artefacto |
| Informes | `GET /api/reports/{report_path}/download` | descarga protegida |
| Informes | `GET /api/reports/archive` | archivo historico |
| Informes | `POST /api/runs/{run_id}/report` | genera informe bajo demanda |
| Inteligencia | `GET /api/attack-surface` | superficie externa |
| Inteligencia | `POST /api/employee-risk/analyze` | modulo independiente de personas |
| Inteligencia | `GET /api/mitre/groups` | catalogo de grupos |
| Inteligencia | `GET /api/disinformation/framework` | DISARM normalizado |
| Escenarios | `GET /api/scenarios/library` | plantillas y coincidencias |
| IA | `GET/PUT /api/ai/config` | configuracion de proveedores |
| IA | `POST /api/ai/package` | paquete de contexto gobernado |
| Monitoreo | `GET /api/monitoring` | estado, alertas y logs |
| Monitoreo | `POST /api/monitoring/profiles` | crea perfil programado |
| Monitoreo | `PATCH /api/monitoring/profiles/{profile_id}` | modifica perfil |
| Monitoreo | `PATCH /api/monitoring/alerts/{alert_id}` | ciclo de alerta |
| Soporte | `POST /api/support/tickets` | registra falla reportada |
| Soporte | `PATCH /api/support/tickets/{ticket_id}` | gestiona soporte |
| Plataforma | `GET /api/platform/logs` | auditoria operativa |
| Licencias | `GET /api/licensing/overview` | arbol de gobierno |
| Licencias | `GET/POST /api/licensing/companies` | empresas |
| Licencias | `GET/POST /api/licensing/licenses` | licencias |
| Licencias | `PATCH /api/licensing/licenses/{license_id}` | activacion y modulos |
| Licencias | `GET/POST /api/licensing/users` | usuarios |
| Licencias | `PATCH /api/licensing/users/{user_id}` | estado, rol y permisos |

Todas las rutas protegidas pasan por el contrato de sesion/rol de la API. La
descarga valida el nombre del artefacto para impedir traversal.
