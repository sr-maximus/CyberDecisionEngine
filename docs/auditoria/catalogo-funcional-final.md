# Catálogo funcional final

**Fecha de corte:** 2026-07-20  
**Superficie canónica:** `http://localhost:8080/?view=<vista>`  
**Estados:** terminado; pendiente de configuración; parcial; oculto por diseño.

## Criterio de clasificación

- **Terminado:** tiene ruta, componente, datos reales o estado vacío honesto,
  permisos y acción verificable.
- **Pendiente de configuración:** la función está implementada, pero necesita un
  proveedor, credencial o servicio opcional para producir resultados.
- **Parcial:** aporta una función útil, pero conserva una deuda conocida.
- **Oculto por diseño:** no se presenta como disponible porque carece de datos,
  permiso o validación.

## Menús y superficies

| Función | Vista | Estado | Duplicada | Decisión | Destino canónico | Evidencia/prueba |
|---|---|---|---|---|---|---|
| Visión general | `overview` | terminado | no | conservar como superficie canónica de alcance, ejecución y lectura resumida | Overview | `App.renderView`; configuración, progreso y resultados sin marca predefinida |
| Tablero estratégico | `dashboards` | terminado | no | conservar como análisis principal | StrategicDashboard | snapshot común y evidencia global |
| Escenarios de decisión | `scenarios` | terminado | no | conservar; mostrar solo activaciones aplicables | ScenarioDecisionView | pruebas de esquema y escenarios |
| Asistente estratégico | `ai` | pendiente de configuración | no | conservar con degradación determinista | AIAssistantView | proveedor opcional; OpenClaw opcional |
| Superficie de ataque | `attackSurface` | terminado | no | conservar | AttackSurfaceView | datos del run; no recollecta al navegar |
| Marca y fraude | `brand` | terminado | no | conservar | BrandRiskView | evidencia filtrada por módulo |
| Riesgo virtual de empleados | `employeeRisk` | terminado | no | mantener aislado | EmployeeRiskView | formulario individual/lote e informe propio |
| Desinformación | `disinformation` | terminado | no | conservar; vacío sin señales | DisinformationView | mapeo DISARM derivado del run |
| OSINT | `osint` | terminado | no | conservar | SourceIntelligenceView | fuentes públicas, URLs y estado vacío |
| Inteligencia SOCMINT | `socmint` | terminado | no | conservar | SocmintView | grafo derivado de entidades/relaciones reales |
| Dark Web | `darkweb` | terminado con cobertura variable | no | conservar con estado explícito | SourceIntelligenceView | Tor e índices autorizados; no inventa URLs |
| Mapeo de frameworks | `frameworks` | terminado | no | conservar | FrameworksView | ATT&CK, D3FEND, ATLAS, DISARM y controles |
| Historial | `runs` | terminado | no | conservar | RunsView | abrir run, relanzar y solicitar informe |
| Informes | `reports` | terminado | no | conservar | ReportsView | técnico/ejecutivo, descarga y control de borrado |
| Uso y modelo | `help` | terminado | no | conservar | UsageGuideView | manual, guía y Methodology Registry |
| Configuración | `settings` | terminado por rol | no | conservar | SettingsView | usuarios, licencias, fuentes, API y auditoría |

## Fronteras funcionales aplicadas

### Overview y alcance

`overview` es la superficie canónica. Allí se configura la organización, los
dominios, comparativos, país, sector, ventana, modo y autorización; también se
observan la etapa, el progreso y los resultados de la ejecución seleccionada. La
ruta heredada `?view=domains` redirige a Overview y ya no existe un segundo menú
ni una segunda copia del dashboard.

### Organización y personas

La creación general envía `subject_type="organization"` y nunca incluye
`person_name`. El análisis de personas permanece dentro de
`employeeRisk`, con formulario, permisos, minimización e informe separados. El
backend reutilizable conserva soporte de persona para ese flujo, no como caja
genérica del tablero principal.

### Evidencia global y por módulo

El tablero estratégico muestra el libro global. Las vistas OSINT, SOCMINT, Dark
Web, superficie, marca, desinformación, frameworks y escenarios reciben un libro
filtrado por su semántica. Un estado sin datos no dibuja nodos ni inventa valores.

## Acciones verificadas

| Acción | Componente/endpoint | Estado |
|---|---|---|
| Iniciar análisis autorizado | `POST /api/analysis` | funcional |
| Ver progreso durable | `GET /api/runs/{run_id}` | funcional |
| Relanzar corrida | `POST /api/runs/{run_id}/rerun` | funcional |
| Generar informe bajo solicitud | endpoint de reporte del run | funcional |
| Descargar informe | `/api/reports/{path}/download` | funcional |
| Eliminar informe con rol | ReportsView/API | funcional |
| Cambiar idioma ES/EN | AppShell | funcional |
| Cambiar tema claro/oscuro | AppShell | funcional |
| Cerrar sesión y expirar por inactividad | App/session | funcional |
| Contraer menú | AppShell | funcional |
| Guardar/gestionar fuentes | SettingsView/API | funcional por rol |
| Administrar empresas, usuarios y licencias | SettingsView/control plane | funcional por rol |

## Funciones opcionales o condicionadas

| Función | Condición | Comportamiento sin condición |
|---|---|---|
| OpenClaw | gateway habilitado, política válida y modelo verificable | gateway activo; sin credencial, el modelo queda `configured_unverified` y el pipeline determinista continúa |
| OpenCTI | `OPENCTI_MODE` diferente de `disabled` y configuración válida | backend interno completo |
| Proveedores opcionales | clave/modelo configurado | análisis determinista y editor disponibles |
| Fuentes con API | credencial válida | estado `unconfigured` o `skipped`; no entra en elegibles |
| Captura visual | asset local con hash y dimensiones | “captura no disponible” con causa |
| PESTEL/Porter | evidencia corporativa, regulatoria, sectorial y de noticias con cobertura suficiente | muestra aspectos y cobertura disponible; la presión agregada permanece `insufficient_evidence` si no es publicable |
| Grafo SOCMINT | nodos y relaciones derivados | estado vacío, sin nodos sintéticos |

## Funciones retiradas o desactivadas

| Función | Motivo | Reemplazo |
|---|---|---|
| Búsqueda genérica de personas en alcance | mezclaba propósitos y privacidad | Riesgo virtual de empleados |
| KPI “Fuentes saludables / total registrado” | denominador ambiguo | registradas/elegibles/consultadas/productivas |
| 1,500 “escenarios activos” | eran plantillas combinatorias | plantillas preventivas + escenarios activados por evidencia |
| Menú separado “Alcance de análisis” | duplicaba la configuración y el flujo del Overview | configuración, ejecución y progreso integrados en Overview; redirección heredada |
| Capturas remotas inferidas | no prueban captura interna | `EvidenceCapture` verificada o ausencia explícita |
| OpenCTI obligatorio | acoplamiento y costo operacional | `KnowledgeBackendPort`; modo deshabilitado por defecto |

## Pruebas y limitaciones

- la regresión Python, el lint y el build web deben aprobarse antes de publicar;
- los informes sintéticos se validan desde la misma fuente de verdad;
- los nombres, dominios, cuentas y resultados operativos permanecen fuera del
  repositorio;
- el acceso autenticado se valida únicamente en un entorno local autorizado y
  sin registrar credenciales;
- la evidencia visual se genera localmente y no se publica;
- `GET /api/runs` requiere paginación antes de escalar el historial.

## Estado final

No quedan menús duplicados ni placeholders presentados como resultados reales.
Las funciones condicionadas muestran su dependencia y degradan sin bloquear el
análisis principal. Las deudas conocidas quedan en
`docs/roadmap/Mejoras_Recomendadas.md`.
