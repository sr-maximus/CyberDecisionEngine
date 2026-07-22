# Mejoras recomendadas de CyberDecisionEngine

Documento separado del manual. Cada elemento se deriva de evidencia observada el 2026-07-19.

| Prioridad | Horizonte | Esfuerzo | Problema/evidencia | Propuesta | Beneficio | Riesgo/dependencia | Criterio de aceptación |
|---|---|---:|---|---|---|---|---|
| P0 | urgente | S | Python local 3.9 frente a requisito 3.13 | instalar 3.13 o declarar Docker como único runtime soportado | reproducibilidad | scripts locales | `doctor` falla explícitamente fuera de versión |
| P0 | urgente | M | 31 incidencias Ruff | limpiar imports/variables y renombrar parámetros ambiguos sin cambiar fórmulas | mantenibilidad | pruebas completas | Ruff y pytest pasan |
| P0 | urgente | M | respuesta `/api/runs` cercana a 3 MB y polling continuo | endpoint de lista resumida, detalle por run y polling solo activo | rendimiento | contrato frontend | reposo <1 request/30 s y lista <100 KB |
| P1 | corto | M | validación de informes recién incorporada | mostrar estado y observaciones en UI; bloquear publicación final rechazada | gobierno | UX/reportes | estado visible y test E2E |
| P1 | corto | M | healthcheck Tor genera avisos | sustituir conexión SOCKS incompleta por comprobación de proceso/control segura | observabilidad | imagen Tor | cero avisos periódicos y health correcto |
| P1 | corto | L | geolocalización normalizada incompleta | modelo `GeoObservation` con tipo, precisión, confianza y procedencia | honestidad geográfica | migración | 100 % de puntos trazables; desconocidos sin coordenada |
| P1 | corto | L | grafo SOCMINT usa layout parcialmente sintético | construir nodos/aristas solo desde entidades y relaciones; métricas backend | rigor | modelo de entidades | cero nodos sin evidencia; export y panel lateral |
| P1 | corto | M | autenticación local no es suficiente para SaaS | IdP/SSO, JWT rotativo, MFA, revocación y enforcement API | seguridad | proveedor de identidad | pruebas de aislamiento y sesión |
| P1 | corto | M | OpenClaw tiene gateway pero roles limitados | contratos de agentes, auditoría, sanitización y fixtures de prompt injection | IA controlada | proveedor opcional | ejecución sin IA y pruebas de permisos |
| P2 | mediano | L | chunk de ciudades 2.19 MB gzip | generar catálogos por país y caché persistente | UX | pipeline build | <250 KB gzip por país |
| P2 | mediano | L | mapas y grafos dependen de resumen frontend | endpoints agregados geoespaciales y de grafo por `runId` | escalabilidad | esquema PostgreSQL | 10k registros sin bloquear UI |
| P2 | mediano | M | ausencia de comparación histórica uniforme | snapshots comparables y delta por métrica/versiones | decisiones | migraciones | comparación no mezcla modelos |
| P2 | mediano | L | fórmulas heurísticas sin dataset de outcomes | programa de calibración, Brier score y reliability curves | predicción honesta | datos etiquetados | solo usar “probabilidad” tras calibración |
| P2 | mediano | M | frameworks dinámicos requieren gobierno | job de sincronización firmado, changelog y rollback | actualización segura | licencias/red | versión/hash en cada run |
| P2 | mediano | L | licencia solo preparada | enforcement server-side por módulo, empresa y usuario | comercialización | autenticación | pruebas cross-tenant negativas |
| P3 | largo | XL | PostgreSQL sin capa geoespacial | evaluar PostGIS para agregaciones | rendimiento mapa | operación DB | benchmarks justifican adopción |
| P3 | largo | XL | interoperabilidad CTI opcional | piloto OpenCTI/TAXII con datos validados únicamente | colaboración | costo operacional | evaluación demuestra valor neto |
| P3 | largo | L | informes HTML únicamente | PDF accesible firmado y paquete verificable | distribución | renderer | hash y paridad con HTML |
| P3 | largo | L | observabilidad dispersa | métricas, traces, correlación run/tool y SLO | soporte | stack observabilidad | error trazable por runId |
| P3 | investigación | XL | sentimiento puede inducir error | validar modelo multilingüe por dominio y sesgo | marca/fraude | dataset etiquetado | métricas y limitaciones publicadas |
| P3 | investigación | XL | Admiralty Code no implementado | doble dimensión confiabilidad de fuente/credibilidad de información | CTI | gobierno analítico | tabla, fórmula y test |

