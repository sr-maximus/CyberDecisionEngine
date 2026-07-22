# Rendimiento y arquitectura

**Fecha de medición:** 2026-07-19  
**Alcance:** API, frontend, PostgreSQL, sidecars, informes y dos ejecuciones autorizadas.  
**Regla:** no se atribuyen mejoras temporales cuando no existe una medición histórica comparable.

## Resultado ejecutivo

La arquitectura local opera como siete servicios aislados: web, API, PostgreSQL,
OSINT tools, SpiderFoot, superficie externa y proxy Tor. Todos se encontraron
activos; API, PostgreSQL y sidecars reportaron estado saludable. El frontend no
queda bloqueado por las investigaciones: el `runId` persiste el estado y el worker
continúa aunque termine la sesión web.

La principal deuda de rendimiento confirmada no está en el render inicial, sino
en `GET /api/runs`: la lista entrega contextos completos y alcanzó 6.62 MB. Debe
separarse en resumen paginado y detalle bajo demanda antes de aumentar el número
de organizaciones o ejecuciones.

## Mediciones actuales

### Frontend de producción

Build verificado con TypeScript y Vite 6.4.3:

| Artefacto | Tamaño | Gzip | Carga |
|---|---:|---:|---|
| HTML | 0.40 KB | 0.27 KB | inicial |
| CSS | 160.71 KB | 26.82 KB | inicial |
| JavaScript principal | 867.35 KB | 201.71 KB | inicial |
| `country-state-city` | 8,065.19 KB | 2,188.53 KB | diferida |

- módulos transformados: 1,628;
- build Vite de esta verificación: 4.81 s;
- el catálogo geográfico no forma parte del chunk inicial;
- los módulos funcionales principales se cargan con `lazy()` y `Suspense`.

La decisión de conservar `country-state-city` de forma diferida está documentada
en `docs/auditoria/01-optimizacion-geografica.md`. No se justifica perder cobertura
geográfica solo para eliminar un warning de tamaño.

### API e informes servidos localmente

| Recurso | HTTP | Tiempo observado |
|---|---:|---:|
| Overview | 200 | 1.7 ms |
| Manual HTML | 200 | 2.2 ms |
| Informe técnico NTT DATA | 200 | 5.8-18.7 ms |
| Informe técnico Grupo Aval | 200 | 7.7-8.6 ms |
| Informe multidominio | 200 | 7.4-10.8 ms |
| `GET /api/runs` | 200 | 350 ms; 6,623,404 bytes |

Los tiempos son una muestra local en caliente, no una garantía de producción.
No incluyen latencia de red externa ni tiempo de recolección.

### Recursos de contenedores en reposo

| Servicio | CPU | Memoria observada | Límite explícito |
|---|---:|---:|---:|
| Web | 0.00 % | 10.91 MiB | host |
| API | 0.21 % | 151.6 MiB | host |
| PostgreSQL | 0.00 % | 67.87 MiB | host |
| OSINT tools | 0.24 % | 25.66 MiB | 512 MiB |
| SpiderFoot | 0.21 % | 74.01 MiB | 1 GiB |
| Superficie externa | 0.24 % | 40.63 MiB | 1.5 GiB |
| Tor | 0.01 % | 107.4 MiB | 256 MiB |

La muestra corresponde a `docker stats --no-stream`. CPU y memoria cambian
durante una recolección; los límites de sidecars evitan que una herramienta
auxiliar agote el host.

### Almacenamiento

| Componente | Tamaño observado |
|---|---:|
| `data/` | 54 MB |
| `reports/` | 13 MB |
| `outputs/` | 10 MB |
| `web/dist/` | 9.1 MB |
| Base PostgreSQL | 20 MB |

Los datos originales, contextos normalizados, informes y paquetes de entrega se
mantienen separados. La retención debe gobernarse por organización y tipo de
evidencia antes de un despliegue multiempresa de larga duración.

## Duración de ejecuciones reales

| Ejecución | Alcance | Inicio | Fin del análisis | Duración | Registros brutos / únicos |
|---|---|---|---|---:|---:|
| `2691ce2216b4` | Grupo Aval, `grupoaval.com` | 21:56:12 UTC | 21:59:05 UTC | 173 s | 472 / 376 |
| `d071615257a0` | NTT DATA, `nttdata.com` | 21:59:14 UTC | 22:08:35 UTC | 561 s | 489 / 387 |

La duración depende de fuentes, rate limits, Tor y cobertura. La generación de
informe se ejecuta después y solo por solicitud del usuario; por eso no debe
calcularse restando la fecha de una regeneración posterior.

## Comparación antes/después

| Área | Línea base | Estado final | Efecto verificable |
|---|---|---|---|
| Fuentes | un total registrado podía usarse como denominador | registradas, elegibles, intentadas y productivas separadas | Grupo Aval: 22/17/15/12; NTT DATA: 22/17/15/13 |
| Paquetes de salida | `run-summary.json` conservaba `total_sources=22` | se reconstruye desde el mismo `RunContext` del informe | paridad con API, dashboard, HTML, JSON y CSV |
| Escenarios | 1,500 plantillas podían leerse como escenarios | 1,500 referencias preventivas; 0 escenarios activos sin evidencia | elimina capacidad inflada |
| Informes | capturas no verificadas podían confundirse con evidencia | solo assets locales verificados o causa explícita de ausencia | seis regresiones HTTP 200 sin imágenes remotas |
| Pruebas | 106 pruebas en la primera línea base | 120 pruebas | incluye regresión de sincronización y hash común del paquete |
| Build web | 4.20 s en medición geográfica anterior | 4.81 s en esta sesión | diferencia informativa; entornos no idénticos |
| Tiempos por etapa | no existía telemetría histórica durable por colector | progreso durable y duración total verificable | aún falta histograma por colector |

No se afirma una mejora porcentual de tiempo total: no existe una ejecución
anterior comparable con la misma red, fuentes, alcance y versión.

## Decisiones arquitectónicas

1. Mantener PostgreSQL como persistencia transaccional y los contextos JSON como
   artefactos reproducibles; el regenerador sincroniza ambos cuando
   `DATABASE_URL` está configurado.
2. Mantener API y recolección desacopladas de la sesión del navegador.
3. Mantener Tor y herramientas OSINT en redes y contenedores separados, sin
   exponer sus interfaces al usuario final.
4. Mantener OpenClaw y OpenCTI opcionales y deshabilitados por defecto.
5. Mantener la generación de informes bajo solicitud explícita.
6. Conservar lazy loading geográfico mientras no exista evidencia de impacto en
   el primer render.

## Cuellos de botella y prioridad

| Prioridad | Hallazgo | Acción |
|---|---|---|
| P1 | `/api/runs` entrega 6.62 MB | crear DTO paginado de resumen y endpoint de detalle |
| P1 | no hay tiempos durables por colector | persistir inicio, fin, reintentos y espera por fuente |
| P2 | el chunk geográfico diferido pesa 2.19 MB gzip | evaluar catálogos por país solo con medición de usuario |
| P2 | `outputs/` no es volumen Docker | montar volumen o ejecutar exportación desde el host en producción |
| P2 | retención aún es manual | aplicar políticas por organización, TLP/PAP y tipo de dato |

## Criterio de cierre

- API, web, PostgreSQL y sidecars activos;
- 120 pruebas y lint aprobados;
- build web aprobado;
- seis informes de regresión HTTP 200;
- dos paquetes independientes sincronizados con su snapshot;
- deuda restante registrada sin presentarla como funcionalidad terminada.
