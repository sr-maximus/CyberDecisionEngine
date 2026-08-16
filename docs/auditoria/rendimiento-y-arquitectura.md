# Rendimiento y arquitectura

**Alcance:** API, frontend, PostgreSQL, sidecars e informes con datos sintéticos.
**Regla:** no se atribuyen mejoras temporales cuando no existe una medición histórica comparable.

## Resultado ejecutivo

La arquitectura local separa web, API, PostgreSQL, OSINT tools, SpiderFoot,
superficie externa y proxy Tor. La validación debe confirmar que los servicios
requeridos están saludables y que el frontend no bloquea las investigaciones:
el identificador local persiste el estado y el worker continúa aunque termine la
sesión web.

`GET /api/runs` debe ofrecer resumen paginado y detalle bajo demanda antes de
aumentar el número de organizaciones o ejecuciones. El tamaño observado se
registra únicamente en el artefacto local de rendimiento.

## Mediciones actuales

### Frontend de producción

El build de producción se valida con la versión fijada de TypeScript y Vite:

| Artefacto | Tamaño | Gzip | Carga |
|---|---:|---:|---|
| HTML | `<measure>` | `<measure>` | inicial |
| CSS | `<measure>` | `<measure>` | inicial |
| JavaScript principal | `<measure>` | `<measure>` | inicial |
| Catálogo geográfico | `<measure>` | `<measure>` | diferida |

- módulos transformados: `<measure>`;
- duración del build: `<measure>`;
- el catálogo geográfico no forma parte del chunk inicial;
- los módulos funcionales principales se cargan con `lazy()` y `Suspense`.

La decisión de conservar `country-state-city` de forma diferida está documentada
en `docs/auditoria/01-optimizacion-geografica.md`. No se justifica perder cobertura
geográfica solo para eliminar un warning de tamaño.

### API e informes servidos localmente

| Recurso | HTTP | Tiempo observado |
|---|---:|---:|
| Overview | `<status>` | `<measure-locally>` |
| Manual HTML | `<status>` | `<measure-locally>` |
| Informe técnico sintético | `<status>` | `<measure-locally>` |
| Informe multidominio sintético | `<status>` | `<measure-locally>` |
| `GET /api/runs` | `<status>` | `<measure-locally>` |

Los tiempos son una muestra local en caliente, no una garantía de producción.
No incluyen latencia de red externa ni tiempo de recolección.

### Recursos de contenedores en reposo

| Servicio | CPU | Memoria observada | Límite explícito |
|---|---:|---:|---:|
| Web | `<measure>` | `<measure>` | host |
| API | `<measure>` | `<measure>` | host |
| PostgreSQL | `<measure>` | `<measure>` | host |
| OSINT tools | `<measure>` | `<measure>` | 512 MiB |
| SpiderFoot | `<measure>` | `<measure>` | 1 GiB |
| Superficie externa | `<measure>` | `<measure>` | 1.5 GiB |
| Tor | `<measure>` | `<measure>` | 256 MiB |

La muestra corresponde a `docker stats --no-stream`. CPU y memoria cambian
durante una recolección; los límites de sidecars evitan que una herramienta
auxiliar agote el host.

### Almacenamiento

| Componente | Tamaño observado |
|---|---:|
| `data/` | `<measure-locally>` |
| `reports/` | `<measure-locally>` |
| `outputs/` | `<measure-locally>` |
| `web/dist/` | `<measure-locally>` |
| Base PostgreSQL | `<measure-locally>` |

Los datos originales, contextos normalizados, informes y paquetes de entrega se
mantienen separados. La retención debe gobernarse por organización y tipo de
evidencia antes de un despliegue multiempresa de larga duración.

## Duración de ejecuciones autorizadas

| Ejecución | Alcance | Inicio | Fin del análisis | Duración | Registros brutos / únicos |
|---|---|---|---|---:|---:|
| `<run-id>` | `<authorized-scope>` | `<start>` | `<finish>` | `<duration>` | `<raw/unique>` |

La duración depende de fuentes, rate limits, Tor y cobertura. La generación de
informe se ejecuta después y solo por solicitud del usuario; por eso no debe
calcularse restando la fecha de una regeneración posterior.

## Comparación antes/después

| Área | Línea base | Estado final | Efecto verificable |
|---|---|---|---|
| Fuentes | un total registrado podía usarse como denominador | registradas, elegibles, intentadas y productivas separadas | validar localmente con un alcance sintético |
| Paquetes de salida | el resumen podía conservar cifras obsoletas | se reconstruye desde el mismo `RunContext` del informe | paridad con API, dashboard, HTML, JSON y CSV |
| Escenarios | las plantillas podían leerse como escenarios activos | referencias preventivas separadas de escenarios soportados | elimina capacidad inflada |
| Informes | capturas no verificadas podían confundirse con evidencia | solo assets locales verificados o causa explícita de ausencia | regresión HTTP sin imágenes remotas |
| Pruebas | cobertura inicial parcial | suite vigente completa | incluye sincronización e integridad del paquete |
| Build web | medición histórica no comparable | medición local actual | diferencia solo informativa |
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
| P1 | `/api/runs` puede entregar contextos completos | crear DTO paginado de resumen y endpoint de detalle |
| P1 | no hay tiempos durables por colector | persistir inicio, fin, reintentos y espera por fuente |
| P2 | el chunk geográfico diferido puede ser voluminoso | evaluar catálogos por país solo con medición de usuario |
| P2 | `outputs/` no es volumen Docker | montar volumen o ejecutar exportación desde el host en producción |
| P2 | retención aún es manual | aplicar políticas por organización, TLP/PAP y tipo de dato |

## Criterio de cierre

- API, web, PostgreSQL y sidecars activos;
- suite Python y lint aprobados;
- build web aprobado;
- informes sintéticos de regresión disponibles por HTTP;
- paquetes de salida sincronizados con su snapshot;
- deuda restante registrada sin presentarla como funcionalidad terminada.
