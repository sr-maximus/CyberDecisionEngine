# Decisión sobre OpenCTI

## Qué es

OpenCTI es una plataforma externa de gestión y colaboración de conocimiento CTI basada en entidades, relaciones e interoperabilidad STIX.

## Qué no es

No es un colector obligatorio, un motor de riesgo, un validador de verdad ni una condición para generar dashboards o informes. No se instala, inicia o configura automáticamente.

## Capacidad incremental y duplicada

Puede añadir colaboración multiusuario, intercambio STIX, streams y análisis de grafos. Duplica parcialmente entidades, relaciones, histórico e informes ya mantenidos por el backend interno.

## Modos

- `disabled`: solo `InternalKnowledgeBackend`; predeterminado.
- `read_context`: lee contexto OpenCTI si está disponible y conserva escritura interna.
- `sync_validated`: escribe internamente y sincroniza únicamente conocimiento validado.
- `system_of_record`: habilita lectura y sincronización externa, manteniendo respaldo interno para continuidad.

Todos los modos son tolerantes a URL/token ausentes, caída, licencia insuficiente o fallo de conector. Ningún error externo bloquea colección, análisis, dashboard o informe.

## Datos sincronizables

Solo entidades normalizadas, relaciones validadas, indicadores, vulnerabilidades aplicables, actores, campañas, malware, técnicas, sightings, informes, confianza, TLP/PAP y referencias de evidencia. Se rechazan datos brutos, duplicados, noticias no validadas, escenarios candidatos, relaciones propuestas por IA, caché y falsos positivos.

## Resultado

Modo seleccionado: `disabled`. Valor neto: `-0.30`. Decisión: **dejar opcional**. Debe ejecutarse un piloto solo cuando exista una necesidad contractual o operativa de colaboración, STIX, streams o grafo que el backend interno no cubra de forma suficiente.
