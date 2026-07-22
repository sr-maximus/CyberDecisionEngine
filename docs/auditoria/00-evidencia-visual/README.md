# Evidencia visual de línea base y cierre

La inspeccion visual se realiza con el navegador interno sobre
`http://localhost:8080`. Las capturas historicas ya disponibles se conservan en
`docs/design/`; no se reutilizan como evidencia de una ejecucion actual.

## Casos a conservar en la regresion

- vision general y tablero estrategico;
- OSINT, SOCMINT, Dark Web, superficie, marca/fraude y frameworks;
- historial, informes, uso/modelo y configuracion;
- tema claro y oscuro;
- los seis informes HTML enumerados en `00-linea-base.md`.

Una captura de interfaz solo demuestra presentacion. Una captura de evidencia
tecnica debe pertenecer al `runId`, conservar URL, fecha, hash, dimensiones y
estado de validacion en el modelo de evidencia.

## Capturas de cierre 2026-07-19

- `dashboard-final.png`: tablero estratégico en tema claro, sin desbordamiento horizontal.
- `dashboard-modo-oscuro-final.png`: PESTEL/Porter y estados `N/D` legibles en tema oscuro.
- `metodologia-final.png`: registro metodológico administrativo con fórmulas, versión y estado.
- `frameworks-final.png`: navegación y detalle de framework sin tarjetas recortadas.
- `configuracion-final.png`: licenciamiento, árbol empresarial y creación de empresa sin controles fuera del viewport.
- `manual-final.png`: manual navegable con 24 secciones y 52 enlaces de índice.
- `informe-ejecutivo-final.png`: informe multidominio regenerado desde el snapshot canónico.

La comprobación DOM adicional confirmó: ausencia de scroll horizontal global, cambio completo ES/EN en la vista probada, cero imágenes remotas o rotas en los informes ejecutivo y técnico, los cinco dominios presentes en el informe técnico y 143 enlaces externos de evidencia disponibles para revisión.
