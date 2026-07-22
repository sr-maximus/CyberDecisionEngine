# CyberDecisionEngine: resumen antes/despues

Fecha de validacion: 2026-07-19

## Causas raiz corregidas

1. El contrato de evidencia no separaba de forma uniforme registro recolectado, evidencia contextual, evidencia directa, hallazgo validado e incidente confirmado.
2. La regeneracion de informes reprocesaba contextos ya deduplicados y podia alterar los contadores historicos.
3. El matching de ATT&CK, ATLAS y DISARM permitia relaciones demasiado amplias; una tecnica potencial podia presentarse como actividad observada.
4. El resumen del dashboard y el informe podian leer versiones distintas del mismo contexto historico.
5. Las metricas de riesgo y forecast usaban etiquetas de probabilidad que no correspondian a un modelo calibrado.
6. El volcado del informe conservaba enums Python y algunos filtros internos no reconocian hallazgos validados.
7. La grilla estrategica tenia reglas responsive con menor especificidad que la grilla de 12 columnas, lo que comprimía la interfaz movil.

## Antes y despues

| Area | Antes | Despues |
|---|---|---|
| Evidencia | Estados implicitos y conteos ambiguos | Taxonomia explicita `raw/contextual/related/direct/validated/confirmed/false_positive/discarded` |
| Deduplificacion | La segunda regeneracion podia reportar 0 duplicados | Regeneracion idempotente: 595 brutos, 593 unicos, 2 duplicados |
| Hallazgos | "Validado" podia aparecer como "confirmado" | 2 hallazgos validados, 0 confirmados, 0 incidentes |
| Vulnerabilidades | CVE de inteligencia general podia confundirse con aplicabilidad | 0 CVE/KEV aplicables; las candidatas exigen producto y version confirmados |
| Frameworks | Matching por similitud amplia | Activacion por ID exacto y evidencia asegurada; D3FEND no activa escenarios por si solo |
| Escenarios | Biblioteca y corrida podian mezclarse | 1500 plantillas preventivas; 0 escenarios activos en la corrida validada |
| Prediccion | Etiquetas de probabilidad de ataque | Indice no calibrado de presion de senales y bandas de sensibilidad |
| Controles | Valores heredados podian parecer evaluacion de cumplimiento | Solo controles declarados; los frameworks son mapeo, no certificacion |
| Persistencia | Contexto completo dependia del archivo local | JSON atomico mas `run_contexts` JSONB en PostgreSQL |
| Reportes | Dashboard e informe podian divergir | Generacion por API migra, persiste y resume el mismo contexto |
| UX responsive | Tablero comprimido en columnas estrechas | Una columna movil, menu horizontal compacto, sin overflow horizontal |
| Contenedores | Rebuild Python reinstalaba todas las dependencias | Capa de dependencias separada de la capa de codigo |
| PESTEL y Porter | Valores de soporte derivados de etiquetas generales; el volumen podia confundirse con intensidad | Presion estrategica desde noticias relacionadas, entity resolution, clusters, score nulo sin evidencia y confianza separada |

## PESTEL y Porter antes y despues

Los valores heredados `PESTEL 59.5`, `Porter 56.4` y `Tecnologia 80` citados en
el requerimiento no eran reconstruibles desde noticias y clusters trazables.
No se conservaron por compatibilidad visual.

Para la corrida `a9dad6033577` despues del reprocesamiento:

- noticias estrategicas relacionadas y clasificables: 0;
- clusters estrategicos: 0;
- PESTEL general: `null`, `insufficient_evidence`;
- Porter general: `null`, `insufficient_evidence`;
- confianza general PESTEL: 0;
- confianza general Porter: 0;
- razon: los registros disponibles no cumplen simultaneamente relacion fuerte,
  clasificacion de evento y umbral de corroboracion;
- resultado visual: `Informacion insuficiente`, no `0/100` ni `50/100`.

## Corrida de regresion

- ID: `a9dad6033577`
- Dominios: `puertobahia.com.co`, `odl.com.co`, `fronteraenergy.ca`, `parexresources.com`, `sostenibilidadparex.com`
- Registros brutos: 595
- Registros unicos: 593
- Evidencia directa: 22
- Hallazgos validados de nivel bajo: 2
- Hallazgos confirmados: 0
- Incidentes confirmados: 0
- CVE/KEV aplicables: 0
- Senales validadas de fraude, desinformacion o dark web accionable: 0
- Escenarios activos: 0 de 1500 plantillas preventivas

## Evidencia de validacion

- `artifacts/validation_results.json`
- `artifacts/test_results.txt`
- `artifacts/strategic_score_validation.json`
- `artifacts/strategic_news_test_results.txt`
- `artifacts/strategic_before_after.json`
- `artifacts/visual/strategic-desktop.png`
- `artifacts/visual/strategic-mobile.png`
- `artifacts/visual/report-executive-desktop.png`
- `artifacts/visual/report-technical-desktop.png`

Las limitaciones residuales estan documentadas en `docs/pending_limitations.md`.
