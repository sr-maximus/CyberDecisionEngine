# Evaluación de valor OpenCTI

## Resultado calculado

La función `assess_opencti_value()` evalúa requisitos y costos normalizados entre 0 y 1:

| Variable | Valor |
|---|---:|
| necesidad de grafo | 0.45 |
| interoperabilidad STIX | 0.55 |
| colaboración | 0.35 |
| streams | 0.30 |
| conocimiento histórico | 0.65 |
| reducción de duplicación | 0.40 |
| costo de despliegue | 0.75 |
| complejidad operativa | 0.80 |
| riesgo de duplicación | 0.70 |

Beneficio medio = `(0.45 + 0.55 + 0.35 + 0.30 + 0.65 + 0.40) / 6 = 0.45`.

Costo medio = `(0.75 + 0.80 + 0.70) / 3 = 0.75`.

Valor neto = `0.45 - 0.75 = -0.30`.

## Decisión

**Dejar opcional.** El modo seleccionado es `OPENCTI_MODE=disabled`. OpenCTI puede aportar colaboración, STIX, streams y un grafo compartido cuando exista una necesidad demostrada, pero hoy duplica parte del conocimiento interno y añade costo y complejidad.

No se recomienda por pertenecer al ecosistema CTI. Un piloto futuro debe medir interoperabilidad, reducción real de trabajo y costo operativo, sincronizando solo conocimiento validado.
