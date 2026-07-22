# Matriz de consistencia

| Regla | Fuente de verdad | Comportamiento exigido | Prueba automática |
|---|---|---|---|
| Registros no son amenazas | `ThreatEvent.record_kind` y `evidence_status` | `raw/contextual/potential/related` no generan hallazgo | `test_evidence_pipeline.py` |
| Subdominio no es vulnerabilidad | categoría, tags y validación técnica | DNS inventario permanece `observed_asset` | `test_evidence_pipeline.py` |
| CVE requiere aplicabilidad | activo, producto, versión y tags explícitos | sin versión queda `cve_candidate` | `test_evidence_pipeline.py` |
| KEV no crea aplicabilidad | `vulnerability_status` | solo prioriza CVE aplicable | `test_evidence_pipeline.py` |
| ATT&CK requiere conducta | técnica exacta y `attack_mapping_status` | solo `observed_adversary_behavior` activa | `test_scenario_activation.py` |
| D3FEND no activa por sí solo | mapping defensivo | se muestra como opción de control | `test_scenario_activation.py` |
| ATLAS requiere evidencia IA | ID explícito, señal IA y confianza | genérico o baja confianza queda preventivo | `test_scenario_activation.py` |
| DISARM requiere corroboración | ID explícito y diversidad de fuentes | dos evidencias y dos fuentes independientes | `test_scenario_activation.py` |
| Sin desinformación no hay DISARM activo | evidencia asegurada | biblioteca preventiva separada | `test_historical_run_regression.py` |
| Sin dark web accionable no se afirma exposición | cobertura y estado de evidencia | se muestra fuente/limitación, no hallazgo | `test_historical_run_regression.py` |
| Fuente vacía no significa riesgo cero | `SourceStatus.no_data` | estado visible, sin evidencia inventada | `test_pipeline_integration.py` |
| Timeout no crea hallazgo | `SourceStatus.timed_out` | limita cobertura y salud | `test_pipeline_integration.py` |
| Sector declarado no eleva riesgo | tags de targeting sectorial | solo evidencia explícita activa `S` | `test_evidence_pipeline.py` |
| Hallazgo validado no es incidente | `incident_confirmed` | contadores independientes | `test_historical_run_regression.py` |
| Predicción no calibrada | `prediction_is_calibrated=false` | UI usa índice de presión, no probabilidad | `test_historical_run_regression.py` |
| Cumplimiento no inferido | `control_assessment` | mapeo externo, no auditoría | `test_historical_run_regression.py` |
| Duplicados no inflan conteos | `canonical_id` | fusiona fuentes y aumenta `duplicate_count` | `test_evidence_pipeline.py`, `test_pipeline_integration.py` |
| Riesgo bajo no crea plan crítico | riesgo residual y evidencia | plan derivado solo de hallazgos/escenarios soportados | `test_historical_run_regression.py` |
| Dashboard, informe y exporte comparten contexto | `RunContext` persistido | misma taxonomía y conteos | `test_persistence.py`, `test_report_generation.py` |

## Invariantes del fixture histórico

```text
595 registros crudos
593 registros únicos
2 hallazgos técnicos validados de riesgo bajo
0 incidentes confirmados
0 CVE aplicables o confirmadas
0 KEV aplicables
0 fraude confirmado
0 desinformación confirmada
0 dark web accionable demostrado
0 escenarios multi-framework activados
```
