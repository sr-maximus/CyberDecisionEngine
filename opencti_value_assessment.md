# OpenCTI Value Assessment

Fecha de evaluación: 2026-07-19

| Criterio | Valor |
|---|---:|
| Requisito de grafo | 0.45 |
| Interoperabilidad STIX | 0.55 |
| Colaboración | 0.35 |
| Integración por streams | 0.30 |
| Conocimiento histórico | 0.65 |
| Reducción de duplicación | 0.40 |
| Costo de despliegue | 0.75 |
| Complejidad operativa | 0.80 |
| Riesgo de duplicación | 0.70 |
| **Valor neto** | **-0.30** |

## Conclusión

**Dejar opcional.** `OPENCTI_MODE=disabled` es el valor predeterminado. La plataforma ya cubre recolección, normalización, validación, conocimiento histórico, escenarios, riesgo, dashboard e informes con almacenamiento interno. OpenCTI puede añadir colaboración CTI, interoperabilidad STIX y explotación de grafos, pero hoy su costo, complejidad y duplicación superan el valor incremental demostrado.

La conclusión se recalcula con `assess_opencti_value`; no se recomienda OpenCTI por pertenecer al ecosistema CTI. Un piloto futuro debe demostrar reducción medible de duplicación o una necesidad real de intercambio y colaboración antes de pasar a `sync_validated` o `system_of_record`.
