# Inventario real de escenarios

Fecha de corte: 2026-07-19

## Resultado

| Objeto | Cantidad | Estado |
|---|---:|---|
| Plantillas preventivas de referencia | 1.500 | Catálogo, no ejecutable |
| Definiciones con contrato `ScenarioDefinition` | 0 | Pendiente de diseño investigativo individual |
| Escenarios ejecutables | 0 | No se declara capacidad inexistente |
| Escenarios con matriz completa de pruebas | 0 | No aplica todavía |
| Posibilidades soportadas en una corrida | Variable | Se derivan solo de evidencia de esa corrida |

Las 1.500 filas de `data/scenarios/cyber_scenario_library.json` se generaron mediante combinaciones de referencias ATT&CK, D3FEND, ATLAS, DISARM y sectores. Todas tienen estado `preventive_template`, probabilidad cero y riesgo residual cero. No contienen los criterios mínimos de una regla investigativa ejecutable.

## Decisión

- La API devuelve `reference_template_count=1500` y `scenario_count=0`.
- Tablero e informes muestran las plantillas como referencia, separadas del embudo de evidencia.
- Una posibilidad de decisión puede quedar soportada por evidencia de una corrida sin afirmar que una plantilla sea un escenario ejecutable ni un incidente confirmado.
- El contrato futuro está en `cyberdeck/scenarios/models.py` y exige objetivo, hipótesis, puertas de evidencia, deduplicación, métodos versionados, condiciones de falso positivo y pruebas.

## Evidencia técnica

- Catálogo: `data/scenarios/cyber_scenario_library.json`
- Generador: `scripts/build_scenario_library.py`
- Contrato: `cyberdeck/scenarios/models.py`
- API: `cyberdeck_api/scenarios.py`
- Embudo por corrida: `cyberdeck/decision_intelligence.py`
- Pruebas: `tests/test_scenario_contract.py`, `tests/test_mitre_mapping.py`
