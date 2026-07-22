# Auditoría dashboard e informes

## Alcance

Corrida `a9dad6033577` con 5 dominios. Se inspeccionaron modelos, agregaciones, API, generador HTML, exportes y consumidores frontend.

## Causas raíz encontradas

1. `buildDashboardModel` recalculaba indicadores compartidos en TypeScript.
2. `prepare_context_for_report` y funciones auxiliares recomponían cifras durante el render.
3. El informe mostraba `15/23` como salud, mientras el dashboard mostraba `10/23`; el primer valor era cobertura consultada.
4. Radar y calor reutilizaban riesgo residual aunque la categoría tuviera `evidence_count=0`.
5. Escenarios, decisiones y referencias no tenían un contrato único exportable.

## Corrección

`DecisionIntelligenceSnapshot` se persiste con la corrida y alimenta API, dashboard, ambos HTML, JSON y CSV. Hash actual: `353dbc0a8c7cf6a0c2e088cd73380fe4d7a76aa0f116d53a0977d16d22f309e1`.

## Resultado

- Consistencia matemática: **PASS**.
- Integridad de referencias: **PASS**.
- Fuente saludable: `10/17`.
- Fuente consultada: `15/17`.
- Escenarios soportados: `1`.
