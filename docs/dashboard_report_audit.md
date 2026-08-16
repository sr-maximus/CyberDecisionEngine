# Auditoría dashboard e informes

## Alcance

Se inspeccionan modelos, agregaciones, API, generador HTML, exportes y
consumidores frontend usando una corrida sintética o autorizada. El identificador
de corrida, los dominios y el snapshot permanecen en el entorno local.

## Causas raíz encontradas

1. `buildDashboardModel` recalculaba indicadores compartidos en TypeScript.
2. `prepare_context_for_report` y funciones auxiliares recomponían cifras durante el render.
3. El informe y el dashboard podían interpretar de forma distinta la salud y la
   cobertura consultada de las fuentes.
4. Radar y calor reutilizaban riesgo residual aunque la categoría tuviera `evidence_count=0`.
5. Escenarios, decisiones y referencias no tenían un contrato único exportable.

## Corrección

`DecisionIntelligenceSnapshot` se persiste con la corrida y alimenta API,
dashboard, ambos HTML, JSON y CSV. El hash se registra solo en el artefacto local
de validación.

## Resultado

- Consistencia matemática: `<pass-or-fail>`.
- Integridad de referencias: `<pass-or-fail>`.
- Fuentes saludables: `<healthy>/<eligible>`.
- Fuentes consultadas: `<queried>/<eligible>`.
- Escenarios soportados: `<supported-scenarios>`.

Los valores reales, nombres de organizaciones, dominios, cuentas y resultados no
se incorporan al repositorio público.
