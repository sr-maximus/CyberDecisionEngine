# Fórmula Cyber-Porter basada en evidencia

Cyber-Porter usa el motor `strategic-evidence-v1.2.0` descrito en `pestel_formula.md`, aplicado a cinco IDs canónicos:

- `cyber_rivalry`: Rivalidad digital.
- `cyber_new_entrants`: Nuevos entrantes.
- `cyber_suppliers`: Proveedores y terceros.
- `cyber_customers`: Clientes y aliados.
- `cyber_substitutes`: Sustitución tecnológica.

La unidad de cálculo es `StrategicEventCluster`, no cada publicación. Sindicación y duplicados no multiplican linealmente el resultado. `SignalScore`, confianza, cobertura y presión validada permanecen separados.

Cada corrida incluye `MarketScope` con organización, unidad, producto/servicio, sector, subsector, geografía, competidores, proveedores, periodo, evidencia de definición y confianza. Cuando la confianza del mercado es menor de 50, las fuerzas con evidencia siguen visibles como provisionales, pero el índice agregado y `validatedPressure` quedan `null`.

No se inventan clientes, sustitutos o competidores ausentes. Una lista vacía significa que no fueron declarados ni respaldados en la corrida, no que no existan.

