# Modelo semántico

CyberDecisionEngine separa permiso, recolección, prueba, interpretación y decisión. Una fuente auténtica demuestra procedencia; no vuelve verdadera una afirmación. Una recolección autorizada demuestra alcance permitido; no vuelve validado el registro.

## Cadena de trazabilidad

`afirmación -> evidencia -> interpretación -> limitación -> decisión -> cierre`

- **Afirmación:** proposición verificable sobre una entidad y un alcance.
- **Evidencia:** registro enlazado a la afirmación mediante una relación explícita y un método de validación.
- **Interpretación:** declara qué demuestra y qué no demuestra la evidencia.
- **Limitación:** cobertura ausente, contradicción, incertidumbre o restricción de fuente.
- **Decisión:** posibilidad de tratamiento, responsable y acción recomendada.
- **Cierre:** criterio reproducible para validar, mitigar o descartar.

## Estados

Los registros pueden ser brutos, contextuales, relacionados, directos, validados, confirmados, falsos positivos o descartados. Los escenarios se mantienen separados como candidatos, respaldados, validados o materializados. `no_data`, cero observado y cero calculado son estados diferentes.

## Reglas

Las reglas viven en `config/term_registry.json` y se ejecutan con `TermRegistry.validate`. Dashboard e informes consumen etiquetas generadas desde ese registro. Los modelos `Claim`, `Evidence`, `ClaimEvidenceLink`, `ContradictingEvidence`, `Interpretation` y `Decision` aplican las restricciones estructurales.

Una coincidencia de texto o dominio puede establecer relación con el alcance, pero no evidencia directa. ATT&CK solo se presenta como observado cuando existe telemetría adversaria, comportamiento, fecha, activo y evidencia enlazada. “Probabilidad” solo se usa para un resultado definido y un modelo calibrado; en los demás casos se usa “índice de presión de señales”.
