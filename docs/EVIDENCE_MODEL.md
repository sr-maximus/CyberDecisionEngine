# Modelo de evidencia

## Objetos

`Evidence` conserva identificador, fuente, tipo, fechas de recolección y observación, URL canónica, hash, referencia original, consulta y respuesta cuando el conector las conserva, relación, estado, confianza, método, validador, TLP y PAP.

`Claim` conserva la afirmación, entidades, alcance, tipo, estado, confianza, evidencias favorables y contradictorias, fechas y limitaciones. Una afirmación validada exige método, fecha, validador y `evidence_ids`. Una afirmación confirmada exige además superar el umbral y no tener contradicciones críticas sin resolver.

`ClaimEvidenceLink` evita inferir soporte por proximidad textual. `ContradictingEvidence` registra la prueba que debilita una afirmación y su resolución. `Interpretation` separa observación de significado. `Decision` conserva responsable, acción y criterio de cierre.

## Presentación

Cada hallazgo debe responder: qué se encontró, qué demuestra, qué no demuestra, cómo se validó, cuáles evidencias lo soportan, confianza, limitaciones, decisión, responsable y cierre.

El informe ejecutivo usa referencias compactas y enlaces “Ver evidencia”. El informe técnico expone los campos reproducibles. Cuando una consulta o respuesta no fue conservada, muestra “No conservada por el conector”; nunca rellena el vacío con texto inventado.

## Integridad

El `content_hash` permite detectar alteración y duplicados. TLP/PAP gobiernan difusión. La fuente no se confunde con la afirmación: autenticidad de origen, relación con alcance y validación del contenido son controles independientes.
