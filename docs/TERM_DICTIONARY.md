# Diccionario de términos

Versión: `1.0.0`. Fuente de verdad: `config/term_registry.json`.

## Registros recolectados (`collected_records`)

**Definición:** Elementos obtenidos y normalizados desde conectores; no constituyen por sí mismos evidencia validada ni hallazgos.

**Cuándo usarlo:** cuando se satisfacen `source_id, collected_at` y el estado pertenece a `raw, normalized, related, contextual`.

**Cuándo no usarlo:** Afirmar compromiso únicamente porque existe una URL.

**Ejemplo válido:** Resultado normalizado de una consulta DNS con fuente y fecha.

**Ejemplo inválido:** Afirmar compromiso únicamente porque existe una URL.

## Evento de seguridad (`security_event`)

**Definición:** Condición de seguridad observada sobre una entidad en un momento determinado y atribuida a una fuente.

**Cuándo usarlo:** cuando se satisfacen `timestamp, security_condition, subject_entity, source` y el estado pertenece a `observed, validated, confirmed`.

**Cuándo no usarlo:** Una noticia genérica sobre ransomware sin relación con el alcance.

**Ejemplo válido:** Certificado vencido observado el 2026-07-19 para api.example.com mediante validación TLS.

**Ejemplo inválido:** Una noticia genérica sobre ransomware sin relación con el alcance.

## Evidencia directa (`direct_evidence`)

**Definición:** Registro validado que demuestra una relación directa y reproducible con una afirmación del alcance.

**Cuándo usarlo:** cuando se satisfacen `claim_id, direct_relationship, validation_method, source_id` y el estado pertenece a `validated, confirmed`.

**Cuándo no usarlo:** Coincidencia textual del nombre de una empresa en una página de terceros.

**Ejemplo válido:** Respuesta TLS reproducible que demuestra que el certificado del dominio analizado está vencido.

**Ejemplo inválido:** Coincidencia textual del nombre de una empresa en una página de terceros.

## Hallazgo validado (`validated_finding`)

**Definición:** Condición relevante respaldada por evidencia enlazada y un método de validación identificable.

**Cuándo usarlo:** cuando se satisfacen `validation_status, validation_method, validated_at, validator, evidence_ids` y el estado pertenece a `validated, confirmed`.

**Cuándo no usarlo:** Resultado de buscador marcado como crítico sin abrir ni validar.

**Ejemplo válido:** Subdominio administrativo expuesto, confirmado mediante respuesta HTTP y revisión reproducible.

**Ejemplo inválido:** Resultado de buscador marcado como crítico sin abrir ni validar.

## Confirmado (`confirmed`)

**Definición:** Estado que superó un umbral explícito de confirmación, conserva evidencia y no tiene contradicciones críticas sin resolver.

**Cuándo usarlo:** cuando se satisfacen `confirmation_threshold_passed, evidence_ids` y el estado pertenece a `confirmed`.

**Cuándo no usarlo:** Marcar confirmado porque la fuente es reconocida.

**Ejemplo válido:** Hallazgo confirmado por dos validaciones independientes sin contradicción crítica.

**Ejemplo inválido:** Marcar confirmado porque la fuente es reconocida.

## Alerta (`alert`)

**Definición:** Notificación operativa creada por una regla y umbral explícitos con responsable, acción recomendada y estado.

**Cuándo usarlo:** cuando se satisfacen `alert_rule_id, threshold, owner, recommended_action, status` y el estado pertenece a `open, acknowledged, in_progress, closed`.

**Cuándo no usarlo:** Cualquier registro recolectado mostrado como alerta.

**Ejemplo válido:** Alerta por certificado con menos de 15 días de vigencia asignada a Infraestructura.

**Ejemplo inválido:** Cualquier registro recolectado mostrado como alerta.

## Riesgo (`risk`)

**Definición:** Estimación trazable que combina plausibilidad contextual, impacto, efectividad de controles y confianza de evidencia.

**Cuándo usarlo:** cuando se satisfacen `likelihood, impact, control_effectiveness, evidence_confidence` y el estado pertenece a `calculated, reviewed, accepted, treated`.

**Cuándo no usarlo:** Llamar riesgo crítico a una URL que solo contiene el nombre de la marca.

**Ejemplo válido:** Riesgo residual calculado con entradas y supuestos visibles.

**Ejemplo inválido:** Llamar riesgo crítico a una URL que solo contiene el nombre de la marca.

## Probabilidad calibrada (`probability`)

**Definición:** Probabilidad de un resultado definido producida por un modelo calibrado y medido.

**Cuándo usarlo:** cuando se satisfacen `prediction_is_calibrated, defined_outcome, calibration_metrics, model_version` y el estado pertenece a `calibrated`.

**Cuándo no usarlo:** Porcentaje heurístico de señales presentado como probabilidad de ataque.

**Ejemplo válido:** Probabilidad a 30 días con Brier score, curva de calibración y versión del modelo.

**Ejemplo inválido:** Porcentaje heurístico de señales presentado como probabilidad de ataque.

## Comportamiento ATT&CK observado (`attack_observed`)

**Definición:** Mapeo ATT&CK respaldado por telemetría adversaria que describe un comportamiento sobre un activo y tiempo concretos.

**Cuándo usarlo:** cuando se satisfacen `adversary_telemetry, behavior, timestamp, asset, evidence_ids` y el estado pertenece a `observed, validated, confirmed`.

**Cuándo no usarlo:** Asignar ATT&CK por encontrar el nombre de una técnica en una noticia.

**Ejemplo válido:** Técnica mapeada desde telemetría autenticada de ejecución en el activo afectado.

**Ejemplo inválido:** Asignar ATT&CK por encontrar el nombre de una técnica en una noticia.

## Incidente confirmado (`confirmed_incident`)

**Definición:** Materialización confirmada de impacto de seguridad con identificador y estado de respuesta.

**Cuándo usarlo:** cuando se satisfacen `confirmed_security_impact, incident_id, response_status` y el estado pertenece a `confirmed, contained, eradicated, closed`.

**Cuándo no usarlo:** Noticia de un actor que suele atacar el sector.

**Ejemplo válido:** Incidente IR-2026-004 con impacto confirmado y respuesta en contención.

**Ejemplo inválido:** Noticia de un actor que suele atacar el sector.

## Cero observado (`observed_zero`)

**Definición:** Ausencia cuantificada únicamente cuando la consulta fue exitosa, existe denominador válido y la cobertura es adecuada.

**Cuándo usarlo:** cuando se satisfacen `value_status, successful_query, valid_denominator, adequate_coverage` y el estado pertenece a `observed_zero`.

**Cuándo no usarlo:** 0 % cuando el conector no estaba configurado.

**Ejemplo válido:** 0 de 24 endpoints consultados presentaron certificado vencido; cobertura 100 %.

**Ejemplo inválido:** 0 % cuando el conector no estaba configurado.

## Recolección autorizada (`authorized_collection`)

**Definición:** Actividad de recolección ejecutada dentro del alcance autorizado; no implica que sus resultados sean verdaderos o validados.

**Cuándo usarlo:** cuando se satisfacen `scope_id, authorization_status` y el estado pertenece a `authorized, completed, partial`.

**Cuándo no usarlo:** Usar REAL/AUTORIZADO como equivalente de hallazgo validado.

**Ejemplo válido:** Consulta pasiva autorizada sobre los dominios declarados.

**Ejemplo inválido:** Usar REAL/AUTORIZADO como equivalente de hallazgo validado.

## Evidencia validada (`validated_evidence`)

**Definición:** Registro enlazado a una afirmación y sometido a un método reproducible de validación.

**Cuándo usarlo:** cuando se satisfacen `evidence_id, claim_id, validation_method, validator` y el estado pertenece a `validated, confirmed`.

**Cuándo no usarlo:** Contenido recolectado de una fuente confiable sin validación de la afirmación.

**Ejemplo válido:** Respuesta original y hash conservados después de validación TLS.

**Ejemplo inválido:** Contenido recolectado de una fuente confiable sin validación de la afirmación.

## Mayor concentración de señales (`signal_concentration`)

**Definición:** Distribución relativa de registros relevantes por categoría; no representa por sí sola impacto ni probabilidad.

**Cuándo usarlo:** cuando se satisfacen `numerator, denominator, coverage_status` y el estado pertenece a `calculated`.

**Cuándo no usarlo:** Mayor calor significa mayor impacto confirmado.

**Ejemplo válido:** La categoría fraude concentra 12 de 40 señales relacionadas.

**Ejemplo inválido:** Mayor calor significa mayor impacto confirmado.

## Índice de exposición e inteligencia externa (`external_exposure_intelligence_index`)

**Definición:** Índice compuesto de exposición observable y calidad de inteligencia; no mide cumplimiento ni madurez interna.

**Cuándo usarlo:** cuando se satisfacen `components, coverage_status, model_version` y el estado pertenece a `calculated, not_calculated`.

**Cuándo no usarlo:** Cyber Posture Index presentado como cumplimiento.

**Ejemplo válido:** Índice 62/100 con componentes y cobertura publicados.

**Ejemplo inválido:** Cyber Posture Index presentado como cumplimiento.

## Índice de presión de señales (`signal_pressure_index`)

**Definición:** Índice heurístico de presión relativa construido desde señales ponderadas; no es una probabilidad de ataque.

**Cuándo usarlo:** cuando se satisfacen `model_version, calibrated, inputs` y el estado pertenece a `calculated, not_calculated`.

**Cuándo no usarlo:** 43 % de probabilidad de ciberataque sin calibración.

**Ejemplo válido:** Índice 0,43 a 30 días, explícitamente no calibrado.

**Ejemplo inválido:** 43 % de probabilidad de ciberataque sin calibración.

## Estado de escenarios (`scenario_status`)

**Definición:** Clasificación del grado de soporte de un escenario dentro de candidate, supported, validated o materialized.

**Cuándo usarlo:** cuando se satisfacen `scenario_id, scenario_status, evidence_ids` y el estado pertenece a `candidate, supported, validated, materialized`.

**Cuándo no usarlo:** Escenario activo sin definir el umbral de soporte.

**Ejemplo válido:** Escenario supported por dos evidencias independientes.

**Ejemplo inválido:** Escenario activo sin definir el umbral de soporte.

## Cobertura de mapeo de controles (`control_mapping_coverage`)

**Definición:** Porcentaje de hallazgos elegibles que pudieron mapearse a controles; no representa cumplimiento.

**Cuándo usarlo:** cuando se satisfacen `mapped_items, eligible_items, framework_version` y el estado pertenece a `calculated, not_calculated`.

**Cuándo no usarlo:** 75 % de cumplimiento NIST derivado solo del mapeo.

**Ejemplo válido:** 18 de 24 hallazgos elegibles mapeados a NIST CSF 2.0.

**Ejemplo inválido:** 75 % de cumplimiento NIST derivado solo del mapeo.

## Cobertura operativa de conectores (`connector_operational_coverage`)

**Definición:** Relación entre conectores consultados con éxito y conectores aplicables al alcance.

**Cuándo usarlo:** cuando se satisfacen `successful_connectors, applicable_connectors` y el estado pertenece a `complete, partial, limited, not_applicable`.

**Cuándo no usarlo:** Una fuente saludable significa que toda afirmación es verdadera.

**Ejemplo válido:** 10 de 14 conectores aplicables respondieron correctamente.

**Ejemplo inválido:** Una fuente saludable significa que toda afirmación es verdadera.

## Sin señales de fraude validadas en la cobertura disponible (`no_validated_fraud_signals`)

**Definición:** Estado cualitativo usado cuando no existen señales validadas, sin inferir ausencia total de fraude.

**Cuándo usarlo:** cuando se satisfacen `coverage_status` y el estado pertenece a `no_validated_signal`.

**Cuándo no usarlo:** Presión de fraude 0 % con conectores parciales.

**Ejemplo válido:** No se validaron señales de fraude en las fuentes consultadas.

**Ejemplo inválido:** Presión de fraude 0 % con conectores parciales.

## Sin impacto reputacional validado (`no_validated_reputational_impact`)

**Definición:** Estado que indica que no se validó impacto reputacional; no equivale a impacto nulo.

**Cuándo usarlo:** cuando se satisfacen `coverage_status` y el estado pertenece a `not_validated`.

**Cuándo no usarlo:** Impacto reputacional 0 % cuando no hubo datos.

**Ejemplo válido:** No existe impacto reputacional validado en esta corrida.

**Ejemplo inválido:** Impacto reputacional 0 % cuando no hubo datos.
