# Fórmulas de métricas de decisión

## `active_targets`

Sujeto principal declarado y dominios primarios persistidos en la corrida.

Fórmula: `count(distinct declared_subject + primary_domains)`. Unidad: `targets`. Estado sin datos: `no_data`.

## `active_domains`

Dominios primarios persistidos en la corrida; no incluye comparativos.

Fórmula: `count(distinct primary_domains)`. Unidad: `domains`. Estado sin datos: `no_data`.

## `raw_records`

Registros recibidos antes de normalizacion y deduplicacion.

Fórmula: `processing_summary.raw_records_collected`. Unidad: `records`. Estado sin datos: `no_data`.

## `unique_records`

Registros restantes despues de normalizacion, descarte y deduplicacion.

Fórmula: `raw_records - duplicates_removed - discarded_records`. Unidad: `records`. Estado sin datos: `no_data`.

## `validated_evidence`

Registros con relacion directa y validacion reproducible en la corrida.

Fórmula: `count(events where evidence_status in {validated, confirmed})`. Unidad: `evidence`. Estado sin datos: `no_data`.

## `direct_evidence`

Registros relacionados directamente con el alcance, aun pendientes de validacion tecnica.

Fórmula: `count(events where evidence_status = direct)`. Unidad: `evidence`. Estado sin datos: `no_data`.

## `validated_findings`

Condiciones de riesgo con estado validado o confirmado.

Fórmula: `count(findings where evidence_status in {validated, confirmed})`. Unidad: `findings`. Estado sin datos: `no_data`.

## `confirmed_incidents`

Hallazgos con evidencia de materializacion adversa confirmada.

Fórmula: `count(findings where incident_confirmed = true)`. Unidad: `incidents`. Estado sin datos: `no_data`.

## `healthy_sources`

Conectores elegibles que fueron consultados y finalizaron correctamente.

Fórmula: `count(source_statuses where succeeded = true)`. Unidad: `sources`. Estado sin datos: `no_data`.

## `queried_sources`

Conectores elegibles que intentaron una consulta, con exito, resultado parcial o fallo.

Fórmula: `count(source_statuses where attempted = true)`. Unidad: `sources`. Estado sin datos: `no_data`.

## `total_sources`

Conectores habilitados, configurados y aplicables al alcance de la corrida.

Fórmula: `count(source_statuses where eligible = true)`. Unidad: `sources`. Estado sin datos: `no_data`.

## `productive_sources`

Conectores consultados que aportaron al menos un registro normalizado aceptado.

Fórmula: `count(source_statuses where productive = true)`. Unidad: `sources`. Estado sin datos: `no_data`.

## `registered_sources`

Conectores presentes en el catalogo de la corrida, sin afirmar que fueron elegibles o consultados.

Fórmula: `count(source_statuses where registered = true)`. Unidad: `sources`. Estado sin datos: `no_data`.

## `max_residual_risk`

Mayor riesgo residual entre hallazgos validados; no se calcula sin hallazgos.

Fórmula: `max(validated_findings.residual_risk)`. Unidad: `risk_points`. Estado sin datos: `no_data`.

## `avg_residual_risk`

Promedio de riesgo residual entre hallazgos validados; no se calcula sin hallazgos.

Fórmula: `sum(validated_findings.residual_risk) / count(validated_findings)`. Unidad: `risk_points`. Estado sin datos: `no_data`.

## `supported_scenarios`

Escenarios deduplicados con evidencia directa o hallazgo validado en esta corrida.

Fórmula: `count(distinct supported_scenario_id)`. Unidad: `scenarios`. Estado sin datos: `no_data`.

## `pending_decisions`

Decisiones trazables que requieren actuar, validar o monitorear y que incluyen responsable y criterio de cierre.

Fórmula: `count(decision_items where status in {act_now, validate_first, monitor})`. Unidad: `decisions`. Estado sin datos: `no_data`.
