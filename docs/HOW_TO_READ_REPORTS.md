# Cómo leer los informes

## Ejecutivo

Empiece por alcance, fecha y cobertura operativa de conectores. Revise después afirmaciones priorizadas, confianza, qué demuestran y la decisión propuesta. Los porcentajes identifican su base; no convierta cobertura, intensidad o mapeo en cumplimiento o probabilidad de ataque.

“Sin señales validadas” significa que no se validaron señales en la cobertura disponible. No significa ausencia universal. “Ver evidencia” abre la referencia técnica sin llenar el resumen de URLs extensas.

## Técnico

Para cada afirmación revise consulta, respuesta original disponible, URL, hash, fecha, fuente, entidad, relación, validación, contradicciones y limitaciones. Confirme que el método sea reproducible y que los `evidence_ids` existan.

## Estados importantes

- Recolección autorizada: existe permiso para recolectar.
- Registro recolectado: dato normalizado; aún no es hallazgo.
- Evidencia validada: existe relación y método reproducible.
- Hallazgo validado: condición validada con evidencias enlazadas.
- Alerta: regla, umbral, responsable, acción y estado.
- Riesgo: likelihood, impacto, efectividad de controles y confianza de evidencia.
- Incidente confirmado: impacto de seguridad confirmado, ID y estado de respuesta.

El dashboard, el informe ejecutivo, el técnico, JSON y CSV se derivan del mismo `RunContext`. Las vistas cambian el nivel de detalle, no la fuente de verdad.
