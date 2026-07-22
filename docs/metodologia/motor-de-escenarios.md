# Motor de escenarios investigativos

## Cadena de activación

`objetivo -> observable -> evidencia -> normalización -> condición -> corroboración -> hipótesis -> evaluación -> hallazgo`

Una definición activa debe cumplir el contrato `ScenarioDefinition`. Las plantillas preventivas no lo cumplen y permanecen como referencias.

## Reglas matemáticas

- La confianza depende de calidad, independencia, actualidad, relación y corroboración de evidencia.
- El impacto se calcula por separado de la confianza.
- El riesgo no se obtiene por conteo bruto de coincidencias.
- Duplicados por URL canónica y hash de contenido no incrementan soporte.
- Varias páginas del mismo dominio no cuentan automáticamente como fuentes independientes.
- La ausencia de datos produce `no_data` o evidencia insuficiente; nunca evidencia negativa automática.
- Los indicadores negativos y contradicciones pueden reducir el soporte o invalidar la hipótesis.

## Estados

- `candidate`: hipótesis construida, evidencia insuficiente.
- `supported`: supera puertas de evidencia e independencia.
- `validated`: revisión explícita con método y responsable.
- `confirmed`: umbral de confirmación superado sin contradicción crítica abierta.
- `discarded`: contradicción o falso positivo demostrado.

## Transparencia

Cada salida debe exponer evidencia usada, contradicciones, contribuciones, limitaciones, método y versión. El número de plantillas de referencia nunca se presenta como cantidad de escenarios ejecutables.
