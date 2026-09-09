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

## Biblioteca versionada

La versión actual contiene 1.138 referencias preventivas:

- 1.116 registros derivados de ATT&CK, D3FEND, ATLAS, DISARM y F3;
- 22 plantillas propias multidominio para IT, IoT, IIoT, OT y fraude.

Las 22 plantillas cubren presencia tecnológica pública, administración remota,
advisories, CVE aplicables, KEV, obsolescencia, terceros, transiciones entre
dominios, campañas ICS, EMB3D, BMS/CCTV/control de acceso, pérdida de
vista/control, suplantación de marca, dominios o aplicaciones falsas, BEC,
empleo falso, mulas, deepfake, canales conectados y monetización.

## Puertas multidominio

- La clasificación tecnológica puede partir de una mención, pero la atribución
  al sujeto requiere relación explícita.
- `observed_public` exige evidencia directa o validada.
- `corroborated_public` exige dos referencias independientes.
- Una CVE aplicable exige producto y versión o CPE.
- Una transición IT-IoT-OT exige una entidad observada compartida; la
  coocurrencia textual no crea una arista.
- Los mappings son referencias preventivas hasta que una regla y evidencia los
  soporten.
- Sin evidencia de controles, el riesgo residual queda
  `insufficient_control_evidence`.

Los filtros tecnológicos y analíticos producen una proyección del snapshot. No
recalculan la evidencia original ni cambian estados históricos.
