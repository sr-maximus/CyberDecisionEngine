# Plantilla de validación de rendimiento

Las mediciones se ejecutan localmente con un alcance sintético o autorizado. El
identificador de corrida, los dominios, los resultados y las características del
entorno no se publican.

| Operación | Línea base | Candidato | Criterio |
|---|---:|---:|---|
| Lectura de corrida | `<baseline-seconds>` | `<candidate-seconds>` | sin regresión material |
| Regeneración HTML/JSON/CSV | `<baseline-seconds>` | `<candidate-seconds>` | snapshot reutilizado |

La validación debe confirmar que la regeneración reutiliza el snapshot
versionado y no recalcula métricas por rutas paralelas. Los datos completos se
conservan únicamente en artefactos locales ignorados por Git.
