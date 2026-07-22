# Resultados de rendimiento

Medición local con Docker, corrida `a9dad6033577` y snapshot persistido.

| Operación | Línea base | Final |
|---|---:|---:|
| GET de corrida | 0.046177 s | 0.042016 s |
| Regeneración HTML/JSON/CSV | 3.207968 s | 2.725074 s |

La regeneración final reutiliza el snapshot versionado; no recalcula métricas por rutas paralelas.
