# Validacion paso a paso de las corridas vigentes

Fecha de verificacion: 2026-07-20. La historia operativa conserva solo las corridas vigentes de Grupo Aval y Frontera Energy. Frontera es el informe final mas reciente.

## 1. Alcances independientes

| Organizacion | runId | Dominios | Ventana |
|---|---|---:|---:|
| Grupo Aval | `14d2a520135c` | 7 | 365 dias |
| Frontera Energy Corporation | `6b9f929f8ce5` | 3 | 365 dias |

Los dominios comparativos no forman parte del alcance principal. El pipeline no contiene una marca predeterminada: cada contexto deriva de los datos declarados para su propia corrida.

## 2. Recoleccion y fuentes

| Corrida | Brutos | Unicos | Duplicados | Registradas | Elegibles | Consultadas | Productivas |
|---|---:|---:|---:|---:|---:|---:|---:|
| Grupo Aval | 1.469 | 1.201 | 268 | 22 | 17 | 15 | 11 |
| Frontera | 761 | 620 | 141 | 22 | 17 | 15 | 12 |

`Consultadas` significa intento real. `Productivas` significa que el conector aporto al menos un registro normalizado aceptado. Fuentes deshabilitadas o sin configurar no inflan el denominador.

## 3. Procesamiento y semantica

Para ambas corridas se comprobaron estas transiciones:

`alcance -> recoleccion -> normalizacion -> deduplicacion -> entidades -> analisis estrategico -> snapshot -> dashboard -> informe -> validacion`

- hallazgos validados: 0;
- incidentes confirmados: 0;
- riesgo residual: `N/D`, no 0;
- escenarios presentes: solo los respaldados por evidencia; las 1.500 entradas de biblioteca siguen identificadas como plantillas de referencia, no como 1.500 escenarios activos;
- fraude sin evidencia validada: `Sin senales validadas en la cobertura disponible`.

## 4. PESTEL y Porter

El motor `strategic-evidence-v1.1.0` utiliza registros corporativos, regulatorios, sectoriales, publicos y noticiosos relacionados. Separa:

- porcentaje de cobertura de evidencia;
- confianza de la evaluacion;
- presion, que solo se publica si supera las puertas de corroboracion y diversidad.

| Corrida | PESTEL | Porter | Estado agregado |
|---|---:|---:|---|
| Grupo Aval | 4,79 % | 1,24 % | Evidencia disponible; presion no publicada. |
| Frontera | 3,22 % | 0,33 % | Evidencia disponible; presion no publicada. |

En Frontera, Ambiental muestra 18,45 %, Economico 0,87 % y Rivalidad 1,63 %. Las demas dimensiones muestran `Sin evidencia suficiente`, no cero artificial.

## 5. Capturas y evidencia visual

El navegador interno intenta capturar URLs HTML publicas representativas por dominio. Conserva URL, fecha, hash, ruta, estado y causa de fallo.

Frontera sirve tres capturas verificadas en el informe tecnico:

- pagina oficial de Frontera Energy;
- pagina publica relacionada de ODL, presentada como registro para revision y no como vulnerabilidad;
- pagina oficial de Puerto Bahia.

Los intentos fallidos muestran causa explicita, como timeout, fallo TLS estricto, DNS o rechazo de conexion. No se desactivaron controles de seguridad para forzar capturas.

## 6. Fuente unica y paridad

Para cada corrida, contexto persistido, dashboard, HTML, JSON y CSV consumen el mismo `DecisionIntelligenceSnapshot`.

| Corrida | snapshotHash | Contexto = JSON | Validador |
|---|---|---|---|
| Grupo Aval | `bbef31a6299d1aa5b327b51ec1b38340657bb59e0d2af8a39cbbd53eb4235257` | Si | `approved` |
| Frontera | `1410e1c576202468e4c46030b0ab89376be3058bd1e68bdc49b7933beb67c95f` | Si | `approved` |

La marca temporal de recoleccion estrategica ahora procede de la corrida; regenerar el mismo contexto ya no cambia el hash por usar la hora del proceso de renderizado.

## 7. OpenClaw

OpenClaw esta activo en un contenedor interno, sin puerto publico, con herramientas denegadas por defecto y modo `analysis_only`. La plataforma no depende de el para recolectar, calcular o generar informes. El runtime esta listo; las funciones generativas permanecen en degradacion controlada mientras no exista un proveedor de modelo configurado y verificado.

## 8. Comprobacion reproducible

```bash
docker compose --profile osint --profile surface up -d
curl -X POST http://localhost:8080/api/runs/<runId>/report
.venv/bin/ruff check .
.venv/bin/pytest -q
```

Los informes se generan unicamente por solicitud. Volver a una vista del dashboard no repite la recoleccion ni regenera el informe.
