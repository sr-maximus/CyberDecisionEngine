# Ejecuciones independientes: Grupo Aval y Frontera Energy

Fecha de verificacion: 2026-07-20. Recoleccion publica, defensiva y autorizada. Los informes se generaron por solicitud despues de completar cada corrida.

## Flujo verificado

1. Se comprobo la salud de API, PostgreSQL, web, recolectores, superficie, Tor y OpenClaw.
2. Cada organizacion se proceso con alcance, `runId`, contexto, evidencias y reporte independientes.
3. La API ejecuto recoleccion, normalizacion, deduplicacion, analisis estrategico y snapshot.
4. Los informes se solicitaron despues de finalizar la recoleccion.
5. El validador comprobo paridad entre contexto, HTML ejecutivo, HTML tecnico, JSON y CSV.
6. Ningun registro se elevo a hallazgo, riesgo o incidente sin cumplir sus requisitos semanticos.

## Grupo Aval

- `runId`: `14d2a520135c`.
- alcance: Grupo Aval y siete dominios primarios declarados y verificados en el alcance.
- dominios: `grupoaval.com`, `bancodebogota.com`, `bancodeoccidente.com.co`, `bancopopular.com.co`, `avvillas.com.co`, `porvenir.com.co` y `corficolombiana.com`.
- ventana: 365 dias; modo profundo; Tor autorizado.
- registros brutos/unicos/duplicados: 1.469 / 1.201 / 268.
- ciclo de fuentes: 22 registradas, 17 elegibles, 15 consultadas y 11 productivas.
- hallazgos validados/incidentes confirmados: 0 / 0; riesgo residual: `N/D`.
- PESTEL: 11 clusters; cobertura de evidencia 4,79 %; presion agregada no publicada por corroboracion o confianza insuficiente.
- Porter: 11 clusters; cobertura de evidencia 1,24 %; presion agregada no publicada por corroboracion o confianza insuficiente.
- capturas servidas en el informe tecnico: 11 imagenes unicas verificadas.
- modelo estrategico: `strategic-evidence-v1.1.0`.
- `snapshotHash`: `bbef31a6299d1aa5b327b51ec1b38340657bb59e0d2af8a39cbbd53eb4235257`.
- validador: `approved`; informe final.

Informes:

- ejecutivo: `reports/web/14d2a520135c-grupoaval-com-bancodebogota-com-bancodeoccidente-com-co.html`;
- tecnico: `reports/web/14d2a520135c-grupoaval-com-bancodebogota-com-bancodeoccidente-com-co-technical.html`.

## Frontera Energy Corporation

- `runId`: `6b9f929f8ce5`.
- alcance: Frontera Energy Corporation, Puerto Bahia y Oleoducto de los Llanos.
- dominios: `fronteraenergy.ca`, `puertobahia.com.co` y `odl.com.co`.
- ventana: 365 dias; modo profundo; Tor autorizado.
- registros brutos/unicos/duplicados: 761 / 620 / 141.
- ciclo de fuentes: 22 registradas, 17 elegibles, 15 consultadas y 12 productivas.
- hallazgos validados/incidentes confirmados: 0 / 0; riesgo residual: `N/D`.
- PESTEL: 6 clusters; cobertura de evidencia 3,22 %. Ambiental registra 18,45 % de cobertura y Economico 0,87 %.
- Porter: 6 clusters; cobertura de evidencia 0,33 %. Rivalidad registra 1,63 % de cobertura.
- capturas servidas en el informe tecnico: 3 imagenes unicas verificadas; los demas intentos conservan su causa de fallo sin evadir TLS, DNS, login o timeout.
- modelo estrategico: `strategic-evidence-v1.1.0`.
- `snapshotHash`: `1410e1c576202468e4c46030b0ab89376be3058bd1e68bdc49b7933beb67c95f`.
- validador: `approved`; informe final y mas reciente.

Informes:

- ejecutivo: `reports/web/6b9f929f8ce5-fronteraenergy-ca-puertobahia-com-co-odl-com-co.html`;
- tecnico: `reports/web/6b9f929f8ce5-fronteraenergy-ca-puertobahia-com-co-odl-com-co-technical.html`.

## Interpretacion

Los conteos demuestran cobertura de recoleccion y paridad de productos; no demuestran compromiso. PESTEL y Porter muestran aspectos y porcentajes de cobertura cuando existe evidencia, pero no publican una presion agregada si faltan diversidad, corroboracion o confianza. Esta regla evita sustituir datos faltantes por cero o por una precision aparente.

## Verificacion final del modelo estrategico v1.2.0

Las ejecuciones anteriores `14d2a520135c` y `6b9f929f8ce5` se conservaron como linea base. En ellas existian evidencias por dimension, pero el modelo multiplicativo dejaba todos los scores estrategicos en `N/D`. Las siguientes corridas son nuevas, aisladas y utilizan la misma evidencia como unica fuente de verdad para dashboard, HTML, JSON y CSV.

### Grupo Aval — corrida nueva

- `runId`: `4c39f9089b25`.
- duracion de recoleccion y analisis: aproximadamente 31 minutos.
- registros brutos/unicos/duplicados: 1.148 / 883 / 265.
- fuentes elegibles/consultadas/productivas: 17 / 15 / 11.
- PESTEL `SignalScore`: 71,01; confianza 33,88; cobertura de evidencia 30,59 %.
- dimensiones PESTEL con señal: economia digital 89,87; tecnologia y superficie 39,71; resiliencia y continuidad 83,45.
- Porter `SignalScore`: 80,77; confianza 14,37; cobertura 14,08 %; rivalidad digital 80,77.
- presion validada: `N/D`; no se publicaron riesgo, hallazgo validado ni incidente sin evidencia suficiente.
- narrativas: 0 despues de exigir relacion explicita con el sujeto; no se presentaron resultados genericos de consultas como afirmaciones.
- capturas HTML tecnico: 28 referencias, 12 archivos unicos persistidos.
- `snapshotHash`: `b49a4e368b6e3de28fec2cb8f961251ead6525b3ec46e897642ef1b0b69a1f8c`.
- validador: `approved`, 883 registros en contexto/JSON/CSV y 11 dimensiones estrategicas coherentes.

Informes:

- ejecutivo: `reports/web/4c39f9089b25-grupoaval-com-bancodebogota-com-bancodeoccidente-com-co.html`;
- tecnico: `reports/web/4c39f9089b25-grupoaval-com-bancodebogota-com-bancodeoccidente-com-co-technical.html`.

### Frontera Energy Corporation — corrida nueva

- `runId`: `4b6268e34890`.
- duracion de recoleccion y analisis: aproximadamente 11 minutos.
- registros brutos/unicos/duplicados: 761 / 620 / 141.
- fuentes elegibles/consultadas/productivas: 17 / 15 / 12.
- PESTEL `SignalScore`: 60,17; confianza 21,14; cobertura de evidencia 15,79 %.
- dimensiones PESTEL con señal: economia digital 40,54; resiliencia y continuidad 79,79.
- Porter `SignalScore`: 47,31; confianza 11,29; cobertura 6,09 %; rivalidad digital 47,31.
- presion validada: `N/D`; no se publicaron riesgo, hallazgo validado ni incidente sin evidencia suficiente.
- narrativas: 0. Se descarto una oferta laboral ajena que aparecio en una consulta asociada; la consulta por si sola ya no prueba relacion con el sujeto.
- capturas HTML tecnico: 2 referencias, 1 archivo unico persistido, ampliable y servido con HTTP 200.
- `snapshotHash`: `c6d98ef3b903ea528e9854130b1690b33303fa929a096a78f84e451da552f129`.
- validador: `approved`, 620 registros en contexto/JSON/CSV y 11 dimensiones estrategicas coherentes.

Informes:

- ejecutivo: `reports/web/4b6268e34890-fronteraenergy-ca-puertobahia-com-co-odl-com-co.html`;
- tecnico: `reports/web/4b6268e34890-fronteraenergy-ca-puertobahia-com-co-odl-com-co-technical.html`.

### OpenClaw

El gateway esta saludable y aislado en modo `analysis_only`. El paquete estrategico usa `CDE-AI-STRATEGIC-2026.07-V2`, conserva roles especializados y aplica seleccion determinista: 26 de 40 eventos solicitados, 11.894 tokens de entrada sobre un presupuesto de 12.000. El modelo configurado permanece `configured_unverified`; por tanto, la plataforma genera el paquete trazable, pero no presenta una inferencia externa como ejecutada hasta verificar proveedor/modelo y aprobarla.
