# Matriz de referencias y frameworks

**Corte de verificación:** 2026-07-26. Las versiones dinámicas se verificaron contra fuentes oficiales cuando fue posible. Los análisis históricos conservan la versión registrada en su snapshot.

| Referencia | Versión | Módulo | Uso real | Evidencia en código/datos | Necesaria | Decisión | Justificación |
|---|---|---|---|---|---|---|---|
| MITRE ATT&CK Enterprise | 19.1 | escenarios, mapping, dashboard, informe | clasificación de técnicas y actores; no prueba observación por sí sola | `mitre_mapping.py`, STIX local | sí | conservar actualizada | versión oficial vigente 2026-04-28 |
| MITRE D3FEND | ontología 1.4.0 | mapping defensivo | relación de técnicas defensivas; no mide eficacia de control | `mitre_mapping.py`, JSON oficial | sí | conservar actualizada | versión oficial 2026-03-31 |
| MITRE ATLAS | datos 5.6.0 | riesgo de IA | clasificación solo ante señales explícitas de IA | `build_atlas_profile` | condicional | conservar | evita mapear ATLAS por palabras ambiguas |
| MITRE Fight Fraud Framework (F3) | 1.1 | marca y fraude, escenarios, mapping, dashboard e informes | clasifica conductas antifraude mediante técnicas y tácticas oficiales solo sobre registros asegurados y reglas explícitas | `f3.py`, `f3_mapping.py`, JSON oficial local | sí | incorporar y versionar | complementa ATT&CK para fraude; un mapeo compatible no confirma fraude ni incidente |
| DISARM | catálogo sincronizado | desinformación | taxonomía de tácticas/técnicas sobre registros compatibles | `disinformation.py` | sí | conservar y versionar | complementa ATT&CK; no es score de riesgo |
| NIST CSF | 2.0 / CSWP 29 | control mapping, gobierno | resultados de cobertura de mapeo | configuración e informe | sí | conservar | lenguaje ejecutivo y de gobierno |
| NIST SP 800-30 | Rev. 1 | metodología de riesgo | referencia conceptual de probabilidad, impacto y riesgo | `REFERENCES`, docs de cálculo | sí | conservar | no se presenta como certificación |
| NIST SP 800-61 | Rev. 3 disponible | respuesta | guía conceptual; uso analítico limitado | referencias/documentación | opcional | actualizar en documentación | no participa en score actual |
| NIST SP 800-53 | Rev. 5 update 1 | controles | referencia complementaria | informe | opcional | conservar | catálogo, no evaluación de cumplimiento |
| ISO/IEC 27001 | 2022 | mapping de controles | resumen no propietario de áreas afectadas | `frameworks.yml`, dashboard | sí | conservar | no copiar texto normativo licenciado |
| ISO/IEC 27002 | 2022 | guía de controles | referencia conceptual | documentación | opcional | consolidar con ISO 27001 | evita duplicar porcentajes |
| ISO/IEC 27005 | 2022 | riesgo | referencia metodológica | documentación | opcional | conservar como guía | no reemplaza la fórmula versionada |
| PCI DSS | 4.0.1 | mapping sector pagos | mapeo cuando existen señales de pagos | dashboard/modelo | condicional | conservar | no mostrar cumplimiento porcentual |
| SOC 2 TSC | TSC vigente, sin contenido propietario | mapping | categorías Security, Availability, Processing Integrity, Confidentiality, Privacy | `frameworks.yml` | condicional | conservar | cobertura de mapeo, no atestación |
| GDPR | Reglamento (UE) 2016/679 | privacidad | identifica aspectos de datos personales | dashboard/modelo | condicional | conservar | no emitir conclusión jurídica automática |
| CIS Controls | v8.1 | control mapping | inventario, hardening, acceso, logging y respuesta | dashboard/modelo | sí | conservar | referencia práctica de control |
| COBIT | 2019 | gobierno | mapeo de gobierno, ownership y assurance | dashboard/modelo | condicional | conservar | no calcular madurez sin evaluación |
| CVE | esquema actual NVD/MITRE | vulnerabilidades | identificador de vulnerabilidad | colectores/modelos | sí | conservar | requiere aplicabilidad de producto/versión |
| CVSS | 3.x/4.0 según fuente | vulnerabilidades | severidad técnica reportada por fuente | NVD, eventos | sí | conservar dato fuente | no equivale a riesgo organizacional |
| FIRST EPSS | modelo vigente de la fuente | vulnerabilidades | probabilidad publicada de explotación de CVE | colector EPSS | sí | conservar con fecha | no extrapolar a ataque contra la organización |
| CISA KEV | catálogo dinámico | priorización | marca explotación conocida de CVE | colector KEV | sí | conservar | fuerte señal de priorización, no de exposición |
| CWE | catálogo dinámico | debilidades | referencia cuando llega de fuentes | D3FEND/NVD | opcional | conservar | no inventar CWE ausente |
| CAPEC | catálogo dinámico | patrones | referencia conceptual | documentación | opcional | dejar opcional | no hay motor activo dedicado |
| STIX/TAXII | OASIS 2.1 | interoperabilidad | entrada CTI y backend opcional | colector TAXII, conocimiento | sí | conservar | OpenCTI no es requisito |
| TLP | TLP 2.0 | manejo de evidencia | metadato de distribución | claim-evidence | sí | conservar | valor por defecto TLP:CLEAR debe ser explícito |
| PAP | taxonomía MISP | acciones permisibles | metadato de uso | claim-evidence | sí | conservar | evita reutilización indebida |
| Admiralty Code | conceptual | confiabilidad | no se encontró implementación completa | docs/modelo de fuentes | opcional | roadmap | no mostrarlo hasta implementar doble dimensión |
| Diamond Model | conceptual | análisis CTI | no se encontró modelo operativo completo | documentación | opcional | dejar conceptual | no decorar dashboard |
| Cyber Kill Chain | conceptual | secuenciación | uso mínimo | documentación | opcional | consolidar con ATT&CK | evita duplicidad de narrativa |
| FAIR | conceptual | riesgo financiero | no existe calibración financiera suficiente | documentación | no actual | no publicar score FAIR | faltan distribuciones de pérdida |
| PESTEL | modelo propio trazable 1.x | contexto estratégico | clusters de noticias, cobertura y confianza; publicación condicionada | `strategic_news._score_model` | sí | conservar | no es riesgo ni probabilidad |
| Porter | modelo propio trazable 1.x | contexto competitivo | mismo motor de clusters con dimensiones Porter | `strategic_news._score_model` | sí | conservar | no es score de madurez |
| Matriz 4x4 | residual risk 2.0.0 | riesgo | índices discretos de likelihood e impact | `risk_engine.matrix_4x4` | sí | conservar | mostrar entradas y limitaciones |
| Escenarios propios | biblioteca versionada | decisión | candidatos deduplicados con evidencia | `decision_intelligence.py` | sí | conservar | nunca materializar sin evidencia |

## Referencias decorativas o no invocadas

`pestel_cyber_index`, `porter_cyber_index` y `digital_proximity` existen como funciones heredadas sin llamadas productivas detectadas por el grafo. No deben presentarse como cálculos activos. El dashboard y los informes deben describir el modelo de clusters realmente usado y registrar su versión.

## Reglas de presentación

- ATT&CK observado exige telemetría de comportamiento, activo, timestamp y evidencia.
- F3 mapeado describe compatibilidad conductual sobre evidencia asegurada; no equivale a fraude confirmado ni genera porcentajes de pérdida.
- Un mapeo de control indica cobertura de mapeo, no cumplimiento ni madurez.
- CVE + CVSS no demuestra aplicabilidad sin producto y versión confirmados.
- EPSS es un dato externo calibrado para CVE, no una probabilidad de ataque organizacional.
- PESTEL y Porter describen presión contextual; no sustituyen el riesgo técnico.

## Fuentes oficiales verificadas

- MITRE ATT&CK Version History: https://attack.mitre.org/resources/versions/
- MITRE D3FEND Version Information: https://d3fend.mitre.org/version/
- MITRE ATLAS data releases: https://github.com/mitre-atlas/atlas-data/releases
- MITRE Fight Fraud Framework: https://ctid.mitre.org/fraud
- MITRE Fight Fraud Framework source: https://github.com/center-for-threat-informed-defense/fight-fraud-framework
- NIST CSF 2.0: https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20
