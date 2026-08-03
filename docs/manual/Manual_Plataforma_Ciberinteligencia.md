# Manual de CyberDecisionEngine

| Campo | Valor |
|---|---|
| Plataforma | CyberDecisionEngine |
| Versión de aplicación | 0.1.0 |
| Versión del manual | 1.1.0 |
| Fecha | 2026-07-20 |
| Clasificación | Uso interno / información pública autorizada |
| Creador conceptual | Edwin Peñuela, modelo desarrollado desde 2022 |

## 1. Introducción

CyberDecisionEngine transforma registros públicos y autorizados en evidencia normalizada, relaciones, hallazgos, escenarios y posibilidades de decisión. Está orientada a dirección, CISO, riesgo, fraude, SOC, infraestructura, legal y analistas de inteligencia.

La plataforma diferencia:

- **recolección:** obtención de registros desde una fuente;
- **procesamiento:** normalización, canonicalización, deduplicación y clasificación;
- **análisis:** evaluación reproducible de relaciones, riesgo y contexto;
- **inteligencia:** interpretación trazable que soporta una decisión;
- **informe:** representación ejecutiva o técnica de un snapshot persistido.

No explota vulnerabilidades, no autentica contra terceros, no realiza fuerza bruta y no convierte una mención en incidente.

## 2. Objetivo

La plataforma responde:

1. qué alcance fue analizado;
2. qué fuentes fueron consultadas y con qué resultado;
3. qué registros únicos fueron recolectados;
4. qué afirmaciones tienen evidencia;
5. qué escenarios son candidatos o están respaldados;
6. qué riesgo externo puede justificarse;
7. qué información falta;
8. qué posibilidades de tratamiento deben evaluarse.

No sustituye una auditoría interna, un pentest, un peritaje, una certificación, una evaluación legal ni la respuesta a incidentes.

## 3. Casos de uso

- evaluación pública de una organización o dominio autorizado;
- monitoreo periódico o 24/7 con alertas internas;
- OSINT de dominios, marca, noticias, advisories y documentos públicos;
- SOCMINT basado en contenido público indexado y atribuible;
- superficie externa defensiva: DNS, certificados, WHOIS, subdominios y tecnologías;
- inteligencia de vulnerabilidades con control de aplicabilidad;
- fraude y suplantación de marca;
- desinformación y mapeo DISARM;
- contexto estratégico PESTEL/Porter;
- escenarios ATT&CK, D3FEND, ATLAS y DISARM;
- informe ejecutivo y técnico bajo solicitud del usuario;
- análisis separado de riesgo virtual de empleados con consentimiento.

## 4. Arquitectura

```mermaid
flowchart LR
    U["Usuario web"] --> W["React + Nginx"]
    W --> A["FastAPI"]
    A --> R["RunStore y workers"]
    R --> C["Recolectores públicos"]
    R --> S1["OSINT tools"]
    R --> S2["Superficie externa"]
    R --> S3["SpiderFoot pasivo"]
    R --> T["Tor SOCKS opcional"]
    R --> P["Normalización y deduplicación"]
    P --> M["Análisis, riesgo y escenarios"]
    M --> AI["OpenClaw aislado: borradores y revisión"]
    M --> K["Backend interno de conocimiento"]
    K -. "opcional" .-> O["OpenCTI"]
    M --> DB[("PostgreSQL")]
    M --> F["Contexto por runId"]
    F --> D["Dashboard"]
    F --> G["Generador de informes"]
    G --> V["Validador HTML + JSON + CSV"]
```

### Contenedores

| Servicio | Función | Exposición |
|---|---|---|
| `web` | interfaz y reportes | host 8080 |
| `api` | API y motor | host 8000 |
| `postgres` | datos persistentes | host 15432 para administración local |
| `osint-tools` | búsquedas auxiliares autorizadas | solo red interna |
| `kali-surface` | superficie defensiva | solo red interna |
| `spiderfoot` | recolección pasiva | solo red interna |
| `tor-proxy` | proxy SOCKS opcional | solo red interna |
| `openclaw-gateway` | orquestación de IA controlada | solo red interna, sin puerto host |

### Fuente de verdad

Cada ejecución produce un `RunContext` persistido bajo `data/web_runs/<runId>/context.json` y replicado en PostgreSQL. Dashboard, informe ejecutivo, informe técnico, JSON y CSV se derivan del mismo `DecisionIntelligenceSnapshot`.

## 5. Despliegue y operación

La topología soportada usa Docker Compose, PostgreSQL y servicios internos sin exponer sidecars de recolección al host. El manual funcional no depende de una ruta local ni de un sistema operativo específico.

Los prerrequisitos, variables, arranque, migraciones, respaldo, restauración, actualización, observabilidad y comandos reproducibles están separados en `docs/operacion/Guia_Despliegue_y_Operacion.md`. Los secretos permanecen fuera del repositorio y nunca deben aparecer en informes.

## 6. Configuración

### Organización y alcance

Una ejecución organizacional requiere al menos un dominio o nombre de organización/marca y `authorized_scope=true`. La investigación de personas pertenece exclusivamente al módulo **Riesgo virtual de empleados**, con permisos, minimización, retención e informe separados. Campos principales:

- marca, grupo o conglomerado;
- dominios propios;
- sector y subsector;
- país y países de operación;
- marcas, filiales, productos y activos estratégicos;
- ventana temporal;
- modo `snapshot` o `deep`;
- presupuesto de tiempo;
- autorización Tor;
- idioma español o inglés.

Los dominios comparativos se almacenan aparte y no se mezclan con el alcance propio.

### Fuentes

Las API keys son opcionales. Su ausencia debe producir `disabled`, `not_applicable` o `skipped`, nunca registros simulados. OpenCTI usa `OPENCTI_MODE=disabled` por defecto.

## 7. Operación paso a paso

1. Inicie sesión con un rol habilitado.
2. Cree o seleccione una empresa si corresponde.
3. Abra **Overview**; allí se integran alcance, configuración, ejecución, progreso y resumen de resultados.
4. Escriba la marca/organización y dominios autorizados.
5. Defina sector, país, ventana, profundidad y Tor.
6. Confirme el alcance.
7. Lance la ejecución.
8. Observe `Estado de corrida`; cada etapa cambia progreso y estado.
9. Revise cobertura de conectores y errores parciales.
10. Desde Overview abra tablero estratégico, evidencia, superficie, OSINT, Inteligencia SOCMINT y posibilidades soportadas.
11. Valide o descarte evidencia desde el ledger.
12. Solicite el informe con el botón **Generar informe**.
13. Revise el resultado del validador.
14. Descargue HTML, JSON o CSV.

Cerrar sesión no detiene el worker: la ejecución vive en la API y queda persistida.

## 8. Proceso de inteligencia

```mermaid
flowchart TD
    D["Dirección: pregunta y alcance"] --> P["Planeación de fuentes y tiempo"]
    P --> C["Recolección pública autorizada"]
    C --> N["Normalización, hashes y deduplicación"]
    N --> E["Entidades, relaciones y validación"]
    E --> A["Análisis de riesgo, contexto y escenarios"]
    A --> PR["Producción de dashboard"]
    PR --> H["Revisión humana"]
    H --> I["Informe solicitado"]
    I --> F["Retroalimentación, cierre o monitoreo"]
```

## 9. Fuentes y estados

El catálogo puede incluir buscadores públicos/RSS, noticias, CISA KEV, NVD, FIRST EPSS, GitHub Advisories, OTX, urlscan, DNS/certificados/WHOIS, SpiderFoot, índices autorizados de dark web, MISP y TAXII.

Estados del ciclo de vida:

- `registered`: el conector existe en el catálogo;
- `eligible`: configuración, licencia y alcance permitían consultarlo;
- `attempted`: la corrida inició una consulta real;
- `succeeded`: la consulta terminó sin fallo;
- `productive`: entregó al menos un registro;
- `empty`: consulta correcta sin registros relacionados;
- `degraded`: resultado parcial, timeout o rate limit con respuesta utilizable;
- `skipped`: no se intentó por una regla explícita;
- `unconfigured`: faltó configuración obligatoria;
- `failed`: error técnico sin resultado utilizable.

Los KPI usan denominadores explícitos: productividad sobre intentadas y cobertura sobre elegibles. Los conectores registrados nunca inflan por sí solos la salud operativa.

Una fuente real indica procedencia real; no convierte cada afirmación en verdadera.

## 10. Normalización y deduplicación

Cada registro conserva el dato original y añade:

- identificador canónico;
- hash de contenido;
- URL canónica;
- timestamp observado;
- tipo de registro;
- relación con el alcance;
- estado de evidencia;
- confianza;
- referencias de fuente;
- número de duplicados;
- resultado y método de validación.

Duplicados exactos se agrupan por identidad/hash. Copias sindicadas no multiplican automáticamente el impacto. La evidencia original y la interpretación permanecen separadas.

## 11. Análisis realizados

### OSINT

Consolida información pública relacionada con el alcance. Muestra consultas, registros, fuentes, URLs y limitaciones. Un resultado por coincidencia de palabra permanece relacionado o candidato hasta validar relación directa.

### SOCMINT

Trabaja con menciones y perfiles públicos indexados. Los nodos representan entidades presentes en registros; las aristas representan relaciones derivadas de evidencia. Si no hay datos, no se dibuja una red.

### Superficie externa

Revisa DNS, correo, certificados, WHOIS, subdominios y tecnologías mediante técnicas defensivas. Un servicio visible no es vulnerabilidad. Una CVE solo se vuelve aplicable si producto y versión pueden justificarse.

### Marca y fraude

Busca suplantación, dominios similares y narrativas relacionadas. La similitud lexical es una señal, no prueba de fraude. El impacto reputacional requiere evidencia de alcance, contexto y corroboración.

### Dark web

Usa índices y metadatos autorizados. Tor es opcional. No descarga datos robados ni interactúa con mercados. `no_data` describe la cobertura disponible, no ausencia global.

### Desinformación

Mapea registros compatibles a DISARM. Sin evidencia posterior a la corrida, las tácticas no se muestran como activas.

### Vulnerabilidades

Combina CVE, CVSS, EPSS y KEV con aplicabilidad. CVSS mide severidad técnica; EPSS estima explotación de CVE; KEV registra explotación conocida; ninguno prueba afectación del activo sin identificación tecnológica.

### PESTEL y Porter

Clasifican clusters de evidencia vinculada al sujeto: información corporativa, regulatoria, sectorial, financiera, tecnológica, operacional, de sostenibilidad y noticias públicas. El análisis se calcula una vez para la marca, grupo o conglomerado y sus dominios propios; los comparativos permanecen fuera del alcance. Cada dimensión muestra cobertura de evidencia aunque todavía no exista soporte suficiente para publicar una presión direccional. La presión agregada solo se publica cuando cobertura >= 60 %, confianza >= 50 y más de la mitad de dimensiones tienen datos puntuables. Cobertura no es riesgo, cumplimiento ni probabilidad de ataque.

### Escenarios y plantillas preventivas

El catálogo contiene 1.500 **plantillas preventivas de referencia**, no 1.500 escenarios ejecutables. Actualmente existen 0 definiciones que satisfagan el contrato completo de escenario ejecutable. Una posibilidad se muestra como soportada solo cuando evidencia de la corrida satisface criterios explícitos; esto no confirma un ataque ni un incidente. El detalle auditable está en `docs/auditoria/escenarios-inventario.md`.

## 12. Matemáticas y cálculos

**Versión de riesgo residual:** `P-CIDER 1.0.0`.  
**Versión de evidencia:** `1.0.0`.  
**Versión claim-evidence:** registrada en cada contexto.

### Actividad de amenazas

Para cada registro `i`:

`T = sum(sourceWeight_i * confidence_i * 2^(-ageDays_i / halfLife_i))`

`A = 1 - exp(-0.35 * T)`

El resultado está acotado a `[0,1]` y normaliza saturación de volumen. No es probabilidad.

### Plausibilidad contextual P-CIDER

`L_raw = sigmoid(-2.10 + 0.70A + 0.85E + 0.75V + 0.90logit(P)/6 + 0.85K + 0.70TTP + 0.55S + 0.35G)`

`L = DS*L_raw + (1-DS)*base_rate`

Variables: actividad, exposición, vulnerabilidad, prior EPSS, KEV, TTP, sector,
geografía, suficiencia de datos y tasa base conservadora. Es una heurística
versionada, no un modelo predictivo calibrado. Los controles, detección y
respuesta no reducen `L`; se aplican una sola vez al riesgo residual.

### Impacto

`I = 0.25F + 0.20O + 0.20C + 0.15In + 0.10A + 0.05L + 0.05R`

Los pesos suman 1.0. Datos ausentes no deben sustituirse por cero observado.

### Efectividad de controles

`CE_raw = 1 - product((1 - e_c)^w_c)`

`CE = min(0.85, CE_raw)`

El valor máximo aplicado al riesgo residual es 0.85 para evitar una reducción total no justificable.

### Riesgo

`R_inherent = 100 * L * I`

`R_residual = R_inherent * (1 - min(0.85, CE))`

Ejemplo: `L=0.40`, `I=0.60`, `CE=0.50`. Riesgo inherente `24`; residual `12`.

### Matriz 4x4

`L` e `I` se discretizan en 1..4 y se multiplican. 1-3 bajo, 4-7 medio, 8-11 alto, 12-16 crítico.

### Monte Carlo

Muestrea distribuciones beta alrededor de `L`, `I` y `CE` con semilla reproducible y reporta p10, p50 y p90. Son bandas de sensibilidad del modelo, no intervalos de una frecuencia observada.

### Índice de presión de señales

La implementación activa muestra bandas de sensibilidad derivadas de intensidad reciente cuando existen datos suficientes. La función Poisson permanece registrada como `reference_only`, sin caller productivo ni calibración; por ello no se publica como probabilidad de ataque.

### PESTEL/Porter operativo

Cada cluster aporta `match * quality * recency * directness * novelty * corroboration * extraction * mapping`; la presión final usa una transformación `tanh` acotada. La cobertura ponderada de evidencia se calcula por separado para impedir que un dato real pero no direccional se convierta en un cero o porcentaje inventado. Sin umbral de cobertura/confianza, la presión queda `insufficient_evidence`, pero el tablero conserva los aspectos respaldados, sus fuentes y la cobertura disponible. Las funciones heredadas `pestel_cyber_index` y `porter_cyber_index` no son el cálculo productivo actual.

## 13. Marcos de referencia

- ATT&CK 19.1: comportamiento adversario y técnicas;
- D3FEND 1.4.0: contramedidas defensivas;
- ATLAS 5.6.0: amenazas contra sistemas de IA;
- DISARM: tácticas de desinformación;
- NIST CSF 2.0: resultados de gobierno y ciberseguridad;
- ISO 27001:2022: áreas de control mediante resúmenes no propietarios;
- PCI DSS 4.0.1, SOC 2, GDPR, CIS Controls y COBIT: cobertura de mapeo.

Un porcentaje de framework significa cobertura de mapeo de señales, no cumplimiento.

## 14. Dashboard

El dashboard debe leerse de arriba hacia abajo:

1. alcance y ventana;
2. estado y duración;
3. cobertura de conectores;
4. registros únicos y hallazgos;
5. distribución web/geográfica;
6. confianza y limitaciones;
7. riesgo;
8. relaciones;
9. cambios históricos;
10. posibilidades de decisión.

Cada KPI se deriva del snapshot y debe enlazar al detalle. `0 observado` y `sin datos` son estados diferentes.

## 15. Distribución geográfica

Las ubicaciones deben distinguir coordenada exacta, ciudad, región, país, infraestructura e inferencia. Nunca se usa una coordenada arbitraria para datos sin ubicación. Una IP puede representar infraestructura y no una persona. La precisión y confianza deben acompañar el punto o agregado.

## 16. Inteligencia SOCMINT y grafos

- nodo: persona, organización, cuenta, dominio, alias, correo, publicación, URL, hashtag, evento o infraestructura;
- arista: relación sustentada o inferida, con dirección, peso, fecha y evidencia;
- degree: número de relaciones;
- in/out-degree: relaciones entrantes/salientes;
- betweenness: capacidad de puente;
- densidad: relaciones presentes respecto de las posibles;
- comunidad: grupo estructural detectado.

Centralidad alta no implica culpabilidad, intención ni control. Las métricas se muestran solo con suficiente estructura.

## 17. Lectura de informes

### Ejecutivo

Presenta alcance, cobertura, hallazgos validados, riesgo, contexto y plan de trabajo. Usa referencias compactas y enlaza a evidencia. No contiene respuestas técnicas completas.

### Técnico

Incluye consulta, respuesta original disponible, URL, hash, timestamp, fuente, entidad, relación, validación, contradicciones y limitaciones. Las evidencias HTTP(S) públicas priorizadas pueden incluir una captura aislada con hash, dimensiones, URL final, código HTTP y fecha; la imagen amplía al seleccionarla. Una captura demuestra el contenido observado en ese momento, no confirma por sí sola la interpretación. Permite reconstruir el análisis.

### Estados

- candidato: relación pendiente;
- respaldado: evidencia relacionada suficiente para análisis;
- validado: método y evidencias registradas;
- confirmado: supera umbral y no tiene contradicción crítica abierta;
- materializado: impacto de seguridad demostrado.

## 18. Modelo claim-evidence

Toda afirmación importante recorre:

`Claim -> Evidence -> Interpretation -> Limitation -> Decision -> Closure`

Cada hallazgo explica qué se encontró, qué demuestra, qué no demuestra, cómo se validó, confianza, limitaciones, decisión, responsable y criterio de cierre.

## 19. Asistencia analítica opcional

OpenClaw es una capa reemplazable de orquestación analítica, no el núcleo. En el despliegue local actual su gateway se inicia en una red Docker interna con autenticación por token, filesystem de solo lectura, límites de CPU/memoria y herramientas de ejecución denegadas. Puede preparar borradores, explicar scores, detectar contradicciones y proponer consultas; no publica, no cambia scores ni ejecuta comandos arbitrarios.

El tablero **Asistente estratégico** trabaja siempre sobre la corrida seleccionada. El usuario puede elegir los módulos que forman el contexto, formular preguntas ejecutivas o técnicas, abrir los tableros relacionados y solicitar con lenguaje natural la generación de los informes ejecutivo y técnico. La conversación se separa por `runId`; el historial del usuario se trata como solicitud no confiable y nunca como evidencia.

El botón **Análisis profundo** prepara un paquete acotado a la corrida y activa,
según los módulos elegidos, agentes especializados de calidad de recolección,
confiabilidad de fuentes, evidencia estratégica, causalidad, narrativas,
contradicciones, escenarios, riesgo, síntesis ejecutiva y consistencia.

La ejecución usa una arquitectura híbrida:

1. un planificador selecciona hasta tres especialistas en modo interactivo o
   seis en modo profundo;
2. cada especialista reduce de forma determinista solo los datos de su alcance;
3. un sintetizador determinista produce la respuesta interactiva inmediata, u
   OpenClaw realiza una única síntesis profunda con el modelo local de mayor
   capacidad;
4. un verificador determinista comprueba que las referencias pertenezcan al
   `runId`;
5. la interfaz muestra la traza, el estado y las limitaciones de cada etapa.

No se ejecuta un modelo generativo independiente por agente. Así se evita
duplicar contexto, competir por memoria y multiplicar latencia. Los agentes son
roles lógicos sin acceso a shell, navegación ni escritura.

La ejecución local usa dos perfiles Ollama:

- `cyberdecision-cti-chat`, derivado de `qwen3:0.6b`, disponible como capacidad
  local de respaldo y prueba;
- `cyberdecision-cti`, derivado de `qwen3:1.7b`, para análisis profundo orquestado por OpenClaw.

Las cifras, estados, cobertura y enlaces no los calcula un modelo generativo. Se leen directamente de la fuente de verdad de la corrida y llevan referencias `kpi:*`. La conversación interactiva sintetiza de forma determinista las reducciones especializadas; el análisis profundo puede usar OpenClaw. Si el modelo solicitado falla, la respuesta se limita a esa lectura verificable y registra la limitación. Sin hallazgos validados, ninguna ruta puede convertir registros relacionados o contextuales en hechos. La generación de informes continúa siendo determinista y solo ocurre por una acción explícita del usuario.

`ollama_chat.ready` describe el respaldo conversacional y
`openclaw_gateway.ready` la orquestación analítica principal. La configuración
publica además `agent_architecture`, con el modo, número máximo de especialistas,
síntesis y validación posterior. Los modelos se descargan de memoria tras tres
minutos de inactividad. Si cualquiera falla, la recolección, los cálculos, los
tableros y los informes continúan operando. Una salida incompleta del modelo se
reemplaza por una respuesta segura basada en KPI; nunca se publica como
conclusión.

El contenido web se trata como dato no confiable. Las salidas deben registrar hechos, inferencias, evidencia, confianza, versión del motor y limitaciones. La aprobación humana permanece obligatoria. Una respuesta vacía, `NO_REPLY`, una referencia desconocida o un desbordamiento de contexto no se marca como análisis completado.

## 20. OpenCTI

OpenCTI es un backend de conocimiento opcional y está deshabilitado por defecto. Modos: `disabled`, `read_context`, `sync_validated`, `system_of_record`. Solo `sync_validated` envía entidades y relaciones validadas; nunca datos brutos, caché, falsos positivos o propuestas no aprobadas.

## 21. Seguridad y privacidad

- alcance autorizado obligatorio;
- redes Docker separadas;
- sidecars sin puertos host;
- capacidades Linux eliminadas y `no-new-privileges`;
- secretos fuera del repositorio;
- roles y licencias por organización;
- logs y auditoría;
- TLP/PAP en evidencia;
- sesiones y MFA disponibles en la capa local, pendientes de IdP/SSO para producción;
- OpenClaw en modo propuesta y allowlist;
- redacción de datos sensibles en informes.

## 22. Administración

`superadmin` gestiona empresas, licencias, usuarios, módulos y auditoría. `admin` gestiona usuarios de su empresa. Roles operativos consumen módulos permitidos. Antes de producción, el control de acceso debe aplicarse server-side con JWT/refresh o SSO, MFA, revocación y hashing robusto.

## 23. Solución de problemas

| Síntoma | Verificación | Acción |
|---|---|---|
| Web no abre | `docker compose ps` | reconstruir `web` y revisar 8080 |
| API no responde | `/api/health`, logs API | validar PostgreSQL y reiniciar API |
| corrida no avanza | `GET /api/runs/<runId>` | revisar etapa, timeout y conectores |
| conector sin datos | estado y `message` | no confundir con cero; revisar cuota/alcance |
| Tor parcial | logs de `tor-proxy` | validar `allow_tor` y red interna |
| informe rechazado | `_validation.json` | corregir evidencia, referencias o conteos y regenerar |
| ciudades tardan | red del navegador | el catálogo se carga de forma diferida |
| Python local falla | `python --version` | usar Docker o Python 3.13 |

## 24. Glosario y anexos

- **registro recolectado:** dato obtenido de una fuente;
- **evidencia validada:** registro unido a una afirmación mediante método registrado;
- **hallazgo:** condición analizada que cumple reglas de evidencia;
- **confianza:** calidad de soporte de una afirmación;
- **likelihood:** plausibilidad contextual heurística;
- **riesgo:** likelihood, impacto y controles con evidencia;
- **alerta:** regla, umbral, responsable, acción y estado;
- **incidente confirmado:** impacto de seguridad demostrado y estado de respuesta;
- **runId:** identidad única de una ejecución;
- **snapshot:** fuente canónica de dashboard e informes;
- **TLP/PAP:** restricciones de distribución y acción.

### Checklist operativo

- [ ] alcance autorizado;
- [ ] sujeto y dominios sin valores por defecto;
- [ ] ventana y país definidos;
- [ ] conectores revisados;
- [ ] corrida completada;
- [ ] evidencia crítica inspeccionada;
- [ ] afirmaciones sin huérfanos;
- [ ] informe solicitado por el usuario;
- [ ] validador aprobado;
- [ ] limitaciones comunicadas;
- [ ] cierre o monitoreo asignado.

### Documentos relacionados

- `docs/SEMANTIC_MODEL.md`
- `docs/EVIDENCE_MODEL.md`
- `docs/CLAIM_EVIDENCE_GUIDE.md`
- `docs/TERM_DICTIONARY.md`
- `docs/OPENCTI_DECISION.md`
- `docs/opencti_value_assessment.md`
- `docs/HOW_TO_READ_REPORTS.md`
- `docs/arquitectura/openclaw-cti.md`
- `docs/seguridad/openclaw-threat-model.md`
- `docs/seguridad/openclaw-controls.md`
- `docs/auditoria/00-diagnostico-inicial.md`
- `docs/auditoria/01-optimizacion-geografica.md`
- `docs/auditoria/02-matriz-referencias.md`
- `docs/auditoria/03-ejecuciones-grupo-aval-frontera.md`
- `docs/roadmap/Mejoras_Recomendadas.md`
