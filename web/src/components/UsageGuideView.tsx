import {
  BookOpen,
  Bot,
  BrainCircuit,
  Crosshair,
  ExternalLink,
  FileClock,
  FileSearch,
  Fingerprint,
  GitBranch,
  LockKeyhole,
  MessageSquareWarning,
  Network,
  Radar,
  Settings2,
  ShieldAlert,
  Users
} from "lucide-react";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getMethodologyRegistry } from "../api";
import type { LanguageMode, MethodologyRecord, UserRole } from "../types";

const content = {
  es: {
    title: "Uso de la plataforma",
    subtitle: "Guía rápida para leer CyberDecisionEngine y convertir hallazgos en decisiones.",
    modelTitle: "Matemática y lógica de escenarios",
    modelSubtitle: "Visible solo para admin. CyberDecisionEngine separa fuente, transformación, cálculo e interpretación.",
    originTitle: "Origen y propósito",
    originBody:
      "CyberDecisionEngine fue creado por Edwin Peñuela como modelo de cyberinteligencia estratégica para toma de decisiones accionables. El enfoque se viene desarrollando desde 2022 y combina inteligencia defensiva, análisis de riesgo, fraude, postura, cumplimiento y predicción preventiva para organizaciones.",
    moduleTitle: "Lectura de menús y tableros",
    moduleSubtitle: "Cada menú responde una pregunta de decisión distinta. Los tableros muestran evidencia, no datos inventados.",
    theoryTitle: "Teorías, modelos y frameworks aplicados",
    theorySubtitle: "Base conceptual usada para interpretar señales y convertirlas en riesgo, escenarios y recomendaciones.",
    sections: [
      {
        icon: Radar,
        title: "Tablero estratégico",
        body: "Concentra postura, radar de riesgo, mapa de calor, forecast, PESTEL, Porter y TTP. Empieza aquí para priorizar decisiones ejecutivas."
      },
      {
        icon: BrainCircuit,
        title: "Escenarios de decisión",
        body: "Cruza evidencia de dominios con ATT&CK, D3FEND, ATLAS y DISARM para mostrar posibilidades accionables por dominio y grupo, sin afirmar eventos no evidenciados."
      },
      {
        icon: Bot,
        title: "IA estratégica",
        body: "Construye un prompt maestro, contexto exacto, payloads multi-IA y propuestas OpenClaw para análisis aumentado. No ejecuta automatizaciones externas hasta que el borrador sea aprobado."
      },
      {
        icon: Crosshair,
        title: "Superficie de Ataque",
        body: "Valida DNS, RDAP/WHOIS y certificados TLS de dominios propios y competidores declarados. Un riesgo alto indica fricción técnica a revisar, no explotación confirmada."
      },
      {
        icon: Fingerprint,
        title: "Marca y Fraude",
        body: "Ordena menciones, noticias, sentimiento por frase, impacto reputacional y dominios parecidos observados en URLs para apoyar prevención, comunicación, fraude y takedown."
      },
      {
        icon: Users,
        title: "Riesgo Empleados",
        body: "Ejecuta el modelo OSINT autorizado de exposición pública por empleado, con revisión humana e informe HTML descargable."
      },
      {
        icon: MessageSquareWarning,
        title: "Desinformación",
        body: "Mapea señales públicas, narrativas y comportamiento de influencia con DISARM. Si no hay evidencia, no dibuja actividad."
      },
      {
        icon: FileSearch,
        title: "OSINT",
        body: "Muestra resultados abiertos, consultas tipo dork defensivo y evidencia URL por URL. Sirve para descubrir exposición accionable que un adversario podría observar."
      },
      {
        icon: Network,
        title: "SOCMINT",
        body: "Presenta redes de menciones públicas, nodos, relaciones y comportamiento de tendencia. Si no hay datos, el tablero queda vacío para evitar inventar información."
      },
      {
        icon: LockKeyhole,
        title: "Dark Web",
        body: "Trabaja con indices publicos, importaciones autorizadas y metadatos redacted. No interactua con mercados, no compra datos y no descarga payloads."
      },
      {
        icon: GitBranch,
        title: "Mapeo de Frameworks",
        body: "Relaciona hallazgos con NIST, ISO 27001, PCI DSS, SOC 2, GDPR, MITRE ATT&CK, D3FEND y ATLAS para explicar controles afectados y decisiones de remediación."
      },
      {
        icon: FileClock,
        title: "Informes",
        body: "Genera salida ejecutiva y técnica. El ejecutivo prioriza decisión; el técnico conserva evidencia, fuentes, metodología y trazabilidad."
      },
      {
        icon: ShieldAlert,
        title: "Monitoreo 24/7",
        body: "Crea perfiles persistentes con duración por ciclo o ejecución indefinida. La plataforma recolecta, deduplica y genera alertas internas; los informes se generan solo por solicitud."
      },
      {
        icon: Settings2,
        title: "Configuración",
        body: "Centraliza fuentes, API, usuarios, acceso y la cobertura operativa de conectores de la corrida seleccionada. Esa cobertura indica capacidad de recolección, no riesgo ni ausencia de amenazas."
      }
    ],
    modules: [
      {
        icon: Radar,
        title: "Tablero estratégico",
        focus: "Vista ejecutiva para decidir rápido: qué riesgo sube, dónde impacta y qué debe priorizarse.",
        boards: [
          "Radar ejecutivo y mapa de calor: resumen de severidad por tipo de riesgo.",
          "Alerta temprana: presión relativa de señales por modalidad, TTP, sector y ventana temporal.",
          "PESTEL y Porter: lectura estratégica externa y competitiva.",
          "Grafo de amenazas y noticias: relaciones entre actores, TTP, acciones y evidencia reciente.",
          "Alcance, geografía, sector y fuentes: contexto real de la corrida."
        ]
      },
      {
        icon: BrainCircuit,
        title: "Escenarios de decisión",
        focus: "Panel para ver qué escenarios aplican al dominio o grupo analizado y qué posibilidades de decisión se abren.",
        boards: [
          "Lectura por dominio: filtra escenarios por uno, varios o todos los dominios.",
          "Mapa de frameworks: ATT&CK, D3FEND, ATLAS y DISARM presentes.",
          "Tarjetas de escenario: evidencia, criterio, pregunta directiva, posibilidad de decisión y dominios relacionados."
        ]
      },
      {
        icon: Bot,
        title: "IA estratégica",
        focus: "Prepara análisis aumentado para modelos actuales con contexto controlado, límites de tokens y reglas anti-alucinación.",
        boards: [
          "Proveedores IA: selecciona OpenAI, Azure OpenAI, Anthropic, Gemini, Mistral, endpoint local compatible u OpenClaw Gateway.",
          "Presupuesto de tokens: estima entrada/salida para evitar prompts excesivos.",
          "Prompt maestro y payloads: conserva sistema, usuario, esquema JSON, manifiesto de evidencia y política de automatización antes de aprobar."
        ]
      },
      {
        icon: Crosshair,
        title: "Superficie de ataque",
        focus: "Revisa exposición técnica pasiva del dominio: DNS, RDAP/WHOIS, TLS y comparación declarada.",
        boards: [
          "Inventario de dominio: configuración observable.",
          "Certificados y vencimientos: señales de higiene técnica.",
          "Comparativo propio vs competencia: posición relativa frente a dominios declarados."
        ]
      },
      {
        icon: Fingerprint,
        title: "Marca y Fraude",
        focus: "Organiza menciones públicas, fraude, abuso de marca y señales reputacionales.",
        boards: [
          "Sentimiento por frase y dominio: positivo, neutro o negativo según evidencia recolectada.",
          "Impacto reputacional: indicador de decisión calculado desde señales negativas, dark web y SOCMINT.",
          "Dominios parecidos observados: evidencia URL por URL para validar typosquatting, sustituciones 0/o, 1/l u otras similitudes.",
          "Menciones y URLs: dónde aparece la marca, grupo, conglomerado o dominio."
        ]
      },
      {
        icon: Users,
        title: "Riesgo virtual de empleados",
        focus: "Ejecuta el modelo OSINT autorizado por empleado individual o archivo masivo.",
        boards: [
          "Formulario individual: al menos un campo verificable para ejecutar búsqueda.",
          "Carga masiva: archivo estructurado con empleados y contexto.",
          "Informe del módulo: exposición, hallazgos y recomendaciones descargables."
        ]
      },
      {
        icon: MessageSquareWarning,
        title: "Desinformación",
        focus: "Analiza narrativas, señales de influencia y mapping DISARM cuando existe evidencia pública.",
        boards: [
          "Pulso DISARM: técnicas y tácticas observadas.",
          "Riesgo narrativo: alcance, confianza de fuente y posible impacto.",
          "Mapping: relación entre narrativa, dominio, marca o actor."
        ]
      },
      {
        icon: FileSearch,
        title: "OSINT",
        focus: "Muestra resultados abiertos y búsquedas defensivas que evidencian exposición accionable.",
        boards: [
          "Resultados URL por URL: fuente, título y señal encontrada.",
          "Dorks defensivos: consultas para descubrir exposición observable.",
          "Evidencia por dominio: hallazgos asociados al alcance analizado."
        ]
      },
      {
        icon: Network,
        title: "SOCMINT",
        focus: "Lee menciones públicas y relaciones en redes como red de nodos/aristas cuando hay datos.",
        boards: [
          "Red de menciones: nodos movibles, plataformas, temas y relaciones.",
          "Tendencias: volumen, temas y comportamiento público.",
          "Usuarios o entidades relacionadas: solo si la fuente pública lo permite."
        ]
      },
      {
        icon: LockKeyhole,
        title: "Dark Web",
        focus: "Revisión pasiva y segura de índices, imports autorizados y metadatos redacted.",
        boards: [
          "Señales de leak o credenciales: evidencia resumida y segura.",
          "Fuentes y estado: indica si no hubo data o si la fuente requiere configuración.",
          "Riesgo operativo: lectura sin comprar, descargar ni interactuar con mercados."
        ]
      },
      {
        icon: GitBranch,
        title: "Mapeo de frameworks",
        focus: "Traduce hallazgos a controles, aspectos afectados y decisiones de remediación.",
        boards: [
          "NIST, ISO, PCI, SOC 2, GDPR: controles y aspectos a revisar.",
          "MITRE ATT&CK/D3FEND/ATLAS: ofensiva, defensa y riesgos de IA.",
          "Detalle expandible: evidencia usada, análisis y uso para decisión."
        ]
      },
      {
        icon: FileClock,
        title: "Informes e historial",
        focus: "Consulta corridas, descarga informes ejecutivos/técnicos y conserva trazabilidad.",
        boards: [
          "Historial: corridas, estado, ventana temporal y fuentes.",
          "Informes: versión ejecutiva para decisión y técnica para evidencia, sin fórmulas extensas en la salida.",
          "Programación: permite ejecutar revisiones periódicas sobre dominios por defecto o alcance actual.",
          "Configuración: fuentes, API keys, usuarios, idioma y tema."
        ]
      },
      {
        icon: ShieldAlert,
        title: "Monitoreo 24/7 y soporte",
        focus: "Activa recolección persistente para una marca, grupo o dominios autorizados sin generar informes automáticos.",
        boards: [
          "Perfiles: frecuencia, duración máxima por ciclo, último cierre, siguiente ejecución y pausa/reanudación.",
          "Alertas: señales nuevas deduplicadas por huella de evidencia; permiten reconocer, cerrar o marcar falso positivo.",
          "Bitácora operativa: lanzamientos, cierres, fallas de colectores, timeouts y eventos de soporte.",
          "Soporte: el usuario registra fallas visibles y el superadmin puede revisarlas como tickets operativos."
        ]
      },
      {
        icon: Settings2,
        title: "Configuración y conectores",
        focus: "Administra fuentes, accesos y capacidad operativa sin mezclarla con los hallazgos del análisis.",
        boards: [
          "Cobertura operativa de conectores: muestra estado, registros y actualización de la última corrida seleccionada.",
          "Fuentes y API: habilitación y referencias de credenciales sin exponer secretos.",
          "Usuarios y acceso: roles, MFA, licencias y permisos efectivos.",
          "Lectura correcta: un conector sin datos no equivale a un cero observado ni a ausencia de riesgo."
        ]
      },
      {
        icon: ShieldAlert,
        title: "Gobierno y licenciamiento",
        focus: "Opera la plataforma por empresa, plan, usuario, acceso modular y auditoría.",
        boards: [
          "Empresas: estructura tipo árbol para grupos, filiales o clientes.",
          "Licencias: plan por empresa, cupos, vencimiento, estado y módulos.",
          "Usuarios: rol, plan asignado, módulos efectivos y bitácora de cambios."
        ]
      },
      {
        icon: LockKeyhole,
        title: "Seguridad de acceso",
        focus: "Controla autenticación local, MFA temporal, bloqueo por intentos y restablecimiento de contraseña.",
        boards: [
          "MFA: el admin genera un código temporal de doble factor por usuario.",
          "Bloqueo: cinco intentos fallidos bloquean la cuenta por ventana temporal.",
          "Reset: el admin emite contraseña temporal y el usuario debe cambiarla al entrar."
        ]
      }
    ],
    theories: [
      {
        title: "Ciclo de inteligencia",
        body: "Usa dirección, recolección, procesamiento, análisis, difusión y retroalimentación. Por eso cada tablero separa fuente, evidencia, cálculo y lectura ejecutiva."
      },
      {
        title: "Riesgo ISO/NIST",
        body: "Combina plausibilidad contextual, impacto, exposición, vulnerabilidad aplicable, controles declarados y riesgo residual. El objetivo es priorizar tratamiento sin convertir señales públicas en certeza."
      },
      {
        title: "Estrategia PESTEL y Porter",
        body: "PESTEL interpreta presión política, económica, social, tecnológica, ambiental y legal. Porter ayuda a leer fuerzas competitivas, terceros, sustitutos y presión sectorial."
      },
      {
        title: "MITRE + DISARM",
        body: "ATT&CK modela comportamiento adversario, D3FEND controles defensivos, ATLAS riesgos de IA y DISARM narrativas/influencia. Los escenarios aparecen solo cuando cruzan con evidencia."
      },
      {
        title: "IA aumentada controlada",
        body: "El análisis IA usa solo el contexto comprimido de la corrida, reglas anti-alucinación, manifiesto de evidencia y aprobación humana antes de cualquier automatización externa. OpenClaw se usa como gateway/asistente de propuestas, no como ejecución libre."
      },
      {
        title: "Graph intelligence",
        body: "Los nodos representan actores, señales, temas o plataformas; las aristas representan relación observada. Si no hay relaciones, no se dibuja red."
      },
      {
        title: "Índice preventivo de presión de señales",
        body: "Regresión logística acotada, ponderación de controles declarados, Monte Carlo y análisis de sensibilidad se usan como apoyo de decisión. Cuando faltan datos, el resultado se presenta como no evaluado."
      },
      {
        title: "Marca, reputación y similitud",
        body: "El análisis de marca calcula sentimiento por frase y reputación desde evidencia real. La similitud de dominios se presenta como validación requerida, no como fraude confirmado."
      },
      {
        title: "Gobierno SaaS y mínimo privilegio",
        body: "El licenciamiento usa jerarquía empresa-usuario, módulos explícitos y bitácora de auditoría. El acceso se calcula por rol, plan de usuario, licencia de empresa y overrides controlados."
      },
      {
        title: "Seguridad local de acceso",
        body: "En escritorio/laboratorio se aplica MFA temporal, bloqueo por intentos, expiración de sesión y reseteo por admin. Para producción debe migrarse a IAM/backend con MFA real, hashing fuerte, salting, auditoría central y recuperación segura."
      },
      {
        title: "Alertas guiadas",
        body: "Los formularios explican qué falta, dónde falta y por qué bloquea la acción. Si una fuente no está configurada o no devuelve datos, se informa el estado en vez de inventar resultados."
      },
      {
        title: "Monitoreo continuo y deduplicación",
        body: "El monitoreo 24/7 usa perfiles persistentes del backend. Cada ciclo genera datos nuevos, compara huellas de evidencia contra lo ya visto y alerta solo señales no repetidas. Las corridas quedan listas para dashboard; el informe HTML sigue siendo manual."
      }
    ],
    model: [
      {
        title: "1. Ingesta y trazabilidad",
        body: "Cada señal debe venir de una fuente configurada: OSINT, SOCMINT pública, índices autorizados de dark web, RDAP/WHOIS, TLS, MITRE o frameworks. La ventana temporal elegida filtra evidencia y queda registrada en el informe. Si una fuente no entrega registros, el tablero queda vacío o muestra estado de fuente, no genera datos ficticios."
      },
      {
        title: "2. Búsqueda pública y alcance",
        body: "El dominio tiene prioridad sobre el nombre del grupo: si existe dominio específico, las consultas salen del dominio y alias derivados. OSINT/SOCMINT usa APIs configurables cuando existan y fallback público conservador sin evasión de bloqueos; si una fuente responde 403/429, se registra y se corta para esa corrida. Dark Web se limita a índices públicos, imports redacted y fuentes autorizadas."
      },
      {
        title: "3. Riesgo contextual",
        body: "La plausibilidad contextual usa una función logística acotada. Solo combina evidencia sustentada de actividad, exposición, vulnerabilidad aplicable y controles declarados; no es una probabilidad calibrada de ataque."
      },
      {
        title: "4. Impacto y residual",
        body: "Riesgo inherente = plausibilidad contextual x impacto. Riesgo residual = inherente x (1 - efectividad de controles declarados), con límites para evitar valores imposibles."
      },
      {
        title: "5. Forecast defensivo",
        body: "La alerta temprana usa un índice no calibrado de presión de señales: IPS(t)=1-e^(-r*t). r solo aumenta con evidencia directa o validada, CVE aplicables y contexto declarado; no estima la probabilidad de un ataque."
      },
      {
        title: "6. Incertidumbre",
        body: "Monte Carlo simula variación de plausibilidad contextual, impacto y controles declarados con distribuciones beta. El informe expone percentiles p10, p50 y p90 como intervalo de sensibilidad, no como pronóstico confirmado."
      },
      {
        title: "7. Estrategia",
        body: "PESTEL explica presiones externas; Porter explica fuerzas competitivas; el mapeo de frameworks traduce hallazgos a controles NIST, ISO, PCI, SOC, GDPR, ATT&CK, D3FEND y ATLAS."
      },
      {
        title: "8. Escenarios avanzados",
        body: "La biblioteca de escenarios cruza ATT&CK, D3FEND, ATLAS, DISARM, PESTEL, Porter, riesgo reputacional y continuidad para generar posibilidades preventivas que solo se muestran como presentes cuando se cruzan con evidencia."
      },
      {
        title: "9. Licenciamiento y auditoría",
        body: "El super admin administra empresas y licencias; el admin de empresa administra usuarios operativos. Acceso efectivo = rol + módulos del plan de usuario o licencia de empresa + overrides autorizados. Cada cambio crítico genera registro de auditoría para seguridad, soporte y trazabilidad comercial."
      },
      {
        title: "10. IA estratégica y tokens",
        body: "El paquete IA usa selección por riesgo y recencia: primero hallazgos de mayor riesgo residual, luego eventos recientes y diversidad de fuente. El presupuesto estimado aproxima tokens = caracteres/4 y corta evidencia de menor prioridad antes de modificar conclusiones. OpenClaw puede recibir el mismo contexto como propuesta de análisis/agenda, sin herramientas ni comandos hasta aprobación."
      },
      {
        title: "11. Acceso, MFA y recuperación",
        body: "El login valida campos obligatorios, cuenta bloqueada, credenciales y MFA. El admin puede generar un código MFA temporal, resetear contraseña, desbloquear usuarios y exigir cambio de clave. Las cuentas seed no activan MFA por defecto para evitar bloqueo accidental; se habilita desde Configuración."
      },
      {
        title: "12. Alertas de usuario",
        body: "Cuando falta alcance de análisis, nombre de fuente, datos de usuario, contraseña fuerte o código MFA, la app muestra una alerta específica con causa y acción esperada. La intención es evitar pantallas silenciosas o botones que no expliquen por qué no avanzan."
      },
      {
        title: "13. Progreso, programación y reportes",
        body: "Estado de corrida muestra porcentaje, ETA, checks de fuentes y advertencias de TOR/dark web/sidecars. El tiempo máximo de corrida ajusta profundidad, registros y timeouts sin evadir controles de terceros; el backend continúa aunque cierre sesión. Los informes se generan solo por solicitud y el técnico conserva URLs completas."
      },
      {
        title: "14. Monitoreo 24/7, logs y soporte",
        body: "Un perfil activo conserva alcance, ventana, fuentes, TOR autorizado y tiempo máximo de recolección. El worker de backend lanza ciclos, procesa resultados, evita alertas duplicadas con fingerprint criptográfico de señal/URL/categoría y registra fallas en bitácora. El usuario puede crear tickets de soporte; el superadmin ve logs, estado de alertas y tickets sin detener los análisis."
      }
    ]
  },
  en: {
    title: "Platform Usage",
    subtitle: "Quick guide to read CyberDecisionEngine and turn findings into decisions.",
    modelTitle: "Analytical model",
    modelSubtitle: "CyberDecisionEngine does not invent evidence: it separates source, transformation, calculation and interpretation.",
    originTitle: "Origin and purpose",
    originBody:
      "CyberDecisionEngine was created by Edwin Peñuela as a strategic cyberintelligence model for actionable decision-making. The approach has been developed since 2022 and combines defensive intelligence, risk analysis, fraud, posture, compliance and preventive prediction for organizations.",
    moduleTitle: "Menus and dashboard reading",
    moduleSubtitle: "Each menu answers a different decision question. Dashboards display evidence, not invented data.",
    theoryTitle: "Applied theories, models and frameworks",
    theorySubtitle: "Conceptual basis used to interpret signals and convert them into risk, scenarios and recommendations.",
    sections: [
      {
        icon: Radar,
        title: "Strategic Dashboard",
        body: "Centralizes posture, risk radar, heatmap, forecast, PESTEL, Porter and TTPs. Start here for executive prioritization."
      },
      {
        icon: BrainCircuit,
        title: "Decision Scenarios",
        body: "Crosses domain evidence with ATT&CK, D3FEND, ATLAS and DISARM to show actionable possibilities by domain and group, without asserting unevidenced events."
      },
      {
        icon: Bot,
        title: "Strategic AI",
        body: "Builds a master prompt, exact context, multi-AI payloads and OpenClaw proposals for augmented analysis. It does not run external automations until the draft is approved."
      },
      {
        icon: Crosshair,
        title: "Attack Surface",
        body: "Checks DNS, RDAP/WHOIS and TLS certificates for owned and declared competitor domains. High risk means technical friction to review, not confirmed exploitation."
      },
      {
        icon: Fingerprint,
        title: "Brand & Fraud",
        body: "Organizes mentions, news, phrase sentiment, reputation impact and similar domains observed in URLs for prevention, communications, fraud and takedown."
      },
      {
        icon: Users,
        title: "Employee Risk",
        body: "Runs the authorized employee public-exposure OSINT model with human review and downloadable HTML output."
      },
      {
        icon: MessageSquareWarning,
        title: "Disinformation",
        body: "Maps public signals, narratives and influence behavior with DISARM. If no evidence exists, the board remains empty."
      },
      {
        icon: FileSearch,
        title: "OSINT",
        body: "Shows open results, defensive dork-style queries and URL-level evidence. Use it to discover actionable exposure an adversary could observe."
      },
      {
        icon: Network,
        title: "SOCMINT",
        body: "Shows public mention networks, nodes, relationships and trend behavior. If no data exists, the board remains empty to avoid invented information."
      },
      {
        icon: LockKeyhole,
        title: "Dark Web",
        body: "Uses public indexes, authorized imports and redacted metadata. It does not interact with markets, buy data or download payloads."
      },
      {
        icon: GitBranch,
        title: "Framework Mapping",
        body: "Maps findings to NIST, ISO 27001, PCI DSS, SOC 2, GDPR, MITRE ATT&CK, D3FEND and ATLAS to explain affected controls and remediation decisions."
      },
      {
        icon: FileClock,
        title: "Reports",
        body: "Produces executive and technical outputs. Executive focuses on decisions; technical keeps evidence, sources, methodology and traceability."
      },
      {
        icon: ShieldAlert,
        title: "24/7 Monitoring",
        body: "Creates persistent profiles with per-cycle duration or indefinite collection. The platform collects, deduplicates and creates internal alerts; reports are generated only on request."
      },
      {
        icon: Settings2,
        title: "Settings",
        body: "Centralizes sources, APIs, users, access and the operational connector coverage of the selected run. Coverage describes collection capability, not organizational risk or the absence of threats."
      }
    ],
    modules: [
      {
        icon: Radar,
        title: "Strategic Dashboard",
        focus: "Executive view to decide quickly: what risk is rising, where it impacts and what should be prioritized.",
        boards: [
          "Executive radar and heatmap: severity by cyber-risk type.",
          "Early warning: relative signal pressure by modality, TTP, sector and time window.",
          "PESTEL and Porter: external and competitive strategic reading.",
          "Threat graph and news: relationships between actors, TTP, actions and recent evidence.",
          "Scope, geography, sector and sources: real context from the run."
        ]
      },
      {
        icon: BrainCircuit,
        title: "Decision Scenarios",
        focus: "Shows which scenarios apply to the analyzed domain or group and which decision possibilities open.",
        boards: [
          "Domain reading: filters scenarios by one, many or all domains.",
          "Framework map: ATT&CK, D3FEND, ATLAS and DISARM presence.",
          "Scenario cards: evidence, criterion, executive question, decision possibility and related domains."
        ]
      },
      {
        icon: Bot,
        title: "Strategic AI",
        focus: "Prepares augmented analysis for current models with controlled context, token limits and anti-hallucination rules.",
        boards: [
          "AI providers: select OpenAI, Azure OpenAI, Anthropic, Gemini, Mistral, a local compatible endpoint or OpenClaw Gateway.",
          "Token budget: estimates input/output to avoid oversized prompts.",
          "Master prompt and payloads: preserves system, user, JSON schema, evidence manifest and automation policy before approval."
        ]
      },
      {
        icon: Crosshair,
        title: "Attack Surface",
        focus: "Passive technical exposure review: DNS, RDAP/WHOIS, TLS and declared comparison.",
        boards: ["Domain inventory", "Certificates and expiration signals", "Owned vs competitor comparison"]
      },
      {
        icon: Fingerprint,
        title: "Brand & Fraud",
        focus: "Organizes public mentions, fraud, brand abuse and reputation signals.",
        boards: [
          "Phrase and domain sentiment: positive, neutral or negative based on collected evidence.",
          "Reputation impact: decision indicator calculated from negative, dark web and SOCMINT signals.",
          "Observed similar domains: URL-level evidence to validate typosquatting, 0/o, 1/l substitutions or other similarities.",
          "Mentions and URLs: where the brand, group, conglomerate or domain appears."
        ]
      },
      {
        icon: Users,
        title: "Employee Virtual Risk",
        focus: "Runs the authorized OSINT employee model for one person or a structured batch file.",
        boards: ["Individual form", "Batch upload", "Downloadable module report"]
      },
      {
        icon: MessageSquareWarning,
        title: "Disinformation",
        focus: "Analyzes narratives, influence signals and DISARM mapping when public evidence exists.",
        boards: ["DISARM pulse", "Narrative risk", "Narrative-domain-brand mapping"]
      },
      {
        icon: FileSearch,
        title: "OSINT",
        focus: "Shows open results and defensive searches that evidence actionable exposure.",
        boards: ["URL-by-URL results", "Defensive dorks", "Domain evidence"]
      },
      {
        icon: Network,
        title: "SOCMINT",
        focus: "Reads public mentions and relationships as node-edge networks when data exists.",
        boards: ["Mention network", "Trends", "Related public entities when available"]
      },
      {
        icon: LockKeyhole,
        title: "Dark Web",
        focus: "Safe passive review of indexes, authorized imports and redacted metadata.",
        boards: ["Leak or credential signals", "Source status", "Operational risk without unsafe interaction"]
      },
      {
        icon: GitBranch,
        title: "Framework Mapping",
        focus: "Translates findings into controls, affected aspects and remediation decisions.",
        boards: ["NIST, ISO, PCI, SOC 2, GDPR", "MITRE ATT&CK/D3FEND/ATLAS", "Expandable evidence and decision detail"]
      },
      {
        icon: FileClock,
        title: "Reports and History",
        focus: "Reviews runs, downloads executive/technical reports and keeps traceability.",
        boards: [
          "Run history",
          "Executive and technical reports without long formulas in the output.",
          "Scheduling: periodic reviews for default domains or current scope.",
          "Sources, users, language and theme configuration"
        ]
      },
      {
        icon: ShieldAlert,
        title: "24/7 Monitoring and support",
        focus: "Enables persistent collection for an authorized brand, group or domain set without automatic report generation.",
        boards: [
          "Profiles: cadence, max duration per cycle, last completion, next execution and pause/resume.",
          "Alerts: new signals deduplicated by evidence fingerprint; acknowledge, close or mark false positive.",
          "Operational log: launches, completions, collector failures, timeouts and support events.",
          "Support: users report visible failures and the super admin reviews them as operational tickets."
        ]
      },
      {
        icon: Settings2,
        title: "Settings and connectors",
        focus: "Manages sources, access and operating capability without mixing it with analysis findings.",
        boards: [
          "Operational connector coverage: status, records and update time for the selected run.",
          "Sources and APIs: connector enablement and secret references without exposing credentials.",
          "Users and access: roles, MFA, licensing and effective permissions.",
          "Correct reading: a connector with no data is not an observed zero or proof of no risk."
        ]
      },
      {
        icon: ShieldAlert,
        title: "Governance and licensing",
        focus: "Operates the platform by company, plan, user, modular access and audit trail.",
        boards: [
          "Companies: tree structure for groups, subsidiaries or clients.",
          "Licenses: company plan, seats, expiration, status and modules.",
          "Users: role, assigned plan, effective modules and change log."
        ]
      },
      {
        icon: LockKeyhole,
        title: "Access security",
        focus: "Controls local authentication, temporary MFA, failed-attempt lockout and password reset.",
        boards: [
          "MFA: admin generates a temporary two-factor code per user.",
          "Lockout: five failed attempts lock the account for a time window.",
          "Reset: admin issues a temporary password and the user must change it after login."
        ]
      }
    ],
    theories: [
      {
        title: "Intelligence cycle",
        body: "Uses direction, collection, processing, analysis, dissemination and feedback; dashboards separate source, evidence, calculation and executive reading."
      },
      {
        title: "ISO/NIST risk",
        body: "Combines contextual plausibility, impact, exposure, applicable vulnerabilities, declared controls and residual risk to prioritize treatment without turning public signals into certainty."
      },
      {
        title: "PESTEL and Porter strategy",
        body: "PESTEL interprets external pressure; Porter reads competitive forces, third parties, substitutes and sector pressure."
      },
      {
        title: "MITRE + DISARM",
        body: "ATT&CK models adversary behavior, D3FEND defensive controls, ATLAS AI risk and DISARM narratives/influence. Scenarios activate only when evidence matches."
      },
      {
        title: "Controlled augmented AI",
        body: "AI analysis uses only the compressed run context, anti-hallucination rules, an evidence manifest and human approval before any external automation. OpenClaw is used as a proposal gateway/assistant, not as unrestricted execution."
      },
      {
        title: "Graph intelligence",
        body: "Nodes represent actors, signals, topics or platforms; edges represent observed relationships. No relationships means no network is drawn."
      },
      {
        title: "Preventive prediction",
        body: "Bounded logistic scoring, declared-control weighting, Monte Carlo and sensitivity analysis support decisions. Missing inputs are shown as unassessed."
      },
      {
        title: "Brand, reputation and similarity",
        body: "Brand analysis calculates phrase sentiment and reputation from real evidence. Domain similarity is shown as validation-required evidence, not confirmed fraud."
      },
      {
        title: "SaaS governance and least privilege",
        body: "Licensing uses a company-user hierarchy, explicit modules and an audit trail. Access is calculated from role, user plan, company license and controlled overrides."
      },
      {
        title: "Local access security",
        body: "Desktop/lab mode applies temporary MFA, failed-attempt lockout, session expiration and admin reset. Production should move this to backend/IAM with real MFA, strong hashing, salting, central audit and secure recovery."
      },
      {
        title: "Guided alerts",
        body: "Forms explain what is missing, where it is missing and why it blocks the action. If a source is not configured or returns no data, the platform shows status instead of inventing results."
      },
      {
        title: "Continuous monitoring and deduplication",
        body: "24/7 monitoring uses persistent backend profiles. Each cycle generates new data, compares evidence fingerprints against what was already seen and alerts only non-duplicated signals. Runs remain dashboard-ready; HTML reports remain manual."
      }
    ],
    model: [
      {
        title: "1. Ingestion and traceability",
        body: "Every signal must come from a configured source: OSINT, public SOCMINT, authorized dark web indexes, RDAP/WHOIS, TLS, MITRE or frameworks. The selected time window filters evidence and is recorded in the report. If a source returns no records, the board remains empty or shows source status instead of inventing data."
      },
      {
        title: "2. Public search and scope",
        body: "Domain scope has priority over group name: when a specific domain exists, queries are generated from that domain and derived aliases. OSINT/SOCMINT uses configurable APIs when available and a conservative public fallback without block evasion; if a source returns 403/429, it is recorded and stopped for that run. Dark Web is limited to public indexes, redacted imports and authorized sources."
      },
      {
        title: "3. Contextual risk",
        body: "Contextual plausibility uses a bounded logistic function. It only combines supported activity, exposure, applicable vulnerabilities and declared controls; it is not a calibrated attack probability."
      },
      {
        title: "4. Impact and residual",
        body: "Inherent risk = contextual plausibility x impact. Residual risk = inherent x (1 - declared control effectiveness), bounded to avoid impossible values."
      },
      {
        title: "5. Defensive forecast",
        body: "Early warning uses a non-calibrated signal-pressure index: SPI(t)=1-e^(-r*t). r only increases with direct or validated evidence, applicable CVEs and declared context; it does not estimate attack probability."
      },
      {
        title: "6. Uncertainty",
        body: "Monte Carlo simulates variation in contextual plausibility, impact and declared controls with beta distributions. Reports expose p10, p50 and p90 as a sensitivity interval, not a confirmed forecast."
      },
      {
        title: "7. Strategy",
        body: "PESTEL explains external pressure; Porter explains competitive forces; Framework Mapping translates findings into NIST, ISO, PCI, SOC, GDPR, ATT&CK, D3FEND and ATLAS controls."
      },
      {
        title: "8. Advanced scenarios",
        body: "The scenario library crosses ATT&CK, D3FEND, ATLAS, DISARM, PESTEL, Porter, reputation risk and continuity to generate preventive scenarios that activate only when matched to evidence."
      },
      {
        title: "9. Licensing and audit",
        body: "The super admin manages companies and licenses; the company admin manages operational users. Effective access = role + modules from user plan or company license + authorized overrides. Every critical change creates an audit event for security, support and commercial traceability."
      },
      {
        title: "10. Strategic AI and tokens",
        body: "The AI package selects evidence by risk and recency: highest residual-risk findings first, then recent events and source diversity. Estimated tokens approximate characters/4 and lower-priority evidence is omitted before conclusions are changed. OpenClaw can receive the same context as an analysis/scheduling proposal, without tools or commands until approval."
      },
      {
        title: "11. Access, MFA and recovery",
        body: "Login validates required fields, account lockout, credentials and MFA. Admin can generate a temporary MFA code, reset password, unlock users and require password change. Seed accounts do not enable MFA by default to avoid accidental lockout; it is enabled from Settings."
      },
      {
        title: "12. User alerts",
        body: "When analysis scope, source name, user data, strong password or MFA code is missing, the app shows a specific alert with cause and expected action. This avoids silent screens or buttons that do not explain why they cannot proceed."
      },
      {
        title: "13. Progress, scheduling and reports",
        body: "Run status shows percentage, ETA, source checks and TOR/dark web/sidecar warnings. The run time limit tunes depth, records and timeouts without bypassing third-party controls; the backend continues if the session closes. Reports are generated only by request and the technical report keeps complete URLs."
      },
      {
        title: "14. 24/7 monitoring, logs and support",
        body: "An active profile keeps scope, time window, sources, authorized TOR and max collection duration. The backend worker launches cycles, processes results, prevents duplicated alerts with a cryptographic fingerprint of signal/URL/category and records failures in the operational log. Users can create support tickets; the super admin can review logs, alert status and tickets without stopping analyses."
      }
    ]
  }
};

export function UsageGuideView({ language, role }: { language: LanguageMode; role: UserRole }) {
  const copy = content[language];
  return (
    <div className="view-stack">
      <section className="platform-help-hero panel">
        <BookOpen size={24} />
        <div>
          <span>CyberDecisionEngine</span>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
      </section>
      <section className="panel origin-card">
        <ShieldAlert size={22} />
        <div>
          <h2>{copy.originTitle}</h2>
          <p>{copy.originBody}</p>
          <a
            className="manual-open-link"
            href="/docs/Manual_Plataforma_Ciberinteligencia.html"
            target="_blank"
            rel="noreferrer"
          >
            <BookOpen size={16} />
            {language === "es" ? "Abrir manual integral" : "Open full manual"}
            <ExternalLink size={14} />
          </a>
          <a
            className="manual-open-link secondary"
            href="/docs/Guia_Despliegue_y_Operacion.html"
            target="_blank"
            rel="noreferrer"
          >
            <BookOpen size={16} />
            {language === "es" ? "Abrir guía de despliegue y operación" : "Open deployment and operations guide"}
            <ExternalLink size={14} />
          </a>
        </div>
      </section>
      <section className="panel chart-card module-guide">
        <div className="panel-title-row compact">
          <div>
            <h2>{copy.moduleTitle}</h2>
            <p>{copy.moduleSubtitle}</p>
          </div>
        </div>
        <div className="module-guide-grid">
          {copy.modules.map((module) => (
            <article key={module.title}>
              <module.icon size={20} />
              <div>
                <h3>{module.title}</h3>
                <p>{module.focus}</p>
              </div>
              <ul>
                {module.boards.map((board) => (
                  <li key={board}>{board}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>
      <section className="panel chart-card theory-guide">
        <div className="panel-title-row compact">
          <div>
            <h2>{copy.theoryTitle}</h2>
            <p>{copy.theorySubtitle}</p>
          </div>
          <GitBranch size={18} />
        </div>
        <div className="theory-grid">
          {copy.theories.map((theory) => (
            <article key={theory.title}>
              <strong>{theory.title}</strong>
              <p>{theory.body}</p>
            </article>
          ))}
        </div>
      </section>
      {["super_admin", "admin"].includes(role) ? (
        <section className="panel chart-card model-explainer">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.modelTitle}</h2>
              <p>{copy.modelSubtitle}</p>
            </div>
          </div>
          <div className="model-explainer-grid">
            {copy.model.map((item) => (
              <article key={item.title}>
                <strong>{item.title}</strong>
                <p>{item.body}</p>
              </article>
            ))}
          </div>
          <FormulaGallery language={language} />
        </section>
      ) : null}
    </div>
  );
}

function FormulaGallery({ language }: { language: LanguageMode }) {
  const [methods, setMethods] = useState<MethodologyRecord[]>([]);
  const [registryVersion, setRegistryVersion] = useState("");
  const [error, setError] = useState(false);

  useEffect(() => {
    let mounted = true;
    getMethodologyRegistry()
      .then((registry) => {
        if (!mounted) return;
        setMethods(registry.methods);
        setRegistryVersion(registry.registryVersion);
      })
      .catch(() => {
        if (mounted) setError(true);
      });
    return () => {
      mounted = false;
    };
  }, []);

  if (error) {
    return <div className="empty-state">{language === "es" ? "No fue posible cargar el registro metodológico." : "The methodology registry could not be loaded."}</div>;
  }
  if (!methods.length) {
    return <div className="module-loading" role="status">{language === "es" ? "Cargando metodología versionada..." : "Loading versioned methodology..."}</div>;
  }

  const statusLabel = {
    active: language === "es" ? "Activo" : "Active",
    reference_only: language === "es" ? "Solo referencia" : "Reference only",
    inactive: language === "es" ? "Inactivo" : "Inactive"
  };
  const activeMethods = methods.filter((method) => method.status === "active");
  const referenceMethods = methods.filter((method) => method.status !== "active");
  return (
    <div>
      <p className="methodology-version">
        {language === "es" ? "Modelos activos en producción" : "Active production models"} · {language === "es" ? "registro" : "registry"} v{registryVersion}
      </p>
      <div className="formula-visual-grid methodology-registry-grid">
        {activeMethods.map((method) => (
          <article className={`math-card ${method.formula.length > 75 ? "formula-wide" : ""}`.trim()} key={method.methodId}>
            <div className="methodology-card-heading">
              <div>
                <strong>{method.name[language]}</strong>
                <small>{method.methodId} · v{method.version}</small>
              </div>
              <span className={`methodology-status ${method.status}`}>{statusLabel[method.status]}</span>
            </div>
            <BookFormula methodId={method.methodId} fallback={method.formula} />
            <p>{method.interpretation[language]}</p>
            <dl className="methodology-details">
              <div><dt>{language === "es" ? "Rango" : "Range"}</dt><dd>{method.outputRange}</dd></div>
              <div><dt>{language === "es" ? "Datos faltantes" : "Missing data"}</dt><dd>{method.missingDataPolicy}</dd></div>
              <div><dt>{language === "es" ? "Ejemplo" : "Example"}</dt><dd>{method.example}</dd></div>
            </dl>
          </article>
        ))}
      </div>
      {referenceMethods.length ? (
        <details className="methodology-archive">
          <summary>{language === "es" ? "Referencias no utilizadas en los resultados" : "References not used in results"}</summary>
          <p>
            {language === "es"
              ? "Se conservan por trazabilidad metodológica. No alimentan porcentajes, tableros ni informes actuales. PESTEL y Porter se calculan exclusivamente con el modelo activo de presión estratégica basado en evidencia."
              : "They are retained for methodological traceability. They do not feed current percentages, dashboards or reports. PESTEL and Porter are calculated exclusively by the active evidence-based strategic-pressure model."}
          </p>
          <div className="methodology-reference-list">
            {referenceMethods.map((method) => (
              <div key={method.methodId}>
                <strong>{method.name[language]}</strong>
                <span>{statusLabel[method.status]} · {method.interpretation[language]}</span>
              </div>
            ))}
          </div>
        </details>
      ) : null}
    </div>
  );
}

function BookFormula({ methodId, fallback }: { methodId: string; fallback: string }) {
  const formulas: Record<string, ReactNode> = {
    "risk.threat_activity": (
      <mrow><mi>T</mi><mo>=</mo><mi>clip</mi><mo>(</mo><mn>1</mn><mo>−</mo><msup><mi>e</mi><mrow><mo>−</mo><mn>0.35</mn><mo>∑</mo><msub><mi>w</mi><mi>s</mi></msub><mi>c</mi><msup><mi>e</mi><mrow><mo>−</mo><mi>ln</mi><mo>(</mo><mn>2</mn><mo>)</mo><mi>a</mi><mo>/</mo><mi>h</mi></mrow></msup></mrow></msup><mo>,</mo><mn>0</mn><mo>,</mo><mn>1</mn><mo>)</mo></mrow>
    ),
    "risk.contextual_likelihood": (
      <mrow><mi>L</mi><mo>=</mo><mi>σ</mi><mo>(</mo><mo>−</mo><mn>2.10</mn><mo>+</mo><mn>0.70</mn><mi>A</mi><mo>+</mo><mn>0.85</mn><mi>E</mi><mo>+</mo><mn>0.75</mn><mi>V</mi><mo>+</mo><mn>0.90</mn><mfrac><mrow><mi>logit</mi><mo>(</mo><mi>P</mi><mo>)</mo></mrow><mn>6</mn></mfrac><mo>+</mo><mn>0.85</mn><mi>K</mi><mo>+</mo><mn>0.70</mn><mi>T</mi><mo>+</mo><mn>0.55</mn><mi>S</mi><mo>+</mo><mn>0.35</mn><mi>G</mi><mo>−</mo><mn>0.80</mn><mi>C</mi><mo>−</mo><mn>0.60</mn><mi>D</mi><mo>−</mo><mn>0.45</mn><mi>R</mi><mo>)</mo></mrow>
    ),
    "risk.business_impact": (
      <mrow><mi>I</mi><mo>=</mo><mi>clip</mi><mo>(</mo><mn>0.25</mn><mi>F</mi><mo>+</mo><mn>0.20</mn><mi>O</mi><mo>+</mo><mn>0.20</mn><mi>C</mi><mo>+</mo><mn>0.15</mn><mi>In</mi><mo>+</mo><mn>0.10</mn><mi>A</mi><mo>+</mo><mn>0.05</mn><mi>L</mi><mo>+</mo><mn>0.05</mn><mi>R</mi><mo>,</mo><mn>0</mn><mo>,</mo><mn>1</mn><mo>)</mo></mrow>
    ),
    "risk.control_effectiveness": (
      <mrow><mi>CE</mi><mo>=</mo><mi>clip</mi><mo>(</mo><mn>0.25</mn><mi>ISO</mi><mo>+</mo><mn>0.25</mn><mi>NIST</mi><mo>+</mo><mn>0.15</mn><mi>SOC2</mi><mo>+</mo><mn>0.15</mn><mi>D3FEND</mi><mo>+</mo><mn>0.10</mn><mi>Detection</mi><mo>+</mo><mn>0.10</mn><mi>IR</mi><mo>,</mo><mn>0</mn><mo>,</mo><mn>1</mn><mo>)</mo></mrow>
    ),
    "risk.inherent": (
      <mrow><msub><mi>R</mi><mtext>inherente</mtext></msub><mo>=</mo><mn>100</mn><mo>·</mo><mi>clip</mi><mo>(</mo><mi>L</mi><mo>)</mo><mo>·</mo><mi>clip</mi><mo>(</mo><mi>I</mi><mo>)</mo></mrow>
    ),
    "risk.residual": (
      <mrow><msub><mi>R</mi><mtext>residual</mtext></msub><mo>=</mo><mi>max</mi><mo>(</mo><mn>0</mn><mo>,</mo><msub><mi>R</mi><mtext>inherente</mtext></msub><mo>)</mo><mo>·</mo><mo>[</mo><mn>1</mn><mo>−</mo><mi>min</mi><mo>(</mo><mn>0.85</mn><mo>,</mo><mi>clip</mi><mo>(</mo><mi>CE</mi><mo>)</mo><mo>)</mo><mo>]</mo></mrow>
    ),
    "risk.monte_carlo": (
      <mrow><msub><mi>R</mi><mi>i</mi></msub><mo>=</mo><mn>100</mn><mo>·</mo><mi>Beta</mi><mo>(</mo><mi>L</mi><mo>)</mo><mo>·</mo><mi>Beta</mi><mo>(</mo><mi>I</mi><mo>)</mo><mo>·</mo><mo>[</mo><mn>1</mn><mo>−</mo><mi>min</mi><mo>(</mo><mn>0.85</mn><mo>,</mo><mi>Beta</mi><mo>(</mo><mi>CE</mi><mo>)</mo><mo>)</mo><mo>]</mo></mrow>
    ),
    "strategy.pestel_porter_pressure": (
      <mtable>
        <mtr><mtd><msub><mi>q</mi><mi>i</mi></msub></mtd><mtd><mo>=</mo></mtd><mtd><mn>.18</mn><mi>M</mi><mo>+</mo><mn>.16</mn><mi>Q</mi><mo>+</mo><mn>.10</mn><mi>R</mi><mo>+</mo><mn>.16</mn><mi>D</mi><mo>+</mo><mn>.08</mn><mi>N</mi><mo>+</mo><mn>.12</mn><mi>C</mi><mo>+</mo><mn>.10</mn><mi>X</mi><mo>+</mo><mn>.10</mn><mi>G</mi></mtd></mtr>
        <mtr><mtd><msub><mi>m</mi><mi>d</mi></msub></mtd><mtd><mo>=</mo></mtd><mtd><mo>∑</mo><msub><mi>q</mi><mi>i</mi></msub><mo>·</mo><msub><mi>magnitud</mi><mi>i</mi></msub></mtd></mtr>
        <mtr><mtd><msub><mi>S</mi><mi>d</mi></msub></mtd><mtd><mo>=</mo></mtd><mtd><mn>100</mn><mo>[</mo><mn>.65</mn><msub><mi>cobertura</mi><mi>d</mi></msub><mo>+</mo><mn>.20</mn><msub><mi>directitud</mi><mi>d</mi></msub><mo>+</mo><mn>.15</mn><mi>min</mi><mo>(</mo><mn>1</mn><mo>,</mo><msub><mi>n</mi><mi>d</mi></msub><mo>/</mo><mn>4</mn><mo>)</mo><mo>]</mo></mtd></mtr>
      </mtable>
    )
  };
  const expression = formulas[methodId];
  return expression ? (
    <div className="math-expression methodology-formula book-formula" title={fallback}>
      <math display="block" aria-label={fallback}>{expression}</math>
    </div>
  ) : <div className="math-expression methodology-formula">{fallback}</div>;
}
