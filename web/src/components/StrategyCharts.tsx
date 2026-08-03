import { Activity, BrainCircuit, ExternalLink, Flame, Newspaper, ShieldCheck } from "lucide-react";
import type { LanguageMode } from "../types";
import type { AttackPredictionModel, PosturePoint, RiskHeatRow, StrategyLens } from "../utils/dashboard";

const strategyCopy = {
  es: {
    index: "índice",
    noHeat: "Sin datos de calor de riesgo disponibles.",
    noRadar: "Sin datos de radar de riesgo disponibles.",
    radarAria: "Radar ejecutivo de ciberriesgo",
    primaryRisk: "Riesgo principal",
    averageRisk: "Promedio",
    criticalItems: "Críticos",
    evidenceSignals: "Señales",
    priorityMap: "Prioridad de decisión",
    noActiveRisk: "Sin riesgo activo",
    runToPopulate: "Ejecuta un análisis para poblar el modelo de riesgo.",
    noPrediction: "No se puede calcular presión hasta que la corrida tenga evidencia directa o validada.",
    predictiveModel: "Índice prospectivo de presión",
    noLeading: "Sin escenario líder disponible",
    confidence: "Confianza de evidencia",
    attackProbability: "Probabilidad de ataque",
    notCalibrated: "N/D · modelo no calibrado",
    trend: "Tendencia",
    rising: "En aumento",
    stable: "Estable",
    falling: "En descenso",
    insufficient_evidence: "Evidencia insuficiente",
    horizon: "Horizonte",
    scenarioSupport: "Respaldo",
    signals: "señales",
    posture: "Índice de postura externa",
    postureEmpty: "Sin controles externos evaluados en esta corrida.",
    via: "por",
    unassessed: "Sin evidencia suficiente para publicar presión organizacional. La ausencia de score no equivale a presión baja.",
    pressure: "Intensidad de señal",
    confidenceLabel: "Confianza",
    coverage: "Dimensiones evaluadas",
    evidenceCoverage: "Cobertura de evidencia",
    clusters: "clústeres",
    articles: "registros",
    changed: "Cambio",
    evidence: "Evidencia",
    timeline: "Evolución por ventana",
    days: "días",
    noScore: "N/D",
    analysisBasis: "Contexto considerado",
    declaredCoverage: "Cobertura del contexto declarado",
    currentRunOnly: "Solo evidencia de esta corrida",
    calculationBasis: "Base numérica trazable",
    evidenceMass: "Masa de evidencia",
    direction: "Índice direccional",
    directness: "Relación directa",
    agreement: "Concordancia",
    extraction: "Calidad de extracción",
    publicationGate: "Umbral de publicación",
    passed: "cumplido",
    notPassed: "en revisión"
  },
  en: {
    index: "index",
    noHeat: "No risk heat data available.",
    noRadar: "No risk radar data available.",
    radarAria: "Executive cyber risk radar",
    primaryRisk: "Primary risk",
    averageRisk: "Average",
    criticalItems: "Critical",
    evidenceSignals: "Signals",
    priorityMap: "Decision priority",
    noActiveRisk: "No active risk",
    runToPopulate: "Run analysis to populate the risk model.",
    noPrediction: "Pressure cannot be calculated until the run has direct or validated evidence.",
    predictiveModel: "Prospective pressure index",
    noLeading: "No leading scenario available",
    confidence: "Evidence confidence",
    attackProbability: "Attack probability",
    notCalibrated: "N/A · model not calibrated",
    trend: "Trend",
    rising: "Rising",
    stable: "Stable",
    falling: "Falling",
    insufficient_evidence: "Insufficient evidence",
    horizon: "Horizon",
    scenarioSupport: "Support",
    signals: "signals",
    posture: "External posture index",
    postureEmpty: "No external controls were assessed in this run.",
    via: "via",
    unassessed: "Insufficient evidence to publish organizational pressure. No score does not mean low pressure.",
    pressure: "Signal intensity",
    confidenceLabel: "Confidence",
    coverage: "Assessed dimensions",
    evidenceCoverage: "Evidence coverage",
    clusters: "clusters",
    articles: "records",
    changed: "Change",
    evidence: "Evidence",
    timeline: "Window evolution",
    days: "days",
    noScore: "N/A",
    analysisBasis: "Context considered",
    declaredCoverage: "Declared-context coverage",
    currentRunOnly: "Current-run evidence only",
    calculationBasis: "Traceable numeric basis",
    evidenceMass: "Evidence mass",
    direction: "Direction index",
    directness: "Direct relationship",
    agreement: "Agreement",
    extraction: "Extraction quality",
    publicationGate: "Publication threshold",
    passed: "passed",
    notPassed: "under review"
  }
};

const analyticText: Record<LanguageMode, Record<string, string>> = {
  es: {
    "Modelo de presion estrategica contextual basado en clusters de noticias relacionados y trazables. No mide riesgo, probabilidad de ataque, cumplimiento ni madurez.": "Modelo de presión estratégica contextual basado en clústeres de noticias relacionados y trazables. No mide riesgo, probabilidad de ataque, cumplimiento ni madurez.",
    "No hay evidencia suficiente para calcular esta dimension en la ventana analizada.": "No hay evidencia suficiente para calcular esta dimensión en la ventana analizada.",
    "Insufficient directly related evidence in the current 30-day window.": "Evidencia directa relacionada insuficiente en la ventana actual de 30 días.",
    "Politico": "Político",
    "Economico": "Económico",
    "Tecnologico": "Tecnológico",
    "Economico/Fraude": "Económico/Fraude",
    "Social/Ing. social": "Social/Ingeniería social",
    "Ambiental/Continuidad": "Ambiental/Continuidad",
    "Legal/Regulatorio": "Legal/Regulatorio",
    direct: "directa",
    group: "grupo",
    supplier: "proveedor",
    sector: "sector",
    global: "global",
    increase: "aumenta",
    decrease: "reduce",
    low: "baja",
    medium: "media",
    high: "alta",
    critical: "crítica",
    "Credential targeting / phishing": "Ataque a credenciales / phishing",
    "Public application exploitation": "Explotacion de aplicaciones publicas",
    "Ransomware / extortion pressure": "Presion ransomware / extorsion",
    "Data exposure / leak narrative": "Exposicion de datos / narrativa de fuga",
    "Brand abuse / impersonation": "Abuso de marca / suplantacion",
    "Supply chain or AI-enabled abuse": "Cadena de suministro o abuso habilitado por IA",
    "Prioritize anti-phishing, brand takedown, MFA resistance and customer communications.": "Priorizar anti-phishing, takedown de marca, MFA resistente y comunicacion a clientes.",
    "Prioritize exposed asset validation, KEV patching, WAF rules and exploit telemetry.": "Priorizar validacion de activos expuestos, patching KEV, reglas WAF y telemetria de explotacion.",
    "Validate backup restore, segmentation, EDR coverage, crisis comms and extortion monitoring.": "Validar restauracion de backups, segmentacion, cobertura EDR, comunicacion de crisis y monitoreo de extorsion.",
    "Validate data exposure evidence, legal notification path and takedown workflow.": "Validar evidencia de exposicion de datos, ruta legal de notificacion y flujo de takedown.",
    "Increase brand monitoring, takedown SLAs and fraud operations coordination.": "Incrementar monitoreo de marca, SLA de takedown y coordinacion con operaciones de fraude.",
    "Review third-party exposure, SBOM/SCA, AI governance and high-risk integrations.": "Revisar exposicion de terceros, SBOM/SCA, gobierno de IA e integraciones de alto riesgo.",
    "Frequency": "Frecuencia",
    "Last days": "Ultimos dias",
    "Sector": "Sector",
    "Risk heat": "Calor de riesgo",
    "Control gap": "Brecha de control",
    "Public social signal pressure": "Presion de senales sociales publicas",
    "Authorized dark web or ransomware-index signal pressure": "Presion de dark web autorizada o indices ransomware",
    "Highest risk heat row from the report": "Fila de mayor calor de riesgo del informe",
    "Average control gap from report control scores": "Brecha promedio de controles desde el informe",
    "Share of signals observed during the last 7 days": "Proporcion de senales observadas durante los ultimos 7 dias",
    "Exploit, vulnerability, KEV or CVE evidence density": "Densidad de evidencia de exploit, vulnerabilidad, KEV o CVE",
    "Current analysis sector": "Sector del analisis actual",
    "current sector": "sector actual",
    "unattributed": "sin atribucion",
    "Non-calibrated signal-pressure index based on direct or validated evidence, recency, applicable vulnerabilities, declared sector context, SOCMINT, Dark Web and calculated risk. It is not an attack probability.": "Indice no calibrado de presion basado en evidencia directa o validada, recencia, vulnerabilidades aplicables, contexto sectorial declarado, SOCMINT, Dark Web y riesgo calculado. No es una probabilidad de ataque."
  },
  en: {
    "Modelo de presion estrategica contextual basado en clusters de noticias relacionados y trazables. No mide riesgo, probabilidad de ataque, cumplimiento ni madurez.": "Contextual strategic-pressure model based on related, traceable news clusters. It does not measure risk, attack probability, compliance, or maturity.",
    "No hay evidencia suficiente para calcular esta dimension en la ventana analizada.": "There is insufficient evidence to calculate this dimension in the analyzed window.",
    "Geopolítica, política pública y amenaza estatal": "Geopolitics, public policy and state threat",
    "Economía digital, fraude y presión financiera": "Digital economy, fraud and financial pressure",
    "Factor humano, confianza digital y manipulación social": "Human factors, digital trust and social manipulation",
    "Dependencia tecnológica, vulnerabilidades y superficie de ataque": "Technology dependency, vulnerabilities and attack surface",
    "Resiliencia física, energética, ambiental y continuidad digital": "Physical, energy and environmental resilience and digital continuity",
    "Regulación, privacidad, cumplimiento y responsabilidad cibernética": "Regulation, privacy, compliance and cyber liability",
    "Rivalidad digital y presión competitiva de ciberseguridad": "Digital rivalry and competitive cybersecurity pressure",
    "Nuevos entrantes digitales y expansión de la superficie de ataque": "New digital entrants and attack-surface expansion",
    "Poder y dependencia cibernética de proveedores y terceros": "Cyber power and dependency of suppliers and third parties",
    "Poder y exigencia de seguridad de clientes, aliados y canales": "Security power and demands of customers, partners and channels",
    "Sustitución tecnológica y desplazamiento del riesgo cibernético": "Technology substitution and cyber-risk displacement",
    "Geopolítica y amenaza estatal": "Geopolitics and state threat",
    "Economía digital y fraude": "Digital economy and fraud",
    "Factor humano y manipulación": "Human factors and manipulation",
    "Tecnología y superficie": "Technology and surface",
    "Resiliencia y continuidad": "Resilience and continuity",
    "Regulación y responsabilidad": "Regulation and liability",
    "Rivalidad digital": "Digital rivalry",
    "Proveedores y terceros": "Suppliers and third parties",
    "Clientes y aliados": "Customers and partners",
    "Sustitución tecnológica": "Technology substitution",
    "Vulnerabilidades explotables": "Exploitable vulnerabilities",
    "Fraude e ingenieria social": "Fraud and social engineering",
    "Identidad y accesos": "Identity and access",
    "Ransomware y continuidad": "Ransomware and continuity",
    "Cloud, APIs y DevSecOps": "Cloud, APIs and DevSecOps",
    "Terceros y cadena de suministro": "Third parties and supply chain",
    "Datos, privacidad y regulacion": "Data, privacy and regulation",
    "IA, agentes y automatizacion": "AI, agents and automation",
    "Priorizar KEV/EPSS, exposicion externa y activos criticos.": "Prioritize KEV/EPSS, external exposure and critical assets.",
    "Ajustar controles de identidad, monitoreo transaccional y takedown.": "Tune identity controls, transaction monitoring and takedown.",
    "Reforzar MFA resistente a phishing, PAM, deteccion de valid accounts.": "Strengthen phishing-resistant MFA, PAM and valid-account abuse detection.",
    "Validar backups, segmentacion, EDR/NDR y ejercicios de crisis.": "Validate backups, segmentation, EDR/NDR and crisis exercises.",
    "Revisar API security, secretos, SCA/SBOM, CI/CD y CSPM.": "Review API security, secrets, SCA/SBOM, CI/CD and CSPM.",
    "Monitorear proveedores, contratos, SBOM y resiliencia operacional.": "Monitor suppliers, contracts, SBOM and operational resilience.",
    "Reducir exposicion de datos, trazabilidad legal y respuesta regulatoria.": "Reduce data exposure, legal traceability and regulatory response gaps.",
    "Gobernar prompts, agentes, herramientas, logs y decisiones automatizadas.": "Govern prompts, agents, tools, logs and automated decisions.",
    "PESTEL explica por que el riesgo cyber cambia por fuerzas externas, no solo por vulnerabilidades. Para la marca, grupo o conglomerado analizado, la lectura debe cubrir unidades de negocio, canales digitales, terceros, clientes, regulacion, continuidad y exposiciones sectoriales declaradas en la solicitud.": "PESTEL explains why cyber risk changes due to external forces, not only vulnerabilities. For the analyzed brand, group or conglomerate, the reading should cover business units, digital channels, third parties, customers, regulation, continuity and sector exposures declared in the request.",
    "Porter Cyber explica como la estructura competitiva modifica el riesgo. Para la marca, grupo o conglomerado analizado no basta mirar un solo dominio: deben revisarse clientes, filiales, proveedores tecnologicos, sustitutos digitales, presion sectorial y dependencias de continuidad.": "Porter Cyber explains how competitive structure changes risk. For the analyzed brand, group or conglomerate, one domain is not enough: customers, subsidiaries, technology providers, digital substitutes, sector pressure and continuity dependencies should be reviewed.",
    "Politico": "Political",
    "Economico": "Economic",
    "Social": "Social",
    "Economico/Fraude": "Economic/Fraud",
    "Social/Ing. social": "Social/Social engineering",
    "Tecnologico": "Technological",
    "Ambiental": "Environmental",
    "Legal": "Legal",
    "Ambiental/Continuidad": "Environmental/Continuity",
    "Legal/Regulatorio": "Legal/Regulatory",
    "Mantener escenarios de crisis y relacion con CSIRT/regulador.": "Maintain crisis scenarios and CSIRT/regulator coordination.",
    "Refuerzo de fraude digital, monitoreo de pagos y comunicacion a clientes.": "Strengthen digital fraud controls, payment monitoring and customer communications.",
    "Campanas segmentadas y autenticacion resistente a phishing.": "Run segmented campaigns and phishing-resistant authentication.",
    "Priorizar EASM, API security, hardening cloud, terceros criticos y DevSecOps.": "Prioritize EASM, API security, cloud hardening, critical third parties and DevSecOps.",
    "Validar BCP/DRP, continuidad operacional multisector y segregacion IT/OT cuando aplique.": "Validate BCP/DRP, multi-sector operational continuity and IT/OT segregation where applicable.",
    "Preparar evidencias, playbooks legales, reporting ejecutivo y trazabilidad por filial/sector.": "Prepare evidence, legal playbooks, executive reporting and subsidiary/sector traceability.",
    "Rivalidad": "Rivalry",
    "Poder de proveedores": "Supplier power",
    "Poder de clientes": "Customer power",
    "Amenaza de sustitutos": "Threat of substitutes",
    "Amenaza de nuevos entrantes": "Threat of new entrants",
    "Proveedores": "Suppliers",
    "Clientes": "Customers",
    "Sustitutos": "Substitutes",
    "Nuevos entrantes": "New entrants",
    "Proteger disponibilidad, reputacion y monitoreo de suplantacion.": "Protect availability, reputation and impersonation monitoring.",
    "KRIs de terceros, SBOM/SCA, continuidad, clausulas de seguridad y pruebas de resiliencia.": "Track third-party KRIs, SBOM/SCA, continuity, security clauses and resilience testing.",
    "Friccion adaptativa, awareness segmentado, deteccion transaccional y proteccion de identidad.": "Use adaptive friction, segmented awareness, transaction detection and identity protection.",
    "Monitorear nuevos canales y adaptar controles antifraude.": "Monitor new channels and adapt anti-fraud controls.",
    "API security, OAuth governance, rate limits y monitoreo de integraciones.": "Apply API security, OAuth governance, rate limits and integration monitoring."
  }
};

function localizeAnalyticText(value: string | undefined, language: LanguageMode): string {
  if (!value) return "";
  const dictionary = analyticText[language];
  return dictionary[value] ?? value;
}

function formatEvidencePercent(value: number, language: LanguageMode): string {
  return `${new Intl.NumberFormat(language === "es" ? "es-CO" : "en-US", {
    maximumFractionDigits: 2,
    minimumFractionDigits: value > 0 && value < 1 ? 2 : 0
  }).format(value)}%`;
}

export function StrategyLensChart({ lens, language = "en" }: { lens: StrategyLens; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  const title = localizeAnalyticText(lens.title, language);
  const meaning = localizeAnalyticText(lens.meaning, language);
  return (
    <div className="strategy-lens strategic-news-lens">
      <div className="strategic-lens-header">
        <div className={`lens-score ${lens.index === null ? "unassessed" : ""}`}>
          <strong>{lens.index === null ? copy.noScore : Math.round(lens.index)}</strong>
          <span>{title} · {copy.pressure}</span>
        </div>
        <div className="strategic-lens-meta">
          <span><b>{lens.overallConfidence}%</b>{copy.confidenceLabel}</span>
          <span><b>{formatEvidencePercent(lens.evidenceCoverageRatio * 100, language)}</b>{copy.evidenceCoverage}</span>
          <span><b>{lens.clusterCount}</b>{copy.clusters}</span>
          <span><b>{lens.articleCount}</b>{copy.articles}</span>
        </div>
      </div>
      <p>{meaning}</p>
      {lens.analysisBasis ? (
        <div className="strategic-analysis-basis">
          <div>
            <strong>{copy.analysisBasis}</strong>
            <span>{copy.declaredCoverage}: {formatEvidencePercent(lens.analysisBasis.declaredContextCoverage, language)}</span>
            <em>{copy.currentRunOnly}</em>
          </div>
          <div className="strategic-context-chips">
            {Object.entries(lens.analysisBasis.context)
              .filter(([, values]) => values.length)
              .map(([key, values]) => <span key={key}><b>{key.split("_").join(" ")}</b>{values.slice(0, 3).join(" · ")}{values.length > 3 ? ` +${values.length - 3}` : ""}</span>)}
          </div>
        </div>
      ) : null}
      {lens.snapshots.length ? <div className="strategic-timeline" aria-label={copy.timeline}>
        <strong>{copy.timeline}</strong>
        <div>
          {lens.snapshots.map((snapshot) => (
            <span className={snapshot.status} key={`${lens.title}-${snapshot.windowDays}`}>
              <small>{snapshot.windowDays} {copy.days}</small>
              <b>{snapshot.score === null ? copy.noScore : snapshot.score}</b>
              <em>{snapshot.confidence}% {copy.confidenceLabel.toLowerCase()}</em>
            </span>
          ))}
        </div>
      </div> : null}
      {lens.assessmentStatus === "insufficient_evidence" || lens.signalCount === 0 ? <div className="chart-empty">{copy.unassessed}</div> : null}
      <div className="strategic-dimension-stack">
        {lens.dimensions.map((dimension) => (
          <details className={`strategic-dimension-row ${dimension.status}`} key={dimension.key}>
            <summary>
              <div>
                <strong>{localizeAnalyticText(dimension.name, language)}</strong>
                <small>{dimension.shortName}</small>
                <span>{dimension.clusterCount} {copy.clusters} · {dimension.independentSourceCount} {language === "es" ? "fuentes independientes" : "independent sources"}</span>
              </div>
              <div className="dimension-score-pair">
                <span><b>{dimension.signalScore === null ? copy.noScore : dimension.signalScore}</b>{copy.pressure}</span>
                <span><b>{formatEvidencePercent(dimension.evidenceCoverage, language)}</b>{copy.evidenceCoverage}</span>
                <span><b>{dimension.confidence}%</b>{copy.confidenceLabel}</span>
                <span><b>{dimension.validatedPressure === null ? copy.noScore : dimension.validatedPressure}</b>{language === "es" ? "Presión validada" : "Validated pressure"}</span>
                <em>{dimension.delta === null ? "-" : `${dimension.delta > 0 ? "+" : ""}${dimension.delta}`} {copy.changed}</em>
              </div>
            </summary>
            <div className="dimension-pressure-bars" aria-label={`${dimension.name} ${copy.pressure}`}>
              <span><i style={{ width: `${dimension.evidenceCoverage}%` }} /></span>
              <span><i style={{ width: `${dimension.confidence}%` }} /></span>
            </div>
            <p>{localizeAnalyticText(dimension.why, language)}</p>
            <div className="dimension-evidence-mix">
              <span>{dimension.directCount} {language === "es" ? "directos" : "direct"}</span>
              <span>{dimension.groupCount} {language === "es" ? "grupo" : "group"}</span>
              <span>{dimension.sectorCount} {language === "es" ? "sectoriales" : "sector"}</span>
            </div>
            <p className="dimension-change-note">{localizeAnalyticText(dimension.whatChanged, language)}</p>
            <div className="strategic-calculation-basis">
              <strong>{copy.calculationBasis}</strong>
              <span><b>{dimension.calculation.evidenceMass.toFixed(3)}</b>{copy.evidenceMass}</span>
              <span><b>{dimension.calculation.directionIndex === null ? copy.noScore : dimension.calculation.directionIndex.toFixed(2)}</b>{copy.direction}</span>
              <span><b>{formatEvidencePercent(dimension.calculation.weightedDirectness * 100, language)}</b>{copy.directness}</span>
              <span><b>{formatEvidencePercent(dimension.calculation.directionAgreement * 100, language)}</b>{copy.agreement}</span>
              <span><b>{formatEvidencePercent(dimension.calculation.extractionQuality * 100, language)}</b>{copy.extraction}</span>
              <span><b>{dimension.calculation.publicationGatePassed ? copy.passed : copy.notPassed}</b>{copy.publicationGate}</span>
            </div>
            {dimension.events.length ? <div className="strategic-event-list">
              {dimension.events.map((event) => (
                <article key={event.id}>
                  <Newspaper size={16} />
                  <div>
                    <strong>{event.title}</strong>
                    <span>{localizeAnalyticText(event.relationship, language)} · {localizeAnalyticText(event.direction, language)} · {localizeAnalyticText(event.magnitude, language)}</span>
                    <small>{event.mappingReason}</small>
                    {event.evidenceUrls.map((url) => <a href={url} target="_blank" rel="noreferrer" key={url}><ExternalLink size={13} />{url}</a>)}
                  </div>
                </article>
              ))}
            </div> : null}
          </details>
        ))}
      </div>
    </div>
  );
}

export function StrategicSignalHeatmap({ pestel, porter, language = "en" }: { pestel: StrategyLens; porter: StrategyLens; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  const dimensions = [
    ...pestel.dimensions.map((dimension) => ({ ...dimension, family: "Cyber-PESTEL" })),
    ...porter.dimensions.map((dimension) => ({ ...dimension, family: "Cyber-Porter" }))
  ];
  const populated = dimensions.filter((dimension) => dimension.signalScore !== null);
  if (!populated.length) return <div className="chart-empty">{copy.unassessed}</div>;
  return (
    <div className="strategic-signal-heatmap" role="list">
      {dimensions.map((dimension) => {
        const score = dimension.signalScore;
        const tone = score === null ? "no-data" : score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
        return (
          <div className={`strategic-heat-cell ${tone}`} key={`${dimension.family}-${dimension.key}`} role="listitem">
            <span>{dimension.family}</span>
            <strong>{localizeAnalyticText(dimension.shortName || dimension.name, language)}</strong>
            <b>{score === null ? copy.noScore : Math.round(score)}</b>
            <div aria-hidden="true"><i style={{ width: `${score ?? 0}%` }} /></div>
            <small>{copy.confidenceLabel} {Math.round(dimension.confidence)}% · {copy.evidenceCoverage} {formatEvidencePercent(dimension.evidenceCoverage, language)}</small>
          </div>
        );
      })}
    </div>
  );
}

export function RiskHeatMap({ rows, language = "en" }: { rows: RiskHeatRow[]; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  if (!rows.length) return <div className="chart-empty">{copy.noHeat}</div>;
  return (
    <div className="risk-heat-grid">
      {rows.map((row) => (
        <div className={`risk-heat-cell ${row.heat}`} key={`${row.index}-${row.name}`}>
          <Flame size={15} />
          <span>{row.index}. {localizeAnalyticText(row.name, language)}</span>
          <strong>{Math.round(row.score * 100)}%</strong>
          <em>{localizeAnalyticText(row.decision, language)}</em>
        </div>
      ))}
    </div>
  );
}

export function RiskRadarChart({ rows, language = "en" }: { rows: RiskHeatRow[]; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  if (!rows.length) return <div className="chart-empty">{copy.noRadar}</div>;
  const visibleRows = rows.slice(0, 8);
  const center = 50;
  const maxRadius = 34;
  const points = visibleRows
    .map((row, index) => {
      const angle = (Math.PI * 2 * index) / visibleRows.length - Math.PI / 2;
      const radius = Math.max(7, Math.min(maxRadius, row.score * maxRadius));
      return {
        row,
        x: center + Math.cos(angle) * radius,
        y: center + Math.sin(angle) * radius,
        labelX: center + Math.cos(angle) * 42,
        labelY: center + Math.sin(angle) * 42
      };
    });
  const polygon = points.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ");
  const rankedRows = [...rows].sort((left, right) => right.score - left.score);
  const highest = rankedRows[0];
  const averageRisk = rows.reduce((sum, row) => sum + row.score, 0) / rows.length;
  const criticalCount = rows.filter((row) => row.heat === "critical").length;
  const evidenceSignals = rows.reduce((sum, row) => sum + row.evidenceCount, 0);
  const dominantScore = highest ? Math.round(highest.score * 100) : 0;

  return (
    <div className="risk-radar">
      <div className="risk-radar-plot">
        <svg viewBox="0 0 100 100" role="img" aria-label={copy.radarAria}>
          <defs>
            <radialGradient id="risk-radar-glow" cx="50%" cy="50%" r="62%">
              <stop offset="0%" stopColor="currentColor" stopOpacity="0.16" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
            </radialGradient>
          </defs>
          <circle className="radar-glow" cx={center} cy={center} r="43" />
          <circle className="radar-ring outer" cx={center} cy={center} r="38" />
          <circle className="radar-ring" cx={center} cy={center} r="25" />
          <circle className="radar-ring" cx={center} cy={center} r="12" />
          {points.map((point) => (
            <line className="radar-axis" key={`axis-${point.row.index}`} x1={center} y1={center} x2={point.labelX} y2={point.labelY} />
          ))}
          <polygon className="radar-area" points={polygon} />
          <circle className="radar-core" cx={center} cy={center} r="10.8" />
          <text className="radar-core-score" x={center} y={center - 1.5} textAnchor="middle">
            {dominantScore}%
          </text>
          <text className="radar-core-label" x={center} y={center + 5.3} textAnchor="middle">
            {language === "es" ? "pico" : "peak"}
          </text>
          {points.map((point) => (
            <g key={point.row.name}>
              <circle className={`radar-dot ${point.row.heat}`} cx={point.x} cy={point.y} r="3.1" />
              <text className="radar-index" x={point.labelX} y={point.labelY} textAnchor={point.labelX < center ? "end" : point.labelX > center ? "start" : "middle"}>
                {point.row.index}
              </text>
            </g>
          ))}
        </svg>
      </div>
      <div className="risk-radar-summary">
        <span>{copy.primaryRisk}</span>
        <strong>{highest ? localizeAnalyticText(highest.name, language) : copy.noActiveRisk}</strong>
        <p>{highest ? localizeAnalyticText(highest.decision, language) : copy.runToPopulate}</p>
        <div className="risk-radar-kpis">
          <div>
            <b>{Math.round(averageRisk * 100)}%</b>
            <span>{copy.averageRisk}</span>
          </div>
          <div>
            <b>{criticalCount}</b>
            <span>{copy.criticalItems}</span>
          </div>
          <div>
            <b>{evidenceSignals}</b>
            <span>{copy.evidenceSignals}</span>
          </div>
        </div>
        <span className="risk-radar-list-title">{copy.priorityMap}</span>
        <div className="risk-radar-list">
          {rankedRows.map((row) => (
            <div className={`risk-radar-item ${row.heat}`} key={`${row.index}-${row.name}`}>
              <b>{row.index}</b>
              <span>{localizeAnalyticText(row.name, language)}</span>
              <strong>{Math.round(row.score * 100)}%</strong>
              <i>
                <u style={{ width: `${Math.max(4, Math.round(row.score * 100))}%` }} />
              </i>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function AttackPredictionPanel({ prediction, language = "en" }: { prediction: AttackPredictionModel; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  if (prediction.status === "insufficient_evidence") {
    return <div className="chart-empty">{copy.noPrediction}</div>;
  }
  const leading = prediction.leadingScenario;
  const horizons = [
    { label: "7d", value: prediction.pressure7d },
    { label: "14d", value: prediction.pressure14d },
    { label: "30d", value: prediction.pressure30d },
    { label: "90d", value: prediction.pressure90d }
  ];
  const trendLabel = copy[prediction.trendDirection];
  return (
    <div className="prediction-panel">
      <div className="prediction-hero">
        <div className="prediction-hero-heading">
          <BrainCircuit size={24} />
          <span>{copy.predictiveModel}</span>
        </div>
        <strong>{Math.round(prediction.pressure30d * 100)}<small>/100 · 30d</small></strong>
        <p>{leading ? localizeAnalyticText(leading.modality, language) : copy.noLeading}</p>
        <div className={`prediction-trend ${prediction.trendDirection}`}>
          <Activity size={15} />
          <span>{copy.trend}</span>
          <b>{trendLabel}</b>
          {prediction.trendChangeRatio !== null ? (
            <em>{prediction.trendChangeRatio > 0 ? "+" : ""}{Math.round(prediction.trendChangeRatio * 100)}%</em>
          ) : null}
        </div>
      </div>
      <div className="prediction-probability-note">
        <span>{copy.attackProbability}</span>
        <strong>{prediction.probabilityValue === null ? copy.notCalibrated : `${Math.round(prediction.probabilityValue * 100)}%`}</strong>
        <small>{copy.confidence}: {Math.round(prediction.evidenceConfidence)}% · {prediction.modelVersion}</small>
      </div>
      <div className="prediction-horizons" aria-label={copy.horizon}>
        {horizons.map((item) => (
          <div key={item.label}>
            <span>{item.label}</span>
            <strong>{Math.round(item.value * 100)}/100</strong>
            <i><b style={{ width: `${Math.max(2, Math.round(item.value * 100))}%` }} /></i>
          </div>
        ))}
      </div>
      <div className="prediction-drivers">
        {prediction.drivers.map((driver) => (
          <div className="prediction-driver" key={driver.name} title={localizeAnalyticText(driver.explanation, language)}>
            <span>{localizeAnalyticText(driver.name, language)}</span>
            <i>
              <b style={{ width: `${Math.max(4, driver.value)}%` }} />
            </i>
            <strong>{driver.value}%</strong>
          </div>
        ))}
      </div>
      <div className="prediction-scenarios">
        {prediction.scenarios.map((scenario) => (
          <article key={scenario.id || `${scenario.modality}-${scenario.technique}`}>
            <div>
              <Activity size={15} />
              <strong>{localizeAnalyticText(scenario.modality, language)}</strong>
              <span>{copy.scenarioSupport}: {Math.round(scenario.supportScore * 100)}/100</span>
            </div>
            <p>{scenario.technique !== "N/D" ? localizeAnalyticText(scenario.technique, language) : localizeAnalyticText(scenario.status || "", language)}</p>
            <em>{scenario.evidenceCount} {copy.signals} · {scenario.sourceCount ?? 0} fuentes. {localizeAnalyticText(scenario.decision, language)}</em>
          </article>
        ))}
      </div>
      <p className="prediction-method">{localizeAnalyticText(prediction.methodology, language)}</p>
    </div>
  );
}

export function PosturePanel({ score, points, language = "en" }: { score: number; points: PosturePoint[]; language?: LanguageMode }) {
  const copy = strategyCopy[language];
  return (
    <div className="posture-panel">
      <div className="posture-score">
        <ShieldCheck size={20} />
        <strong>{Math.round(score)}</strong>
        <span>{copy.posture}</span>
      </div>
      <div className="posture-points">
        {points.length ? points.map((point) => (
          <div className={`posture-point ${point.tone}`} key={point.name}>
            <span>{point.name}</span>
            <i>
              <b style={{ width: `${point.value}%` }} />
            </i>
            <strong>{point.value}%</strong>
          </div>
        )) : <div className="posture-empty"><ShieldCheck size={22} /><span>{copy.postureEmpty}</span></div>}
      </div>
    </div>
  );
}
