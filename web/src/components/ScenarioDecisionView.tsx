import { BrainCircuit, Crosshair, GitBranch, Layers3, Lightbulb, ShieldCheck, Target } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { getScenarioLibrary } from "../api";
import type { DisinformationScenario, LanguageMode, RunRecord, ScenarioLibraryResponse, ThreatEvent } from "../types";
import { BarRanking } from "./ChartPrimitives";

type FrameworkKey = "attack" | "d3fend" | "atlas" | "disarm" | "f3";
type ScenarioFamily = "exploit" | "identity" | "fraud" | "influence" | "ai" | "continuity" | "general";
type DecisionLens = { criteria: string; question: string; decision: string };

const ALL_SCOPE = "__all__";
const GROUP_SCOPE = "__group__";

interface EvidenceSignal {
  id: string;
  title: string;
  category: string;
  source: string;
  technique?: string | null;
  url?: string | null;
  domains: string[];
  tokens: Set<string>;
  evidenceStatus: string;
  confidenceScore: number;
  attackMappingStatus: string;
  sourceRefs: string[];
  disarmSignal: boolean;
  atlasSignal: boolean;
  f3Signal: boolean;
  frameworkIds: Set<string>;
}

interface ScenarioMatch {
  scenario: DisinformationScenario;
  score: number;
  confidence: number;
  reasons: string[];
  domains: string[];
  evidenceCount: number;
  primaryFramework: FrameworkKey;
}

interface DomainCard {
  domain: string;
  scope: string;
  signalCount: number;
  maxRisk: number;
  topScenario?: ScenarioMatch;
}

const labels = {
  es: {
    title: "Escenarios de decisión accionable",
    subtitle: "Cruce multi-framework de la evidencia recolectada para los dominios de búsqueda. No usa dominios comparativos y no afirma escenarios sin señales.",
    library: "Biblioteca",
    evidence: "Señales usadas",
    active: "Escenarios priorizados",
    frameworks: "Cobertura framework",
    domainScope: "Lectura por dominio",
    domainSubtitle: "Relación entre dominios consultados, evidencia y escenarios aplicables",
    frameworkMap: "Frameworks mapeados",
    frameworkSubtitle: "Cantidad de identificadores únicos presentes en los escenarios aplicables",
    scenarioTitle: "Panel de posibilidades para decisión",
    scenarioSubtitle: "Opciones estratégicas y técnicas para evaluar, no órdenes automáticas de ejecución",
    noRun: "Ejecuta una búsqueda de dominios para construir escenarios presentes.",
    noEvidence: "No hay evidencia suficiente para activar escenarios. La biblioteca queda disponible como referencia preventiva.",
    group: "Grupo de búsqueda",
    supported: "soportado por evidencia",
    confidence: "confianza",
    decision: "Posibilidad de decisión",
    question: "Pregunta directiva",
    criteria: "Base de criterio",
    evidenceBase: "Base de evidencia",
    domains: "Dominios",
    allDomains: "Todos",
    selectedScope: "Alcance seleccionado",
    visibleScenarios: "Escenarios visibles",
    noneForScope: "No hay escenarios aplicables para el alcance seleccionado.",
    scenarioNavigator: "Navegación de escenarios",
    priority: "Prioridad",
    selectedScenario: "Escenario seleccionado",
    relatedDomains: "Dominios relacionados",
    general: "Grupo general",
    attack: "ATT&CK",
    d3fend: "D3FEND",
    atlas: "ATLAS",
    disarm: "DISARM",
    f3: "F3"
  },
  en: {
    title: "Actionable decision scenarios",
    subtitle: "Multi-framework crosswalk over collected evidence for searched domains. Competitor domains are excluded and scenarios are not asserted without signals.",
    library: "Library",
    evidence: "Signals used",
    active: "Prioritized scenarios",
    frameworks: "Framework coverage",
    domainScope: "Domain-level reading",
    domainSubtitle: "Relationship between searched domains, evidence and applicable scenarios",
    frameworkMap: "Mapped frameworks",
    frameworkSubtitle: "Unique identifiers represented in applicable scenarios",
    scenarioTitle: "Decision possibilities board",
    scenarioSubtitle: "Strategic and technical options to evaluate, not automatic execution orders",
    noRun: "Run a domain search to build present scenarios.",
    noEvidence: "There is not enough evidence to activate scenarios. The library remains available as preventive reference.",
    group: "Search group",
    supported: "evidence-supported",
    confidence: "confidence",
    decision: "Decision possibility",
    question: "Executive question",
    criteria: "Criteria base",
    evidenceBase: "Evidence base",
    domains: "Domains",
    allDomains: "All",
    selectedScope: "Selected scope",
    visibleScenarios: "Visible scenarios",
    noneForScope: "No applicable scenarios for the selected scope.",
    scenarioNavigator: "Scenario navigation",
    priority: "Priority",
    selectedScenario: "Selected scenario",
    relatedDomains: "Related domains",
    general: "Overall group",
    attack: "ATT&CK",
    d3fend: "D3FEND",
    atlas: "ATLAS",
    disarm: "DISARM",
    f3: "F3"
  }
};

const scenarioTextCatalog: Record<LanguageMode, Record<ScenarioFamily, { questions: string[]; decisions: string[] }>> = {
  es: {
    exploit: {
      questions: [
        "¿Qué activos o servicios asociados a {domain} deben validarse primero si la señal se conecta con {attack}?",
        "¿La evidencia permite tratar {attack} como exposición técnica prioritaria o como monitoreo preventivo?",
        "¿Qué brecha debe confirmarse antes de escalar inversión: reducción de superficie o control {control}?"
      ],
      decisions: [
        "Considerar una validación externa de activos, KEV/EPSS y hardening priorizado; usar {control} como control de contraste.",
        "Evaluar una ventana corta de remediación para servicios expuestos y dejar trazabilidad de evidencia por URL antes de declarar criticidad.",
        "Cruzar inventario, logs perimetrales y exposición observada para decidir entre mitigación inmediata, excepción o monitoreo reforzado."
      ]
    },
    identity: {
      questions: [
        "¿La presión sobre {domain} sugiere riesgo de credenciales, sesión o abuso de acceso frente a {attack}?",
        "¿Qué población, rol o activo de identidad debe revisarse antes de elevar el escenario a riesgo operativo?",
        "¿La cobertura actual de {control} es suficiente para separar exposición pública de intento real de compromiso?"
      ],
      decisions: [
        "Evaluar MFA resistente, monitoreo de sesiones y fricción adaptativa en usuarios relacionados con la evidencia.",
        "Priorizar revisión de cuentas privilegiadas, correos expuestos y señales de suplantación antes de ampliar medidas a toda la organización.",
        "Usar hallazgos OSINT/SOCMINT como insumo de hunting defensivo, no como confirmación automática de compromiso."
      ]
    },
    fraud: {
      questions: [
        "¿La evidencia sobre {domain} puede habilitar fraude, suplantación o abuso de confianza contra clientes o empleados?",
        "¿Qué canal de pago, comunicación o atención debería ser contrastado con la señal asociada a {attack}?",
        "¿La señal requiere decisión de prevención antifraude, comunicación externa o takedown?"
      ],
      decisions: [
        "Considerar monitoreo antifraude segmentado, validación de dominios similares y reglas de detección para campañas de suplantación.",
        "Coordinar prevención, marca y legal para decidir si la evidencia amerita takedown, aviso preventivo o seguimiento.",
        "Cruzar menciones públicas con reclamos, transacciones anómalas y dominios abusivos antes de activar acciones masivas."
      ]
    },
    influence: {
      questions: [
        "¿La narrativa pública relacionada con {domain} muestra señales de influencia, coordinación o erosión de confianza?",
        "¿La señal {disarm} afecta reputación, continuidad comercial o percepción de seguridad?",
        "¿Qué audiencia o canal debe priorizarse antes de decidir respuesta comunicacional?"
      ],
      decisions: [
        "Separar narrativa, canal, audiencia y fuente antes de decidir comunicación, monitoreo ampliado o solicitud de remoción.",
        "Considerar un playbook de respuesta reputacional con evidencia URL por URL y criterio de severidad por alcance.",
        "Mantener el escenario como posibilidad de influencia hasta que existan señales suficientes de coordinación o amplificación."
      ]
    },
    ai: {
      questions: [
        "¿La señal asociada a {atlas} puede aumentar automatización, impersonación o escala del ataque?",
        "¿Qué control humano o técnico reduce mejor el riesgo de abuso de IA frente a {domain}?",
        "¿La evidencia sugiere abuso de modelos, generación de contenido o automatización defensivamente relevante?"
      ],
      decisions: [
        "Evaluar gobierno de IA, monitoreo de agentes, revisión de prompts/logs y límites de automatización en procesos expuestos.",
        "Considerar validaciones manuales adicionales si el escenario combina IA, fraude y presión reputacional.",
        "Cruzar {atlas} con controles de identidad y marca antes de priorizar inversión o respuesta ejecutiva."
      ]
    },
    continuity: {
      questions: [
        "¿La evidencia sobre {domain} puede evolucionar hacia extorsión, interrupción o presión operacional?",
        "¿Qué dependencia crítica debería validarse si {attack} aparece junto con señales de continuidad?",
        "¿La organización tiene umbrales claros para activar crisis, legal y continuidad frente a este escenario?"
      ],
      decisions: [
        "Considerar prueba de restauración, segregación, cobertura EDR/NDR y monitoreo de extorsión como acciones de preparación.",
        "Revisar proveedores críticos y activos expuestos antes de elevar el escenario a crisis o continuidad.",
        "Usar la señal para priorizar tabletop ejecutivo si coincide con brechas de control y exposición pública."
      ]
    },
    general: {
      questions: [
        "¿Qué decisión concreta necesita esta señal antes de convertirse en plan de acción para {domain}?",
        "¿La evidencia actual alcanza para priorizar inversión, monitoreo o revisión humana?",
        "¿Qué fuente adicional reduciría más la incertidumbre del escenario?"
      ],
      decisions: [
        "Asignar propietario, evidencia mínima y umbral de escalamiento antes de convertir el escenario en acción.",
        "Mantener seguimiento hasta sumar evidencia suficiente o descartar por baja relación con el dominio.",
        "Contrastar la señal con controles, exposición y contexto sectorial antes de recomendar inversión."
      ]
    }
  },
  en: {
    exploit: {
      questions: [
        "Which assets or services linked to {domain} should be validated first if the signal connects to {attack}?",
        "Does the evidence support treating {attack} as prioritized exposure or preventive monitoring?",
        "Which gap should be confirmed before escalating investment: surface reduction or {control}?"
      ],
      decisions: [
        "Consider external asset validation, KEV/EPSS review and prioritized hardening; use {control} as the control contrast.",
        "Evaluate a short remediation window for exposed services and retain URL-level evidence before declaring criticality.",
        "Cross inventory, perimeter logs and observed exposure to decide between immediate mitigation, exception or reinforced monitoring."
      ]
    },
    identity: {
      questions: [
        "Does pressure on {domain} suggest credential, session or access-abuse risk linked to {attack}?",
        "Which identity population, role or asset should be reviewed before escalating this to operational risk?",
        "Is current {control} coverage enough to separate public exposure from a real compromise attempt?"
      ],
      decisions: [
        "Evaluate phishing-resistant MFA, session monitoring and adaptive friction for users related to the evidence.",
        "Prioritize privileged-account review, exposed emails and impersonation signals before expanding controls organization-wide.",
        "Use OSINT/SOCMINT findings as defensive hunting input, not automatic confirmation of compromise."
      ]
    },
    fraud: {
      questions: [
        "Can evidence about {domain} enable fraud, impersonation or trust abuse against customers or employees?",
        "Which payment, communication or support channel should be checked against the signal tied to {attack}?",
        "Does the signal require a fraud-prevention, external-communications or takedown decision?"
      ],
      decisions: [
        "Consider segmented fraud monitoring, lookalike-domain validation and detection rules for impersonation campaigns.",
        "Coordinate fraud prevention, brand and legal to decide whether evidence warrants takedown, advisory or monitoring.",
        "Cross public mentions with claims, anomalous transactions and abusive domains before activating broad actions."
      ]
    },
    influence: {
      questions: [
        "Does the public narrative related to {domain} show influence, coordination or trust-erosion signals?",
        "Does {disarm} affect reputation, commercial continuity or perceived security?",
        "Which audience or channel should be prioritized before deciding a communications response?"
      ],
      decisions: [
        "Separate narrative, channel, audience and source before deciding communications, expanded monitoring or removal requests.",
        "Consider a reputational-response playbook with URL-level evidence and severity criteria by reach.",
        "Keep the scenario as an influence possibility until enough coordination or amplification signals exist."
      ]
    },
    ai: {
      questions: [
        "Can the signal associated with {atlas} increase automation, impersonation or attack scale?",
        "Which human or technical control best reduces AI-abuse risk for {domain}?",
        "Does the evidence suggest model abuse, content generation or defensively relevant automation?"
      ],
      decisions: [
        "Evaluate AI governance, agent monitoring, prompt/log review and automation limits in exposed processes.",
        "Consider additional human validation if the scenario combines AI, fraud and reputational pressure.",
        "Cross {atlas} with identity and brand controls before prioritizing investment or executive response."
      ]
    },
    continuity: {
      questions: [
        "Can evidence about {domain} evolve into extortion, disruption or operational pressure?",
        "Which critical dependency should be validated if {attack} appears with continuity signals?",
        "Does the organization have clear thresholds for activating crisis, legal and continuity workflows?"
      ],
      decisions: [
        "Consider restore testing, segmentation, EDR/NDR coverage and extortion monitoring as preparedness actions.",
        "Review critical suppliers and exposed assets before escalating the scenario into crisis or continuity mode.",
        "Use the signal to prioritize an executive tabletop if it coincides with control gaps and public exposure."
      ]
    },
    general: {
      questions: [
        "What concrete decision does this signal need before it becomes an action plan for {domain}?",
        "Is current evidence enough to prioritize investment, monitoring or human review?",
        "Which additional source would reduce scenario uncertainty the most?"
      ],
      decisions: [
        "Assign an owner, minimum evidence and escalation threshold before turning the scenario into action.",
        "Keep monitoring until enough evidence is collected or the domain relationship is ruled out.",
        "Contrast the signal with controls, exposure and sector context before recommending investment."
      ]
    }
  }
};

export function ScenarioDecisionView({ run, language }: { run?: RunRecord; language: LanguageMode }) {
  const t = labels[language];
  const [library, setLibrary] = useState<ScenarioLibraryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getScenarioLibrary()
      .then(setLibrary)
      .catch((exc) => setError(exc instanceof Error ? exc.message : String(exc)));
  }, []);

  const evidence = useMemo(() => buildEvidence(run), [run]);
  const matches = useMemo(() => buildScenarioMatches(library?.scenarios ?? [], evidence, run), [library, evidence, run]);
  const [selectedScopes, setSelectedScopes] = useState<string[]>([ALL_SCOPE]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const scopeOptions = useMemo(() => buildScopeOptions(run, t.allDomains, t.group), [run, t.allDomains, t.group]);
  const filteredMatches = useMemo(() => filterMatchesByScopes(matches, selectedScopes), [matches, selectedScopes]);
  const visibleMatches = useMemo(() => filteredMatches.slice(0, 12), [filteredMatches]);
  const selectedMatch = useMemo(
    () => visibleMatches.find((match) => match.scenario.id === selectedScenarioId) ?? visibleMatches[0],
    [selectedScenarioId, visibleMatches]
  );
  const frameworkItems = frameworkCoverage(filteredMatches).map((item) => ({ name: t[item.key], value: item.value, tone: "medium" as const }));
  const domainCards = filterDomainCardsByScopes(buildDomainCards(run, matches, evidence), selectedScopes);
  const frameworkTotal = frameworkItems.reduce((sum, item) => sum + item.value, 0);

  useEffect(() => {
    setSelectedScopes([ALL_SCOPE]);
    setSelectedScenarioId(null);
  }, [run?.id]);

  useEffect(() => {
    if (visibleMatches.length && !visibleMatches.some((match) => match.scenario.id === selectedScenarioId)) {
      setSelectedScenarioId(visibleMatches[0].scenario.id);
    }
  }, [selectedScenarioId, visibleMatches]);

  function toggleScope(scope: string) {
    setSelectedScopes((current) => {
      if (scope === ALL_SCOPE) return [ALL_SCOPE];
      const withoutAll = current.filter((item) => item !== ALL_SCOPE);
      const next = withoutAll.includes(scope) ? withoutAll.filter((item) => item !== scope) : [...withoutAll, scope];
      return next.length ? next : [ALL_SCOPE];
    });
  }

  return (
    <div className="view-stack">
      <section className="panel module-hero scenario-hero">
        <div>
          <BrainCircuit size={24} />
          <h2>{t.title}</h2>
          <p>{t.subtitle}</p>
        </div>
        <div className="privacy-note scenario-note">
          <GitBranch size={18} />
          <span>{library?.reference_template_count ?? 0} {language === "en" ? "framework-derived analytical scenarios" : "escenarios analíticos derivados de marcos"} · ATT&CK + ATLAS + DISARM + F3 · D3FEND {language === "en" ? "as defensive crosswalk" : "como cruce defensivo"}</span>
        </div>
      </section>

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="dashboard-kpis">
        <Metric icon={<Crosshair size={18} />} label={t.evidence} value={String(evidence.length)} />
        <Metric icon={<BrainCircuit size={18} />} label={t.visibleScenarios} value={String(filteredMatches.length)} />
        <Metric icon={<Target size={18} />} label={t.domains} value={String(run?.domains.length ?? 0)} />
        <Metric icon={<Layers3 size={18} />} label={t.frameworks} value={String(frameworkTotal)} />
      </section>

      {!run ? <div className="panel chart-card chart-empty">{t.noRun}</div> : null}
      {run && !matches.length ? <div className="panel chart-card chart-empty">{t.noEvidence}</div> : null}

      {run && matches.length ? (
        <>
          <section className="scenario-decision-layout">
            <article className="panel chart-card">
              <div className="panel-title-row compact">
                <div>
                  <h2>{t.domainScope}</h2>
                  <p>{t.domainSubtitle}</p>
                </div>
                <ShieldCheck size={18} />
              </div>
              <div className="domain-scope-selector" aria-label={t.selectedScope}>
                {scopeOptions.map((option) => (
                  <button
                    type="button"
                    className={selectedScopes.includes(option.id) || (option.id === ALL_SCOPE && selectedScopes.includes(ALL_SCOPE)) ? "selected" : ""}
                    key={option.id}
                    onClick={() => toggleScope(option.id)}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
              <div className="domain-scenario-list">
                {domainCards.map((card) => (
                  <article key={card.domain}>
                    <div>
                      <strong>{card.domain}</strong>
                      <span>{card.signalCount} {t.evidence} · {card.maxRisk}%</span>
                    </div>
                    <p>{card.topScenario ? scenarioDisplayTitle(card.topScenario, language) : t.noEvidence}</p>
                  </article>
                ))}
              </div>
            </article>

            <article className="panel chart-card">
              <div className="panel-title-row compact">
                <div>
                  <h2>{t.frameworkMap}</h2>
                  <p>{t.frameworkSubtitle}</p>
                </div>
                <GitBranch size={18} />
              </div>
              <BarRanking items={frameworkItems} language={language} />
            </article>
          </section>

          <section className="panel chart-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{t.scenarioTitle}</h2>
                <p>{t.scenarioSubtitle}</p>
              </div>
              <Lightbulb size={18} />
            </div>
            {filteredMatches.length ? (
              <div className="decision-workbench">
                <aside className="decision-list-panel" aria-label={t.scenarioNavigator}>
                  <div className="decision-list-head">
                    <span>{t.scenarioNavigator}</span>
                    <strong>{visibleMatches.length}/{filteredMatches.length}</strong>
                  </div>
                  <div className="decision-scenario-nav">
                    {visibleMatches.map((match, index) => (
                      <button
                        type="button"
                        className={selectedMatch?.scenario.id === match.scenario.id ? "selected" : ""}
                        key={match.scenario.id}
                        onClick={() => setSelectedScenarioId(match.scenario.id)}
                      >
                        <span className="decision-rank">{index + 1}</span>
                        <span className="decision-nav-copy">
                          <strong>{scenarioDisplayTitle(match, language)}</strong>
                          <small>{formatMatchDomains(match.domains, t.general)}</small>
                        </span>
                        <em>{match.confidence}%</em>
                      </button>
                    ))}
                  </div>
                </aside>

                {selectedMatch ? (
                  <article className="decision-detail-panel">
                    <div className="decision-detail-head">
                      <span>{t.selectedScenario}</span>
                      <strong>{t[ selectedMatch.primaryFramework ]} · {selectedMatch.confidence}%</strong>
                    </div>
                    <h3>{scenarioDisplayTitle(selectedMatch, language)}</h3>
                    <div className="decision-summary-card">
                      <span>{t.decision}</span>
                      <p>{scenarioDecision(selectedMatch, language)}</p>
                    </div>
                    <div className="decision-insight-grid">
                      <div className="decision-insight-card">
                        <span>{t.question}</span>
                        <p>{scenarioQuestion(selectedMatch, language)}</p>
                      </div>
                      <div className="decision-insight-card">
                        <span>{t.criteria}</span>
                        <p>{scenarioCriteria(selectedMatch, language)}</p>
                      </div>
                    </div>
                    <div className="framework-chip-row">
                      {selectedMatch.scenario.frameworks.attack.id ? <span>ATT&CK {selectedMatch.scenario.frameworks.attack.id}</span> : null}
                      {selectedMatch.scenario.frameworks.d3fend.id ? <span>D3FEND {selectedMatch.scenario.frameworks.d3fend.id}</span> : null}
                      {selectedMatch.scenario.frameworks.atlas.id ? <span>ATLAS {selectedMatch.scenario.frameworks.atlas.id}</span> : null}
                      {selectedMatch.scenario.frameworks.disarm.id ? <span>DISARM {selectedMatch.scenario.frameworks.disarm.id}</span> : null}
                      {selectedMatch.scenario.frameworks.f3?.id ? <span>F3 {selectedMatch.scenario.frameworks.f3.id}</span> : null}
                    </div>
                    <div className="decision-meta-grid">
                      <p><b>{t.evidenceBase}</b>{formatEvidenceBasis(selectedMatch, language)}</p>
                      <p><b>{t.relatedDomains}</b>{formatMatchDomains(selectedMatch.domains, t.general)}</p>
                    </div>
                    <em>{t.supported} · {t.confidence} {selectedMatch.confidence}%</em>
                  </article>
                ) : null}
              </div>
            ) : (
              <div className="chart-empty">{t.noneForScope}</div>
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}

function buildEvidence(run?: RunRecord): EvidenceSignal[] {
  if (!run) return [];
  const eventSignals = (run.summary.events ?? [])
    .filter((event) => ["direct", "validated", "confirmed"].includes(event.evidence_status ?? "raw"))
    .map((event) => eventToSignal(event, run.domains));
  const findingSignals = (run.summary.findings ?? []).filter((finding) =>
    ["validated", "confirmed"].includes(finding.evidence_status ?? "")
  ).map((finding, index) => {
    const title = String(finding.title ?? "");
    const category = String(finding.category ?? "finding");
    const evidenceText = Array.isArray(finding.evidence) ? finding.evidence.join(" ") : "";
    const recommendationText = Array.isArray(finding.recommendations) ? finding.recommendations.join(" ") : "";
    const text = `${title} ${category} ${evidenceText} ${recommendationText}`;
    return {
      id: `finding-${index}`,
      title,
      category,
      source: "validated_finding",
      technique: extractTechnique(text),
      url: null,
      domains: domainsInText(text, run.domains),
      tokens: tokenize(text),
      evidenceStatus: finding.evidence_status ?? "validated",
      confidenceScore: Number(finding.confidence_score ?? 0.5),
      attackMappingStatus: "potentially_relevant_technique",
      sourceRefs: ["validated_finding"],
      disarmSignal: /\b(disinformation|desinformacion|narrative manipulation|influence operation)\b/i.test(text),
      atlasSignal: /\b(ai model|ai agent|prompt injection|model supply chain|atlas)\b/i.test(text),
      f3Signal: false,
      frameworkIds: extractFrameworkIds(text, [])
    };
  });
  return [...eventSignals, ...findingSignals].filter((item) => item.tokens.size > 0).slice(0, 180);
}

function formatEvidenceBasis(match: ScenarioMatch, language: LanguageMode): string {
  const visible = match.reasons.slice(0, 4);
  const criteriaLabel = visible.length
    ? language === "es"
      ? `${visible.length} criterios visibles: ${visible.join(" / ")}`
      : `${visible.length} visible criteria: ${visible.join(" / ")}`
    : language === "es"
      ? "sin criterio visible"
      : "no visible criterion";
  return language === "es"
    ? `${match.evidenceCount} señales coincidentes; ${criteriaLabel}`
    : `${match.evidenceCount} matching signals; ${criteriaLabel}`;
}

function eventToSignal(event: ThreatEvent, domains: string[]): EvidenceSignal {
  const text = `${event.title} ${event.category} ${event.source} ${event.technique ?? ""} ${(event.tags ?? []).join(" ")}`;
  const tags = new Set((event.tags ?? []).map((tag) => normalize(tag)));
  const validation = event.technical_validation ?? {};
  const f3Mappings = Array.isArray(validation.f3_mappings) ? validation.f3_mappings : [];
  const f3Ids = f3Mappings
    .map((item) => typeof item === "object" && item !== null && "id" in item ? String(item.id).toUpperCase() : "")
    .filter(Boolean);
  return {
    id: event.id,
    title: event.title,
    category: event.category,
    source: event.source,
    technique: event.technique,
    url: event.evidence_url,
    domains: domainsInText(text, domains),
    tokens: tokenize(text),
    evidenceStatus: event.evidence_status ?? "raw",
    confidenceScore: Number(event.confidence_score ?? 0.5),
    attackMappingStatus: event.attack_mapping_status ?? "potentially_relevant_technique",
    sourceRefs: event.source_refs?.length ? event.source_refs : [event.source],
    disarmSignal:
      ["disinformation", "narrative_manipulation"].includes(normalize(event.category)) ||
      ["disarm_signal", "narrative_manipulation", "coordinated_amplification", "influence_operation"].some((tag) => tags.has(tag)),
    atlasSignal:
      ["ai_security", "ai_model_exposure"].includes(normalize(event.category)) ||
      ["atlas_signal", "ai_asset", "ai_model", "ai_agent", "prompt_injection", "model_supply_chain"].some((tag) => tags.has(tag)),
    f3Signal: f3Ids.length > 0,
    frameworkIds: new Set([
      ...extractFrameworkIds(`${text} ${event.external_id ?? ""}`, event.tags ?? []),
      ...f3Ids
    ])
  };
}

function extractFrameworkIds(text: string, tags: string[]): Set<string> {
  const identifiers = new Set<string>();
  for (const tag of tags) {
    const match = tag.match(/^(?:atlas|disarm|f3|framework_id):\s*(AML\.TA\d{4}|T\d{4}(?:\.\d{3})?|F\d{4}(?:\.\d{3})?|FA\d{4})$/i);
    if (match) identifiers.add(match[1].toUpperCase());
  }
  for (const match of text.matchAll(/\bAML\.TA\d{4}\b/gi)) identifiers.add(match[0].toUpperCase());
  for (const match of text.matchAll(/\bDISARM\s*[:#-]?\s*(T\d{4}(?:\.\d{3})?)\b/gi)) identifiers.add(match[1].toUpperCase());
  for (const match of text.matchAll(/\bF3\s*[:#-]?\s*(F\d{4}(?:\.\d{3})?|FA\d{4}|T\d{4}(?:\.\d{3})?)\b/gi)) identifiers.add(match[1].toUpperCase());
  return identifiers;
}

function buildScenarioMatches(scenarios: DisinformationScenario[], evidence: EvidenceSignal[], run?: RunRecord): ScenarioMatch[] {
  if (!scenarios.length || !evidence.length || !run) return [];
  const sector = normalize(run.request.sector || "");
  const matches = scenarios
    .map((scenario) => scoreScenario(scenario, evidence, run.domains, sector))
    .filter((item): item is ScenarioMatch => Boolean(item))
    .sort((a, b) => b.score - a.score);
  const seen = new Set<string>();
  return matches.filter((match) => {
    const key = `${match.scenario.frameworks.attack.id}-${match.scenario.frameworks.disarm.id}-${match.scenario.frameworks.d3fend.id}-${match.scenario.frameworks.f3?.id ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 60);
}

function scoreScenario(scenario: DisinformationScenario, evidence: EvidenceSignal[], domains: string[], sector: string): ScenarioMatch | null {
  const reasons = new Set<string>();
  const matchedDomains = new Set<string>();
  let primaryFramework: FrameworkKey = "attack";
  const attackMatches = evidence.filter((signal) =>
    signal.technique === scenario.frameworks.attack.id && signal.attackMappingStatus === "observed_adversary_behavior"
  );
  const disarmCandidates = evidence.filter((signal) =>
    signal.disarmSignal && signal.frameworkIds.has(scenario.frameworks.disarm.id.toUpperCase())
  );
  const independentDisarmSources = new Set(disarmCandidates.flatMap((signal) => signal.sourceRefs));
  const disarmMatches = disarmCandidates.length >= 2 && independentDisarmSources.size >= 2 ? disarmCandidates : [];
  const atlasMatches = evidence.filter((signal) =>
    signal.atlasSignal && signal.confidenceScore >= 0.65 && signal.frameworkIds.has(scenario.frameworks.atlas.id.toUpperCase())
  );
  const f3Id = scenario.frameworks.f3?.id?.toUpperCase() ?? "";
  const f3Matches = evidence.filter((signal) =>
    Boolean(f3Id) && signal.f3Signal && signal.frameworkIds.has(f3Id)
  );
  let matched: EvidenceSignal[] = [];
  if (f3Matches.length) {
    matched = f3Matches;
    primaryFramework = "f3";
    reasons.add(`F3 ${scenario.frameworks.f3?.id}`);
  } else if (attackMatches.length) {
    matched = attackMatches;
    primaryFramework = "attack";
    reasons.add(`ATT&CK ${scenario.frameworks.attack.id}`);
  } else if (disarmMatches.length) {
    matched = disarmMatches;
    primaryFramework = "disarm";
    reasons.add(`DISARM ${scenario.frameworks.disarm.id}`);
  } else if (atlasMatches.length) {
    matched = atlasMatches;
    primaryFramework = "atlas";
    reasons.add(`ATLAS ${scenario.frameworks.atlas.id}`);
  }
  if (!matched.length) return null;
  matched.forEach((signal) => signal.domains.forEach((domain) => matchedDomains.add(domain)));
  const evidenceCount = matched.length;
  if (!matchedDomains.size) {
    if (domains.length === 1) matchedDomains.add(domains[0]);
    else matchedDomains.add(GROUP_SCOPE);
  }
  const meanConfidence = matched.reduce((sum, signal) => sum + signal.confidenceScore, 0) / evidenceCount;
  const sectorContext = sector && normalize(scenario.sector).includes(sector) ? 2 : 0;
  const score = meanConfidence * 100 + evidenceCount * 5 + sectorContext;
  const confidence = Math.min(95, Math.round(meanConfidence * 100));
  const fallbackReason = scenario.frameworks.f3?.id
    ? `F3 ${scenario.frameworks.f3.id}`
    : scenario.frameworks.attack.id
      ? `ATT&CK ${scenario.frameworks.attack.id}`
      : scenario.frameworks.disarm.tactic;
  return {
    scenario,
    score,
    confidence,
    reasons: [...reasons].slice(0, 4).length ? [...reasons].slice(0, 4) : [fallbackReason],
    domains: [...matchedDomains],
    evidenceCount,
    primaryFramework
  };
}

function buildDomainCards(run: RunRecord | undefined, matches: ScenarioMatch[], evidence: EvidenceSignal[]): DomainCard[] {
  if (!run) return [];
  const signals = run.summary.domain_signals ?? [];
  const byDomain = new Map(signals.map((item) => [item.domain, item]));
  const groupMatches = matches.filter((match) => match.domains.includes(GROUP_SCOPE));
  const groupCard = {
    domain: run.request.person_name || run.request.organization_name || run.domains.join(", "),
    scope: GROUP_SCOPE,
    signalCount: evidence.length,
    maxRisk: Math.round(run.summary.kpis.max_residual_risk ?? 0),
    topScenario: groupMatches[0] ?? matches[0]
  };
  const domainCards = run.domains.map((domain) => {
    const signal = byDomain.get(domain);
    const signalCount = signal?.events ?? evidence.filter((item) => item.domains.includes(domain)).length;
    const domainMatches = matches.filter((match) => match.domains.includes(domain));
    return {
      domain,
      scope: domain,
      signalCount,
      maxRisk: Math.round(signal?.max_residual_risk ?? run.summary.kpis.max_residual_risk ?? 0),
      topScenario: signalCount > 0 ? domainMatches[0] : undefined
    };
  });
  return [groupCard, ...domainCards];
}

function buildScopeOptions(run: RunRecord | undefined, allLabel: string, groupLabel: string): Array<{ id: string; label: string }> {
  if (!run) return [];
  const group = run.request.person_name || run.request.organization_name || groupLabel;
  return [
    { id: ALL_SCOPE, label: allLabel },
    { id: GROUP_SCOPE, label: group },
    ...run.domains.map((domain) => ({ id: domain, label: domain }))
  ];
}

function filterMatchesByScopes(matches: ScenarioMatch[], selectedScopes: string[]): ScenarioMatch[] {
  if (!selectedScopes.length || selectedScopes.includes(ALL_SCOPE)) return matches;
  const selected = new Set(selectedScopes);
  return matches.filter((match) => match.domains.some((domain) => selected.has(domain)));
}

function filterDomainCardsByScopes(cards: DomainCard[], selectedScopes: string[]): DomainCard[] {
  if (!selectedScopes.length || selectedScopes.includes(ALL_SCOPE)) return cards;
  const selected = new Set(selectedScopes);
  return cards.filter((card) => selected.has(card.scope));
}

function frameworkCoverage(matches: ScenarioMatch[]): Array<{ key: FrameworkKey; value: number }> {
  const sets: Record<FrameworkKey, Set<string>> = {
    attack: new Set(),
    d3fend: new Set(),
    atlas: new Set(),
    disarm: new Set(),
    f3: new Set()
  };
  matches.forEach((match) => {
    if (match.scenario.frameworks.attack.id) sets.attack.add(match.scenario.frameworks.attack.id);
    if (match.scenario.frameworks.d3fend.id) sets.d3fend.add(match.scenario.frameworks.d3fend.id);
    if (match.scenario.frameworks.atlas.id) sets.atlas.add(match.scenario.frameworks.atlas.id);
    if (match.scenario.frameworks.disarm.id) sets.disarm.add(match.scenario.frameworks.disarm.id);
    if (match.scenario.frameworks.f3?.id) sets.f3.add(match.scenario.frameworks.f3.id);
  });
  return (Object.keys(sets) as FrameworkKey[]).map((key) => ({ key, value: sets[key].size }));
}

function scenarioDisplayTitle(match: ScenarioMatch, language: LanguageMode): string {
  const family = scenarioFamily(match);
  const titles: Record<LanguageMode, Record<ScenarioFamily, string>> = {
    es: {
      exploit: "Explotación y exposición técnica",
      identity: "Identidad y acceso bajo presión",
      fraud: "Fraude digital y abuso de confianza",
      influence: "Influencia pública y narrativa de riesgo",
      ai: "Abuso de IA y automatización",
      continuity: "Continuidad y extorsión operacional",
      general: "Escenario multi-framework priorizado"
    },
    en: {
      exploit: "Exploitation and technical exposure",
      identity: "Identity and access pressure",
      fraud: "Digital fraud and trust abuse",
      influence: "Public influence and narrative risk",
      ai: "AI abuse and automation",
      continuity: "Operational continuity and extortion",
      general: "Prioritized multi-framework scenario"
    }
  };
  return `${match.scenario.id} · ${titles[language][family]}`;
}

function scenarioQuestion(match: ScenarioMatch, language: LanguageMode): string {
  return scenarioDecisionLens(match, language).question;
}

function scenarioDecision(match: ScenarioMatch, language: LanguageMode): string {
  return scenarioDecisionLens(match, language).decision;
}

function scenarioCriteria(match: ScenarioMatch, language: LanguageMode): string {
  return scenarioDecisionLens(match, language).criteria.replace(/^[^:]{1,90}:\s*/, "");
}

function scenarioFamily(match: ScenarioMatch): ScenarioFamily {
  const scenario = match.scenario;
  const text = normalize([
    scenario.title_es,
    scenario.title_en,
    scenario.sector,
    scenario.frameworks.attack.name,
    scenario.frameworks.attack.tactics.join(" "),
    scenario.frameworks.disarm.name,
    scenario.frameworks.disarm.tactic,
    scenario.frameworks.d3fend.name,
    scenario.frameworks.atlas.name,
    scenario.frameworks.f3?.name ?? "",
    match.reasons.join(" ")
  ].join(" "));
  if (/ransom|extortion|backup|continuity|destruct|wipe|availability|impact/.test(text)) return "continuity";
  if (/fraud|payment|bec|imperson|brand|correo|email|trust/.test(text)) return "fraud";
  if (/narrative|publication|content|influence|propaganda|disinform|fake|viral/.test(text)) return "influence";
  if (/\bai\b|atlas|model|prompt|machine|automation/.test(text)) return "ai";
  if (/exploit|vulnerab|cve|kev|rce|bypass|injection|exposure|access/.test(text)) return "exploit";
  if (/credential|account|identity|mfa|session|login|valid account|phishing/.test(text)) return "identity";
  return "general";
}

function scenarioDecisionLens(match: ScenarioMatch, language: LanguageMode): DecisionLens {
  const family = scenarioFamily(match);
  const primaryDomain = formatMatchDomains(match.domains, language === "es" ? "grupo general" : "overall group");
  const attack = `${match.scenario.frameworks.attack.id} ${match.scenario.frameworks.attack.name}`;
  const control = `${match.scenario.frameworks.d3fend.id} ${match.scenario.frameworks.d3fend.name}`;
  const atlas = `${match.scenario.frameworks.atlas.id} ${match.scenario.frameworks.atlas.name}`;
  const disarm = `${match.scenario.frameworks.disarm.id} ${match.scenario.frameworks.disarm.name}`;
  const f3 = match.scenario.frameworks.f3?.id
    ? `${match.scenario.frameworks.f3.id} ${match.scenario.frameworks.f3.name}`
    : language === "es" ? "F3 sin mapeo" : "F3 not mapped";
  const support = formatScenarioRisk(match.confidence, language);
  const signal = match.reasons.slice(0, 2).join(" / ");

  if (language === "en") {
    const catalog: Record<ScenarioFamily, DecisionLens> = {
      exploit: {
        criteria: "CISM/CyBOK/ISO/COBIT: risk appetite, vulnerability management, control evidence, KRI and treatment owner.",
        question: `For ${primaryDomain}, does evidence support ${support} justify comparing ${attack}, ${disarm} and ${atlas} against the defined appetite/tolerance for exposed services?`,
        decision: `Evaluate the risk treatment path for ${attack}: mitigate with ${control}, document a temporary exception, or formally accept if ${disarm} and the evidence remain below threshold; assign owner, KRI and review date.`
      },
      identity: {
        criteria: "CISM/CIPM/CyBOK: identity governance, human factor, privacy, privileged access and monitoring evidence.",
        question: `For ${primaryDomain}, does ${attack} with ${disarm} and evidence support ${support} indicate credential, session or privilege exposure that current ${control} does not sufficiently reduce?`,
        decision: `Consider a scoped identity review for ${control}: phishing-resistant MFA/PAM, exposed-account validation, privacy-aware monitoring and ${atlas} oversight before broad enforcement changes.`
      },
      fraud: {
        criteria: "CISM/CISA/COBIT/CIPM: fraud accountability, evidence quality, customer impact, third parties and escalation controls.",
        question: `For ${primaryDomain}, can ${f3} with ${attack} plus ${disarm} enable impersonation, payment abuse or trust degradation in customer or employee channels?`,
        decision: `Evaluate F3 behavior ${f3}: channel validation, identity and payment controls, takedown/legal coordination, transaction monitoring and customer-communication thresholds based on evidence quality.`
      },
      influence: {
        criteria: "Threat intelligence/CISM/CyBOK: intelligence requirement, source confidence, narrative reach, reputation and risk communication.",
        question: `For ${primaryDomain}, does ${disarm} represent a narrative or influence risk with enough source confidence and reach to affect strategic trust?`,
        decision: `For ${disarm}, consider monitoring, communications or takedown only after separating source, channel, audience and amplification; keep it as a possibility until coordination is evidenced.`
      },
      ai: {
        criteria: "CISM/CyBOK/ATLAS: AI governance, human oversight, traceability, automated decisions and control testing.",
        question: `For ${primaryDomain}, can ${atlas} amplify ${attack} and ${disarm} through automation, content generation or model-enabled scale beyond current oversight?`,
        decision: `Evaluate AI governance controls for ${atlas}: human approval points, prompt/log traceability, abuse monitoring and integration limits before prioritizing executive investment.`
      },
      continuity: {
        criteria: "CISM/CyBOK/ISO: BIA, RTO/RPO, incident roles, recovery testing, crisis communication and resilience metrics.",
        question: `For ${primaryDomain}, does evidence support ${support} justify evaluating whether ${attack} and ${disarm} can affect continuity thresholds or crisis criteria?`,
        decision: `Consider continuity preparation for ${attack}: restore validation, segmentation, EDR/NDR coverage, supplier dependency review and a tabletop if evidence crosses the KRI threshold.`
      },
      general: {
        criteria: "CISM/CISA/CyBOK: governance, risk ownership, evidence sufficiency, control gap and decision traceability.",
        question: `For ${primaryDomain}, what decision is justified by ${match.evidenceCount} evidence signals, confidence ${match.confidence}% and the mapped control ${control}?`,
        decision: `Assign a risk owner, minimum evidence threshold and next validation source before turning this scenario into action or investment.`
      }
    };
    return enrichDecisionLens(catalog[family], match, language, signal, family);
  }

  const catalog: Record<ScenarioFamily, DecisionLens> = {
    exploit: {
      criteria: "CISM/CyBOK/ISO/COBIT: apetito de riesgo, gestión de vulnerabilidades, evidencia de control, KRI y dueño de tratamiento.",
      question: `Para ${primaryDomain}, ¿el soporte de evidencia ${support} justifica contrastar ${attack}, ${disarm} y ${atlas} con el apetito/tolerancia definido para servicios expuestos?`,
      decision: `Evaluar ruta de tratamiento del riesgo para ${attack}: mitigar con ${control}, documentar excepción temporal o aceptar formalmente si ${disarm} y la evidencia quedan bajo umbral; asignar dueño, KRI y fecha de revisión.`
    },
    identity: {
      criteria: "CISM/CIPM/CyBOK: gobierno de identidad, factor humano, privacidad, acceso privilegiado y evidencia de monitoreo.",
      question: `Para ${primaryDomain}, ¿${attack} con ${disarm} y soporte ${support} indica exposición de credenciales, sesión o privilegios que ${control} no reduce suficientemente?`,
      decision: `Considerar revisión acotada de identidad para ${control}: MFA resistente a phishing/PAM, validación de cuentas expuestas, monitoreo con criterio de privacidad y supervisión ${atlas} antes de cambios amplios.`
    },
    fraud: {
      criteria: "CISM/CISA/COBIT/CIPM: responsabilidad antifraude, calidad de evidencia, impacto a clientes, terceros y controles de escalamiento.",
      question: `Para ${primaryDomain}, ¿${f3} junto con ${attack} y ${disarm} puede habilitar suplantación, abuso de pagos o deterioro de confianza en canales de clientes o empleados?`,
      decision: `Evaluar la conducta F3 ${f3}: validación de canales, controles de identidad y pago, coordinación legal/takedown, monitoreo transaccional y umbrales de comunicación ligados a calidad de evidencia.`
    },
    influence: {
      criteria: "Threat Intelligence/CISM/CyBOK: requerimiento de inteligencia, confianza de fuente, alcance narrativo, reputación y comunicación de riesgo.",
      question: `Para ${primaryDomain}, ¿${disarm} representa riesgo narrativo o de influencia con suficiente confianza de fuente y alcance para afectar la confianza estratégica?`,
      decision: `Para ${disarm}, considerar monitoreo, comunicación o takedown solo tras separar fuente, canal, audiencia y amplificación; mantenerlo como posibilidad hasta evidenciar coordinación.`
    },
    ai: {
      criteria: "CISM/CyBOK/ATLAS: gobierno de IA, supervisión humana, trazabilidad, decisiones automatizadas y prueba de controles.",
      question: `Para ${primaryDomain}, ¿${atlas} puede amplificar ${attack} y ${disarm} mediante automatización, generación de contenido o escala habilitada por modelos más allá de la supervisión actual?`,
      decision: `Evaluar controles de gobierno de IA para ${atlas}: puntos de aprobación humana, trazabilidad de prompts/logs, monitoreo de abuso y límites de integración antes de priorizar inversión ejecutiva.`
    },
    continuity: {
      criteria: "CISM/CyBOK/ISO: BIA, RTO/RPO, roles de incidente, pruebas de recuperación, comunicación de crisis y métricas de resiliencia.",
      question: `Para ${primaryDomain}, ¿el soporte de evidencia ${support} justifica evaluar si ${attack} y ${disarm} pueden afectar continuidad o criterios de crisis?`,
      decision: `Considerar preparación de continuidad para ${attack}: validación de restauración, segmentación, cobertura EDR/NDR, revisión de proveedores críticos y tabletop si la evidencia cruza el KRI.`
    },
    general: {
      criteria: "CISM/CISA/CyBOK: gobierno, dueño de riesgo, suficiencia de evidencia, brecha de control y trazabilidad de decisión.",
      question: `Para ${primaryDomain}, ¿qué decisión justifica ${match.evidenceCount} señales, confianza ${match.confidence}% y el control mapeado ${control}?`,
      decision: `Asignar dueño de riesgo, umbral mínimo de evidencia y próxima fuente de validación antes de convertir el escenario en acción o inversión.`
    }
  };
  return enrichDecisionLens(catalog[family], match, language, signal, family);
}

function enrichDecisionLens(base: DecisionLens, match: ScenarioMatch, language: LanguageMode, signal: string, family: ScenarioFamily): DecisionLens {
  const framework = frameworkName(match.primaryFramework);
  const horizon = decisionHorizon(match.confidence, language);
  const vector = scenarioStrategicVector(match, family, language);
  const questionVariant = scenarioTemplateText(match, language, family, "questions");
  const decisionVariant = scenarioTemplateText(match, language, family, "decisions");
  const signalText = signal || (language === "es" ? "sin señal narrativa dominante; usar evidencia técnica y fuente" : "no dominant narrative signal; use technical evidence and source");
  if (language === "en") {
    return {
      criteria: base.criteria,
      question: `${questionVariant} Verification point: scenario ${match.scenario.id}, primary framework ${framework}, dominant signal "${signalText}" and ${match.evidenceCount} evidence item(s).`,
      decision: `${decisionVariant} Framework contrast: ${base.decision} Strategic vector: ${vector}; horizon ${horizon}; validate one additional source before escalation or budget allocation.`
    };
  }
  return {
    criteria: base.criteria,
    question: `${questionVariant} Punto de verificación: escenario ${match.scenario.id}, framework primario ${framework}, señal dominante "${signalText}" y ${match.evidenceCount} evidencia(s).`,
    decision: `${decisionVariant} Contraste de marco: ${base.decision} Vector estratégico: ${vector}; horizonte ${horizon}; validar una fuente adicional antes de escalar o asignar presupuesto.`
  };
}

function scenarioTemplateText(match: ScenarioMatch, language: LanguageMode, family: ScenarioFamily, kind: "questions" | "decisions"): string {
  const variants = scenarioTextCatalog[language][family][kind];
  const seed = hashString(`${match.scenario.id}:${match.primaryFramework}:${kind}:${match.domains.join("|")}:${match.evidenceCount}:${match.confidence}`);
  const template = variants[seed % variants.length] ?? variants[0];
  return hydrateScenarioTemplate(template, match, language);
}

function hydrateScenarioTemplate(template: string, match: ScenarioMatch, language: LanguageMode): string {
  const primaryDomain = formatMatchDomains(match.domains, language === "es" ? "grupo general" : "overall group");
  const replacements: Record<string, string> = {
    domain: primaryDomain,
    attack: `${match.scenario.frameworks.attack.id} ${match.scenario.frameworks.attack.name}`,
    control: `${match.scenario.frameworks.d3fend.id} ${match.scenario.frameworks.d3fend.name}`,
    atlas: `${match.scenario.frameworks.atlas.id} ${match.scenario.frameworks.atlas.name}`,
    disarm: `${match.scenario.frameworks.disarm.id} ${match.scenario.frameworks.disarm.name}`,
    f3: `${match.scenario.frameworks.f3?.id ?? ""} ${match.scenario.frameworks.f3?.name ?? ""}`.trim()
  };
  return template.replace(/\{(domain|attack|control|atlas|disarm|f3)\}/g, (_, key: string) => replacements[key] ?? "");
}

function hashString(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function frameworkName(key: FrameworkKey): string {
  return { attack: "ATT&CK", d3fend: "D3FEND", atlas: "ATLAS", disarm: "DISARM", f3: "F3" }[key];
}

function decisionHorizon(confidence: number, language: LanguageMode): string {
  if (confidence >= 78) return language === "es" ? "inmediato 0-7 dias" : "immediate 0-7 days";
  if (confidence >= 58) return language === "es" ? "corto plazo 7-30 dias" : "short term 7-30 days";
  return language === "es" ? "observacion 30+ dias" : "watch 30+ days";
}

function scenarioStrategicVector(match: ScenarioMatch, family: ScenarioFamily, language: LanguageMode): string {
  const vectors = {
    es: {
      attack: "control técnico, remediación y validación de exposición",
      d3fend: "efectividad de control, monitoreo y evidencia de cobertura",
      atlas: "gobierno de automatización, IA y trazabilidad de decisión",
      disarm: "narrativa pública, reputación y respuesta coordinada",
      f3: "conducta antifraude, identidad, transacción y protección de marca",
      exploit: "reducir superficie y confirmar activos críticos",
      identity: "proteger identidad, sesión y privilegios",
      fraud: "prevenir abuso de marca, pagos y confianza del cliente",
      influence: "separar fuente, audiencia, canal y amplificación",
      ai: "limitar escala automatizada y supervisar decisiones",
      continuity: "probar resiliencia, recuperación y comunicación de crisis",
      general: "validar suficiencia de evidencia y dueño de riesgo"
    },
    en: {
      attack: "technical control, remediation and exposure validation",
      d3fend: "control effectiveness, monitoring and coverage evidence",
      atlas: "automation, AI governance and decision traceability",
      disarm: "public narrative, reputation and coordinated response",
      f3: "fraud behavior, identity, transaction and brand protection",
      exploit: "reduce surface and confirm critical assets",
      identity: "protect identity, session and privileges",
      fraud: "prevent brand, payment and customer-trust abuse",
      influence: "separate source, audience, channel and amplification",
      ai: "limit automated scale and supervise decisions",
      continuity: "test resilience, recovery and crisis communication",
      general: "validate evidence sufficiency and risk ownership"
    }
  }[language];
  return `${vectors[match.primaryFramework]}; ${vectors[family]}`;
}

function formatScenarioRisk(value: number | undefined, language: LanguageMode): string {
  const raw = Number(value ?? 0);
  const percent = raw > 0 && raw <= 1 ? raw * 100 : raw;
  return `${Math.round(percent)}${language === "es" ? " %" : "%"}`;
}

function formatMatchDomains(domains: string[], fallback: string): string {
  const visible = domains.filter((domain) => domain !== GROUP_SCOPE);
  return visible.length ? visible.join(", ") : fallback;
}

function domainsInText(text: string, domains: string[]): string[] {
  const normalized = normalize(text);
  return domains.filter((domain) => normalized.includes(normalize(domain)));
}

function extractTechnique(text: string): string | null {
  const match = text.match(/T\d{4}(?:\.\d{3})?/i);
  return match ? match[0].toUpperCase() : null;
}

function tokenize(text: string): Set<string> {
  return new Set(
    normalize(text)
      .split(/[^a-z0-9]+/)
      .map(stemToken)
      .filter((token) => token.length > 2)
  );
}

function stemToken(token: string): string {
  if (token.startsWith("exploit")) return "exploit";
  if (token.startsWith("vulnerab")) return "vulnerability";
  if (token.startsWith("credential")) return "credential";
  if (token.startsWith("phish")) return "phishing";
  if (token.startsWith("detect")) return "detect";
  if (token.startsWith("narrativ")) return "narrative";
  if (token.startsWith("publicat")) return "publication";
  if (token.startsWith("influenc")) return "influence";
  if (token.startsWith("control")) return "control";
  return token;
}

function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="dashboard-metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
