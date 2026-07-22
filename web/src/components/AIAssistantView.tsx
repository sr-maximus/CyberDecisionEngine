import { Bot, BrainCircuit, CheckCircle2, ClipboardCheck, Cpu, FileJson, KeyRound, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { createAIAnalysisPackage, getAIOrchestrationConfig } from "../api";
import type { AIAnalysisPackage, AIOrchestrationConfig, AIProvider, AIProviderDescriptor, LanguageMode, RunRecord } from "../types";

interface AIAssistantViewProps {
  run?: RunRecord;
  language: LanguageMode;
}

const copy = {
  es: {
    title: "IA estratégica controlada",
    subtitle: "Prepara análisis trazables y usa el gateway OpenClaw aislado cuando exista un modelo configurado y el borrador haya sido aprobado.",
    noRun: "Selecciona o ejecuta una corrida para construir un paquete IA con evidencia real.",
    providers: "Proveedores IA",
    promptInput: "Prompt orientado al análisis",
    promptInputHelp: "Edita el enfoque antes de generar el paquete. Si lo dejas vacío, se usa este prompt base defensivo.",
    budget: "Presupuesto de tokens",
    inputBudget: "Entrada",
    outputBudget: "Salida",
    audience: "Audiencia",
    depth: "Profundidad",
    objective: "Objetivo",
    instructions: "Instrucciones adicionales",
    generate: "Generar prompt y payload",
    approve: "Aprobar borrador local",
    approved: "Borrador aprobado localmente",
    pending: "Borrador pendiente de aprobación",
    context: "Contexto exacto",
    prompt: "Prompt maestro",
    systemPrompt: "System prompt editable",
    userPrompt: "User prompt editable",
    promptEditHelp: "Puedes ajustar estos textos antes de aprobar el paquete local. La ejecución externa sigue deshabilitada hasta configurar credenciales.",
    payloads: "Payloads por proveedor",
    guardrails: "Reglas anti-alucinación",
    evidence: "Manifiesto de evidencia",
    providerHint: "El estado distingue gateway operativo de modelo disponible. Las credenciales se gestionan fuera del navegador.",
    tokenFit: "Disponible",
    tokenUsed: "Estimado",
    automation: "Automatización deshabilitada hasta aprobar prompt, credenciales y gateway.",
    objectiveStrategic: "Análisis estratégico",
    objectiveSearch: "Plan de búsqueda aumentada",
    searchModeHint: "OpenClaw propondrá consultas, reintentos y mejoras de fuente. CyberDecisionEngine ejecuta solo colectores permitidos tras aprobación.",
    options: {
      executive: "Directivo",
      technical: "Técnico",
      board: "Junta",
      incident: "Incidente",
      fraud: "Fraude",
      standard: "Estándar",
      deep: "Profundo",
      boardDepth: "Junta"
    }
  },
  en: {
    title: "Controlled strategic AI",
    subtitle: "Prepare traceable analysis and use the isolated OpenClaw gateway when a model is configured and the draft is approved.",
    noRun: "Select or run an analysis to build an AI package from real evidence.",
    providers: "AI providers",
    promptInput: "Analysis-oriented prompt",
    promptInputHelp: "Edit the focus before generating the package. If left empty, this defensive base prompt is used.",
    budget: "Token budget",
    inputBudget: "Input",
    outputBudget: "Output",
    audience: "Audience",
    depth: "Depth",
    objective: "Objective",
    instructions: "Additional instructions",
    generate: "Generate prompt and payload",
    approve: "Approve local draft",
    approved: "Draft approved locally",
    pending: "Draft pending approval",
    context: "Exact context",
    prompt: "Master prompt",
    systemPrompt: "Editable system prompt",
    userPrompt: "Editable user prompt",
    promptEditHelp: "You can adjust these texts before approving the local package. External execution remains disabled until credentials are configured.",
    payloads: "Provider payloads",
    guardrails: "Anti-hallucination rules",
    evidence: "Evidence manifest",
    providerHint: "Status distinguishes an operational gateway from an available model. Credentials stay outside the browser.",
    tokenFit: "Available",
    tokenUsed: "Estimated",
    automation: "Automation disabled until prompt, credentials and gateway are approved.",
    objectiveStrategic: "Strategic analysis",
    objectiveSearch: "Augmented search plan",
    searchModeHint: "OpenClaw will propose queries, retries and source improvements. CyberDecisionEngine executes only allowlisted collectors after approval.",
    options: {
      executive: "Executive",
      technical: "Technical",
      board: "Board",
      incident: "Incident",
      fraud: "Fraud",
      standard: "Standard",
      deep: "Deep",
      boardDepth: "Board"
    }
  }
};

const defaultProviders: AIProvider[] = ["openai", "openclaw_gateway"];

export function AIAssistantView({ run, language }: AIAssistantViewProps) {
  const labels = copy[language];
  const [config, setConfig] = useState<AIOrchestrationConfig | null>(null);
  const [providers, setProviders] = useState<AIProvider[]>(defaultProviders);
  const [audience, setAudience] = useState<"executive" | "technical" | "board" | "incident" | "fraud">("executive");
  const [depth, setDepth] = useState<"standard" | "deep" | "board">("deep");
  const [objective, setObjective] = useState("decision_intelligence");
  const [inputBudget, setInputBudget] = useState(12000);
  const [outputBudget, setOutputBudget] = useState(4000);
  const [customInstructions, setCustomInstructions] = useState("");
  const [aiPackage, setAiPackage] = useState<AIAnalysisPackage | null>(null);
  const [systemPromptDraft, setSystemPromptDraft] = useState("");
  const [userPromptDraft, setUserPromptDraft] = useState("");
  const [approved, setApproved] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAIOrchestrationConfig().then(setConfig).catch((exc) => setError(exc instanceof Error ? exc.message : String(exc)));
  }, []);

  const tokenPercent = useMemo(() => {
    if (!aiPackage) return 0;
    return Math.min(100, Math.round(((aiPackage.token_estimate.input_total ?? 0) / inputBudget) * 100));
  }, [aiPackage, inputBudget]);
  const providerCatalog: AIProviderDescriptor[] = config?.provider_catalog?.length
    ? config.provider_catalog
    : defaultProviders.map((provider) => ({
        key: provider,
        label: provider === "openclaw_gateway" ? "OpenClaw Gateway" : provider.toUpperCase(),
        endpoint_hint: "",
        model_hint: "Configure API key in Settings",
        headers_required: [],
        enabled: false
      }));
  const defaultPrompt = useMemo(() => strategicPrompt(language, run), [language, run]);

  useEffect(() => {
    setSystemPromptDraft(aiPackage?.system_prompt ?? "");
    setUserPromptDraft(aiPackage?.user_prompt ?? "");
  }, [aiPackage]);

  function toggleProvider(provider: AIProvider) {
    setProviders((current) => {
      if (current.includes(provider)) return current.filter((item) => item !== provider);
      return [...current, provider];
    });
  }

  function selectObjectiveMode(mode: "strategic" | "search") {
    if (mode === "search") {
      setObjective("evidence_search_planning");
      setCustomInstructions(searchPlanningPrompt(language, run));
      setDepth("deep");
      setProviders((current) => (current.includes("openclaw_gateway") ? current : [...current, "openclaw_gateway"]));
      return;
    }
    setObjective("decision_intelligence");
    setCustomInstructions(strategicPrompt(language, run));
  }

  async function generatePackage() {
    if (!run || !providers.length) return;
    setLoading(true);
    setError(null);
    setApproved(false);
    try {
      const nextPackage = await createAIAnalysisPackage({
        run_id: run.id,
        providers,
        audience,
        depth,
        objective,
        language,
        input_token_budget: inputBudget,
        output_token_budget: outputBudget,
        include_findings_limit: 12,
        include_events_limit: 30,
        custom_instructions: customInstructions.trim() || defaultPrompt
      });
      setAiPackage(nextPackage);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setLoading(false);
    }
  }

  if (!run) {
    return (
      <section className="dashboard-grid ai-dashboard-grid">
        <article className="panel chart-card span-12 ai-hero">
          <Bot size={24} />
          <div>
            <h2>{labels.title}</h2>
            <p>{labels.subtitle}</p>
          </div>
          <div className="chart-empty">{labels.noRun}</div>
        </article>
      </section>
    );
  }

  return (
    <div className="view-stack">
      <section className="dashboard-grid ai-dashboard-grid">
        <article className="panel chart-card span-12 ai-hero">
          <Bot size={24} />
          <div>
            <h2>{labels.title}</h2>
            <p>{labels.subtitle}</p>
          </div>
          <span className={approved ? "ai-status approved" : "ai-status"}>{approved ? labels.approved : labels.pending}</span>
        </article>

        <article className="panel chart-card span-6 ai-control-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.providers}</h2>
              <p>{labels.providerHint}</p>
            </div>
            <KeyRound size={18} />
          </div>
          <div className="ai-provider-list">
            {providerCatalog.map((provider) => (
              <button className={providers.includes(provider.key) ? "selected" : ""} key={provider.key} onClick={() => toggleProvider(provider.key)}>
                <span>{provider.label}</span>
                <small>{provider.model_hint}</small>
                {provider.key === "openclaw_gateway" ? (
                  <em>
                    {provider.enabled
                      ? provider.model_status === "available"
                        ? language === "es" ? "Gateway y modelo disponibles" : "Gateway and model available"
                        : provider.model_status === "configured_unverified"
                          ? language === "es" ? "Gateway activo · credencial de modelo por validar" : "Gateway ready · model credential unverified"
                          : language === "es" ? "Gateway activo · modelo pendiente" : "Gateway ready · model pending"
                      : language === "es" ? "Gateway no disponible" : "Gateway unavailable"}
                  </em>
                ) : null}
              </button>
            ))}
          </div>
          <div className="settings-form settings-stack">
            <select value={audience} onChange={(event) => setAudience(event.target.value as typeof audience)}>
              <option value="executive">{labels.options.executive}</option>
              <option value="technical">{labels.options.technical}</option>
              <option value="board">{labels.options.board}</option>
              <option value="incident">{labels.options.incident}</option>
              <option value="fraud">{labels.options.fraud}</option>
            </select>
            <select value={depth} onChange={(event) => setDepth(event.target.value as typeof depth)}>
              <option value="standard">{labels.options.standard}</option>
              <option value="deep">{labels.options.deep}</option>
              <option value="board">{labels.options.boardDepth}</option>
            </select>
            <input value={objective} onChange={(event) => setObjective(event.target.value)} placeholder={labels.objective} />
            <div className="ai-mode-actions">
              <button className="secondary-button compact" type="button" onClick={() => selectObjectiveMode("strategic")}>
                {labels.objectiveStrategic}
              </button>
              <button className="secondary-button compact" type="button" onClick={() => selectObjectiveMode("search")}>
                {labels.objectiveSearch}
              </button>
            </div>
            <em className="ai-mode-hint">{labels.searchModeHint}</em>
            <label className="ai-prompt-input">
              <span>{labels.promptInput}</span>
              <textarea value={customInstructions} onChange={(event) => setCustomInstructions(event.target.value)} placeholder={defaultPrompt} />
              <em>{labels.promptInputHelp}</em>
            </label>
            <button className="primary-button" onClick={generatePackage} disabled={loading || !providers.length}>
              <Sparkles size={17} />
              <span>{labels.generate}</span>
            </button>
            {error ? <div className="error-banner inline">{error}</div> : null}
          </div>
        </article>

        <article className="panel chart-card span-3 ai-token-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.budget}</h2>
              <p>{labels.automation}</p>
            </div>
            <Cpu size={18} />
          </div>
          <div className="ai-budget-grid">
            <label>
              <span>{labels.inputBudget}</span>
              <input type="number" min={2000} max={64000} step={1000} value={inputBudget} onChange={(event) => setInputBudget(Number(event.target.value))} />
            </label>
            <label>
              <span>{labels.outputBudget}</span>
              <input type="number" min={1000} max={32000} step={500} value={outputBudget} onChange={(event) => setOutputBudget(Number(event.target.value))} />
            </label>
          </div>
          <div className="ai-token-meter">
            <span style={{ width: `${tokenPercent}%` }} />
          </div>
          <div className="ai-token-readout">
            <strong>{labels.tokenUsed}: {aiPackage?.token_estimate.input_total ?? 0}</strong>
            <em>{labels.tokenFit}: {aiPackage?.token_estimate.budget_remaining ?? inputBudget}</em>
          </div>
        </article>

        <article className="panel chart-card span-3 compact-card ai-guardrail-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.guardrails}</h2>
              <p>{aiPackage?.prompt_version ?? config?.prompt_version}</p>
            </div>
            <ShieldCheck size={18} />
          </div>
          <div className="ai-guardrail-list">
            {(aiPackage?.guardrails ?? []).map((guardrail) => (
              <span key={guardrail}>{guardrail}</span>
            ))}
            {!aiPackage ? <div className="chart-empty">{labels.generate}</div> : null}
          </div>
        </article>

        <article className="panel chart-card span-6 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.context}</h2>
              <p>{run.request.person_name || run.request.organization_name || run.domains.join(", ")}</p>
            </div>
            <BrainCircuit size={18} />
          </div>
          <pre className="ai-code-block">{JSON.stringify(aiPackage?.context_digest ?? { run_id: run.id, status: run.status }, null, 2)}</pre>
        </article>

        <article className="panel chart-card span-6 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.evidence}</h2>
              <p>{aiPackage?.approval_question ?? labels.pending}</p>
            </div>
            <ClipboardCheck size={18} />
          </div>
          <pre className="ai-code-block">{JSON.stringify(aiPackage?.evidence_manifest ?? {}, null, 2)}</pre>
          <button className="primary-button subtle" onClick={() => setApproved(true)} disabled={!aiPackage}>
            <CheckCircle2 size={17} />
            <span>{labels.approve}</span>
          </button>
        </article>

        <article className="panel chart-card span-12 scroll-card ai-prompt-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.prompt}</h2>
              <p>{aiPackage?.approval_question ?? labels.promptEditHelp}</p>
            </div>
            <FileJson size={18} />
          </div>
          <div className="ai-prompt-grid">
            <label>
              <span>{labels.systemPrompt}</span>
              <textarea value={systemPromptDraft} onChange={(event) => setSystemPromptDraft(event.target.value)} placeholder="System prompt" />
            </label>
            <label>
              <span>{labels.userPrompt}</span>
              <textarea value={userPromptDraft} onChange={(event) => setUserPromptDraft(event.target.value)} placeholder="User prompt" />
            </label>
          </div>
        </article>

        <article className="panel chart-card span-12 scroll-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{labels.payloads}</h2>
              <p>{labels.providerHint}</p>
            </div>
            <FileJson size={18} />
          </div>
          <pre className="ai-code-block">{JSON.stringify(aiPackage?.provider_payloads ?? [], null, 2)}</pre>
        </article>
      </section>
    </div>
  );
}

function strategicPrompt(language: LanguageMode, run?: RunRecord): string {
  const subject = run ? run.request.person_name || run.request.organization_name || run.domains.join(", ") : "the selected CyberDecisionEngine run";
  const runId = run?.id ?? "current";
  if (language === "en") {
    return `Act as a strategic cyberintelligence analyst. Use only the evidence from run ${runId} for ${subject}. Produce concise executive decisions, technical validation, risk forecast, attack-surface implications, SOCMINT/OSINT/Dark Web caveats, and actionable options. Do not invent facts; cite signal URLs when available and mark uncertainty.`;
  }
  return `Actua como analista senior de ciberinteligencia estrategica. Usa solo la evidencia de la corrida ${runId} para ${subject}. Entrega decisiones ejecutivas concisas, validacion tecnica, proyeccion de riesgo, implicaciones de superficie de ataque, salvedades OSINT/SOCMINT/Dark Web y opciones accionables. No inventes hechos; cita URLs de senales cuando existan y marca la incertidumbre.`;
}

function searchPlanningPrompt(language: LanguageMode, run?: RunRecord): string {
  const subject = run ? run.request.person_name || run.request.organization_name || run.domains.join(", ") : "the selected CyberDecisionEngine run";
  const runId = run?.id ?? "current";
  if (language === "en") {
    return `Create an augmented evidence-search plan for run ${runId} and ${subject}. Review source health, timeout/skipped/partial collectors, domains with low evidence, infrastructure, subdomains, technologies, exposed documents, OSINT/SOCMINT/brand-fraud/surface/dark-web gaps and authorized people-profile scope. Propose safe allowlisted queries for configured search engines such as Google CSE when available, retries, official APIs, caching, scheduling and false-positive checks. Do not execute anything or suggest block evasion.`;
  }
  return `Crea un plan de busqueda aumentada de evidencia para la corrida ${runId} y ${subject}. Revisa salud de fuentes, colectores timeout/skipped/partial, dominios con poca evidencia, infraestructura, subdominios, tecnologias, documentos expuestos, gaps OSINT/SOCMINT/marca-fraude/superficie/dark web y perfiles de personas dentro del consentimiento/alcance autorizado. Propone consultas permitidas para buscadores configurados como Google CSE cuando este disponible, reintentos seguros, APIs oficiales, cache, programacion y controles anti-falso positivo. No ejecutes nada ni sugieras evasion de bloqueos.`;
}
