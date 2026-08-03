import {
  Bot,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Database,
  FileChartColumn,
  FileCode2,
  Gauge,
  Layers3,
  LoaderCircle,
  MessageSquareText,
  RefreshCw,
  Send,
  ShieldCheck,
  Sparkles,
  SquareArrowOutUpRight,
  Target,
  Trash2
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  apiUrl,
  chatWithAI,
  generateRunReport,
  getAIOrchestrationConfig
} from "../api";
import type {
  AIChatScope,
  AIExecutionResult,
  AIOrchestrationConfig,
  LanguageMode,
  RunRecord,
  ViewKey
} from "../types";

interface AIAssistantViewProps {
  run?: RunRecord;
  language: LanguageMode;
  onGenerateReport?: (runId: string) => Promise<void>;
  onOpenView?: (view: ViewKey) => void;
}

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
  result?: AIExecutionResult;
}

interface ModuleOption {
  scope: AIChatScope;
  view: ViewKey;
  labelEs: string;
  labelEn: string;
}

const moduleOptions: ModuleOption[] = [
  { scope: "overview", view: "dashboards", labelEs: "Visión estratégica", labelEn: "Strategic overview" },
  { scope: "evidence", view: "dashboards", labelEs: "Evidencia", labelEn: "Evidence" },
  { scope: "risk", view: "dashboards", labelEs: "Riesgo", labelEn: "Risk" },
  { scope: "scenarios", view: "scenarios", labelEs: "Escenarios", labelEn: "Scenarios" },
  { scope: "frameworks", view: "frameworks", labelEs: "Frameworks", labelEn: "Frameworks" },
  { scope: "osint", view: "osint", labelEs: "OSINT", labelEn: "OSINT" },
  { scope: "socmint", view: "socmint", labelEs: "SOCMINT", labelEn: "SOCMINT" },
  { scope: "darkweb", view: "darkweb", labelEs: "Dark web", labelEn: "Dark web" },
  { scope: "attack_surface", view: "attackSurface", labelEs: "Superficie", labelEn: "Attack surface" },
  { scope: "brand_fraud", view: "brand", labelEs: "Marca y fraude", labelEn: "Brand and fraud" },
  { scope: "disinformation", view: "disinformation", labelEs: "Desinformación", labelEn: "Disinformation" },
  { scope: "geography", view: "dashboards", labelEs: "Geografía", labelEn: "Geography" },
  { scope: "vulnerabilities", view: "attackSurface", labelEs: "Vulnerabilidades", labelEn: "Vulnerabilities" }
];

const quickQuestions = {
  es: [
    {
      label: "Resumen ejecutivo",
      prompt: "Resume qué se analizó, qué se encontró, qué tan confiable es y cuáles son las tres decisiones prioritarias.",
      scopes: ["overview", "risk", "evidence"] as AIChatScope[]
    },
    {
      label: "Lectura técnica",
      prompt: "Explica los hallazgos técnicos, la evidencia que los sustenta, sus limitaciones y qué validaciones siguen pendientes.",
      scopes: ["evidence", "attack_surface", "vulnerabilities"] as AIChatScope[]
    },
    {
      label: "Riesgo y escenarios",
      prompt: "Explica el riesgo y los escenarios aplicables sin confundir presión de señales con probabilidad calibrada.",
      scopes: ["risk", "scenarios", "frameworks"] as AIChatScope[]
    },
    {
      label: "Calidad de evidencia",
      prompt: "Audita la cobertura, las fuentes, los vacíos de información, las contradicciones y el riesgo de falsos positivos.",
      scopes: ["evidence", "osint", "socmint", "darkweb"] as AIChatScope[]
    }
  ],
  en: [
    {
      label: "Executive brief",
      prompt: "Summarize what was analyzed, what was found, how reliable it is and the top three decision priorities.",
      scopes: ["overview", "risk", "evidence"] as AIChatScope[]
    },
    {
      label: "Technical reading",
      prompt: "Explain the technical findings, supporting evidence, limitations and pending validation checks.",
      scopes: ["evidence", "attack_surface", "vulnerabilities"] as AIChatScope[]
    },
    {
      label: "Risk and scenarios",
      prompt: "Explain applicable risk and scenarios without confusing signal pressure with calibrated probability.",
      scopes: ["risk", "scenarios", "frameworks"] as AIChatScope[]
    },
    {
      label: "Evidence quality",
      prompt: "Audit coverage, sources, information gaps, contradictions and false-positive risk.",
      scopes: ["evidence", "osint", "socmint", "darkweb"] as AIChatScope[]
    }
  ]
};

export function AIAssistantView({
  run,
  language,
  onGenerateReport,
  onOpenView
}: AIAssistantViewProps) {
  const [config, setConfig] = useState<AIOrchestrationConfig | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [audience, setAudience] = useState<"executive" | "technical" | "board" | "incident" | "fraud">("executive");
  const [scopes, setScopes] = useState<AIChatScope[]>(["overview", "evidence", "risk"]);
  const [loading, setLoading] = useState(false);
  const [deepAnalysisLoading, setDeepAnalysisLoading] = useState(false);
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messageListRef = useRef<HTMLDivElement>(null);

  const runtime = config?.openclaw_gateway ?? config?.ollama_chat ?? {};
  const runtimeReady = runtime.ready === true;
  const runtimeStatus = String(runtime.runtime_status ?? "unknown");
  const modelStatus = String(runtime.model_status ?? "unknown");
  const modelName = String(runtime.model ?? "cyberdecision-cti");
  const subject = run
    ? run.request.person_name || run.request.organization_name || run.domains.join(", ")
    : "";
  const report = run?.report;
  const questions = quickQuestions[language];

  const sourceCoverage = useMemo(() => {
    if (!run) return "N/D";
    const queried = run.summary.kpis.queried_sources ?? 0;
    const productive = run.summary.kpis.productive_sources ?? 0;
    return queried > 0 ? `${productive}/${queried}` : "N/D";
  }, [run]);

  useEffect(() => {
    void refreshRuntime();
  }, []);

  useEffect(() => {
    if (!run) {
      setMessages([]);
      return;
    }
    setMessages(loadConversation(run.id));
    setQuestion("");
    setError(null);
  }, [run?.id]);

  useEffect(() => {
    if (!run) return;
    saveConversation(run.id, messages);
    requestAnimationFrame(() => {
      if (messageListRef.current) {
        messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
      }
    });
  }, [messages, run?.id]);

  async function refreshRuntime() {
    setRuntimeLoading(true);
    try {
      setConfig(await getAIOrchestrationConfig());
      setError(null);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setRuntimeLoading(false);
    }
  }

  function toggleScope(scope: AIChatScope) {
    setScopes((current) => {
      if (current.includes(scope)) {
        return current.length === 1 ? current : current.filter((item) => item !== scope);
      }
      return [...current, scope];
    });
  }

  async function sendQuestion(prompt = question, selectedScopes = scopes) {
    const cleanPrompt = prompt.trim();
    const reportCommand = requestsReportGeneration(cleanPrompt);
    if (!run || !cleanPrompt || loading || (!runtimeReady && !reportCommand)) return;
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: cleanPrompt,
      createdAt: new Date().toISOString()
    };
    setMessages((current) => [...current, userMessage]);
    setQuestion("");
    setScopes(selectedScopes);
    setLoading(true);
    setError(null);
    try {
      if (reportCommand) {
        if (onGenerateReport) {
          await onGenerateReport(run.id);
        } else {
          await generateRunReport(run.id);
        }
        setMessages((current) => [
          ...current,
          {
            id: crypto.randomUUID(),
            role: "assistant",
            content: language === "es"
              ? "Los informes ejecutivo y técnico fueron generados desde la corrida seleccionada. Ya puedes abrirlos y descargarlos desde este tablero o desde Informes."
              : "The executive and technical reports were generated from the selected run. You can now open and download them here or from Reports.",
            createdAt: new Date().toISOString()
          }
        ]);
        return;
      }
      const result = await chatWithAI({
        run_id: run.id,
        message: cleanPrompt,
        language,
        audience,
        scopes: selectedScopes,
        history: messages.slice(-8).map((message) => ({
          role: message.role,
          content: message.content
        })),
        output_token_budget: 500,
        analysis_mode: "interactive"
      });
      if (result.status === "failed") {
        throw new Error(result.limitations.join(" ") || (language === "es" ? "La IA local no produjo una respuesta." : "Local AI did not produce a response."));
      }
      const answer = analysisText(result.analysis, language);
      setMessages((current) => [
        ...current,
        {
          id: result.id,
          role: "assistant",
          content: answer,
          createdAt: result.generated_at,
          result
        }
      ]);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setLoading(false);
    }
  }

  async function runDeepAnalysis() {
    if (!run || !runtimeReady || deepAnalysisLoading) return;
    setDeepAnalysisLoading(true);
    setError(null);
    try {
      const result = await chatWithAI({
        run_id: run.id,
        message: language === "es"
          ? "Realiza un análisis profundo y trazable de la corrida: contrasta cobertura, evidencia, contradicciones, presión prospectiva, escenarios, vulnerabilidades, marcos y controles. Separa hechos, inferencias y limitaciones, y publica posibilidades de decisión solo cuando tengan sustento."
          : "Perform a deep, traceable analysis of the run: cross-check coverage, evidence, contradictions, prospective pressure, scenarios, vulnerabilities, frameworks and controls. Separate facts, inferences and limitations, and only publish decision options when supported.",
        language,
        audience,
        scopes: moduleOptions.map((item) => item.scope),
        history: messages.slice(-4).map((message) => ({
          role: message.role,
          content: message.content
        })),
        output_token_budget: 1000,
        analysis_mode: "deep"
      });
      if (result.status === "failed") {
        throw new Error(result.limitations.join(" ") || (language === "es" ? "OpenClaw no completó el análisis." : "OpenClaw did not complete the analysis."));
      }
      setMessages((current) => [
        ...current,
        {
          id: result.id,
          role: "assistant",
          content: analysisText(result.analysis, language),
          createdAt: result.generated_at,
          result
        }
      ]);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setDeepAnalysisLoading(false);
    }
  }

  async function requestReports() {
    if (!run || reportLoading || run.status !== "completed") return;
    setReportLoading(true);
    setError(null);
    try {
      if (onGenerateReport) {
        await onGenerateReport(run.id);
      } else {
        await generateRunReport(run.id);
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setReportLoading(false);
    }
  }

  function clearConversation() {
    if (!run) return;
    localStorage.removeItem(conversationKey(run.id));
    setMessages([]);
  }

  if (!run) {
    return (
      <section className="panel ai-empty-workspace">
        <Bot size={28} />
        <div>
          <h2>{language === "es" ? "Asistente IA de auditoría" : "AI audit assistant"}</h2>
          <p>
            {language === "es"
              ? "Selecciona una corrida para conversar sobre sus resultados y evidencias."
              : "Select a run to discuss its results and evidence."}
          </p>
        </div>
      </section>
    );
  }

  return (
    <div className="view-stack ai-audit-view">
      <section className="panel ai-audit-hero">
        <div className="ai-audit-heading">
          <span className="ai-icon-box"><BrainCircuit size={23} /></span>
          <div>
            <h2>{language === "es" ? "Copiloto de análisis y decisión" : "Analysis and decision copilot"}</h2>
            <p>
              {language === "es"
                ? "Consulta la ejecución seleccionada, verifica su trazabilidad y traduce resultados técnicos en posibilidades de decisión."
                : "Query the selected run, verify traceability and translate technical results into decision options."}
            </p>
          </div>
        </div>
        <div className={`ai-runtime-pill ${runtimeReady ? "ready" : "unavailable"}`}>
          {runtimeReady ? <CheckCircle2 size={17} /> : <CircleAlert size={17} />}
          <span>
            <strong>{runtimeReady ? (language === "es" ? "IA local disponible" : "Local AI available") : (language === "es" ? "IA local no disponible" : "Local AI unavailable")}</strong>
            <small>{modelName} · {runtimeStatus}/{modelStatus}</small>
          </span>
          <button type="button" title={language === "es" ? "Comprobar estado" : "Check status"} onClick={refreshRuntime} disabled={runtimeLoading}>
            <RefreshCw size={16} className={runtimeLoading ? "spin" : ""} />
          </button>
        </div>
      </section>

      <section className="ai-context-strip" aria-label={language === "es" ? "Contexto de corrida" : "Run context"}>
        <div><Database size={17} /><span>{language === "es" ? "Corrida" : "Run"}<strong>#{run.id}</strong></span></div>
        <div><Target size={17} /><span>{language === "es" ? "Objeto" : "Subject"}<strong>{subject}</strong></span></div>
        <div><Gauge size={17} /><span>{language === "es" ? "Estado" : "Status"}<strong>{run.status} · {run.progress}%</strong></span></div>
        <div><ShieldCheck size={17} /><span>{language === "es" ? "Fuente productiva" : "Productive sources"}<strong>{sourceCoverage}</strong></span></div>
      </section>

      <section className="ai-workbench">
        <article className="panel ai-conversation-card">
          <header className="ai-section-header">
            <div>
              <span className="eyebrow">{language === "es" ? "CONVERSACIÓN TRAZABLE" : "TRACEABLE CONVERSATION"}</span>
              <h2>{language === "es" ? "Analiza la corrida con la IA" : "Analyze the run with AI"}</h2>
            </div>
            <button className="icon-button" type="button" title={language === "es" ? "Limpiar conversación" : "Clear conversation"} onClick={clearConversation} disabled={!messages.length}>
              <Trash2 size={17} />
            </button>
          </header>

          <div className="ai-quick-questions">
            <button
              className="deep-analysis"
              type="button"
              onClick={() => void runDeepAnalysis()}
              disabled={loading || deepAnalysisLoading || !runtimeReady}
            >
              {deepAnalysisLoading ? <LoaderCircle size={15} className="spin" /> : <BrainCircuit size={15} />}
              <span>{language === "es" ? "Análisis profundo" : "Deep analysis"}</span>
            </button>
            {questions.map((item) => (
              <button key={item.label} type="button" onClick={() => void sendQuestion(item.prompt, item.scopes)} disabled={loading || !runtimeReady}>
                <Sparkles size={15} />
                <span>{item.label}</span>
              </button>
            ))}
          </div>

          <div className="ai-message-list" ref={messageListRef}>
            {!messages.length ? (
              <div className="ai-welcome-message">
                <MessageSquareText size={22} />
                <strong>{language === "es" ? "Pregunta sobre los resultados reales" : "Ask about real results"}</strong>
                <p>
                  {language === "es"
                    ? "Puedo explicar KPI, hallazgos, evidencia, escenarios, frameworks, PESTEL, Porter, SOCMINT, OSINT, dark web y limitaciones de esta corrida."
                    : "I can explain KPIs, findings, evidence, scenarios, frameworks, PESTEL, Porter, SOCMINT, OSINT, dark web and limitations for this run."}
                </p>
              </div>
            ) : null}
            {messages.map((message) => (
              <div className={`ai-message ${message.role}`} key={message.id}>
                <div className="ai-message-avatar">
                  {message.role === "assistant" ? <Bot size={17} /> : <span>U</span>}
                </div>
                <div className="ai-message-body">
                  <div className="ai-message-meta">
                    <strong>{message.role === "assistant" ? "CyberDecision AI" : (language === "es" ? "Auditor" : "Auditor")}</strong>
                    <time>{formatTime(message.createdAt, language)}</time>
                  </div>
                  <p>{message.content}</p>
                  {message.result ? (
                    <AssistantAnalysis
                      result={message.result}
                      language={language}
                      onOpenView={onOpenView}
                    />
                  ) : null}
                </div>
              </div>
            ))}
            {loading ? (
              <div className="ai-message assistant loading">
                <div className="ai-message-avatar"><LoaderCircle size={17} className="spin" /></div>
                <div className="ai-message-body">
                  <strong>{language === "es" ? "Contrastando datos, evidencia y limitaciones..." : "Cross-checking data, evidence and limitations..."}</strong>
                </div>
              </div>
            ) : null}
          </div>

          {error ? <div className="error-banner inline">{error}</div> : null}

          <div className="ai-composer">
            <textarea
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void sendQuestion();
                }
              }}
              placeholder={language === "es" ? "Pregunta qué significa un resultado, qué evidencia lo sustenta o qué decisión considerar..." : "Ask what a result means, what supports it or which decision to consider..."}
              disabled={!runtimeReady || loading}
            />
            <button className="primary-button ai-send-button" type="button" onClick={() => void sendQuestion()} disabled={!question.trim() || !runtimeReady || loading}>
              <Send size={17} />
              <span>{language === "es" ? "Analizar" : "Analyze"}</span>
            </button>
          </div>
          <p className="ai-composer-note">
            {language === "es"
              ? "La pregunta y el historial orientan la respuesta, pero no se aceptan como evidencia. Shift + Enter crea una nueva línea."
              : "The question and history guide the answer but are never accepted as evidence. Shift + Enter adds a new line."}
          </p>
        </article>

        <aside className="ai-audit-sidebar">
          <article className="panel ai-scope-card">
            <header className="ai-section-header compact">
              <div>
                <span className="eyebrow">{language === "es" ? "CONTEXTO" : "CONTEXT"}</span>
                <h2>{language === "es" ? "Módulos consultados" : "Queried modules"}</h2>
              </div>
              <Layers3 size={18} />
            </header>
            <p>{language === "es" ? "Selecciona una o varias áreas. La IA recibirá solo datos de esta corrida." : "Select one or more areas. AI receives data only from this run."}</p>
            <div className="ai-scope-grid">
              {moduleOptions.map((item) => (
                <button
                  className={scopes.includes(item.scope) ? "selected" : ""}
                  key={item.scope}
                  type="button"
                  onClick={() => toggleScope(item.scope)}
                >
                  {scopes.includes(item.scope) ? <CheckCircle2 size={14} /> : <span className="scope-dot" />}
                  <span>{language === "es" ? item.labelEs : item.labelEn}</span>
                </button>
              ))}
            </div>
            <label className="ai-audience-control">
              <span>{language === "es" ? "Perspectiva de respuesta" : "Response perspective"}</span>
              <select value={audience} onChange={(event) => setAudience(event.target.value as typeof audience)}>
                <option value="executive">{language === "es" ? "Ejecutiva" : "Executive"}</option>
                <option value="technical">{language === "es" ? "Técnica" : "Technical"}</option>
                <option value="board">{language === "es" ? "Junta directiva" : "Board"}</option>
                <option value="incident">{language === "es" ? "Respuesta a incidentes" : "Incident response"}</option>
                <option value="fraud">{language === "es" ? "Fraude y marca" : "Fraud and brand"}</option>
              </select>
            </label>
          </article>

          <article className="panel ai-run-facts-card">
            <header className="ai-section-header compact">
              <div>
                <span className="eyebrow">{language === "es" ? "FUENTE DE VERDAD" : "SOURCE OF TRUTH"}</span>
                <h2>{language === "es" ? "Datos disponibles" : "Available data"}</h2>
              </div>
              <Database size={18} />
            </header>
            <div className="ai-run-facts">
              <Fact label={language === "es" ? "Registros únicos" : "Unique records"} value={run.summary.kpis.unique_records ?? run.summary.events.length} />
              <Fact label={language === "es" ? "Evidencia validada" : "Validated evidence"} value={run.summary.kpis.validated_evidence ?? 0} />
              <Fact label={language === "es" ? "Hallazgos validados" : "Validated findings"} value={run.summary.kpis.validated_findings ?? 0} />
              <Fact label={language === "es" ? "Riesgo residual máximo" : "Maximum residual risk"} value={formatRisk(run.summary.kpis.max_residual_risk)} />
            </div>
            <button className="secondary-button ai-open-dashboard" type="button" onClick={() => onOpenView?.("dashboards")}>
              <Gauge size={16} />
              <span>{language === "es" ? "Abrir tablero estratégico" : "Open strategic dashboard"}</span>
              <ChevronRight size={16} />
            </button>
          </article>

          <article className="panel ai-report-actions">
            <header className="ai-section-header compact">
              <div>
                <span className="eyebrow">{language === "es" ? "INFORMES" : "REPORTS"}</span>
                <h2>{language === "es" ? "Ejecutivo y técnico" : "Executive and technical"}</h2>
              </div>
              <FileChartColumn size={18} />
            </header>
            <p>
              {language === "es"
                ? "La IA explica los resultados; el botón usa el generador trazable de la plataforma para producir ambos informes."
                : "AI explains results; the button uses the platform's traceable generator to produce both reports."}
            </p>
            <button className="primary-button" type="button" onClick={requestReports} disabled={reportLoading || run.status !== "completed"}>
              {reportLoading ? <LoaderCircle size={17} className="spin" /> : <FileChartColumn size={17} />}
              <span>{reportLoading ? (language === "es" ? "Generando..." : "Generating...") : (language === "es" ? "Generar ambos informes" : "Generate both reports")}</span>
            </button>
            {report ? (
              <div className="ai-report-links">
                <button type="button" onClick={() => window.open(apiUrl(report.url), "_blank", "noopener,noreferrer")}>
                  <FileChartColumn size={16} />
                  <span>{language === "es" ? "Informe ejecutivo" : "Executive report"}</span>
                  <SquareArrowOutUpRight size={14} />
                </button>
                {report.technical_url ? (
                  <button type="button" onClick={() => window.open(apiUrl(report.technical_url ?? ""), "_blank", "noopener,noreferrer")}>
                    <FileCode2 size={16} />
                    <span>{language === "es" ? "Informe técnico" : "Technical report"}</span>
                    <SquareArrowOutUpRight size={14} />
                  </button>
                ) : null}
              </div>
            ) : (
              <span className="ai-report-empty">{language === "es" ? "Aún no hay informes para esta corrida." : "No reports for this run yet."}</span>
            )}
          </article>

          <details className="panel ai-trace-details">
            <summary>
              <BrainCircuit size={17} />
              <span>{language === "es" ? "Trazabilidad del motor IA" : "AI engine traceability"}</span>
            </summary>
            <dl>
              <div><dt>Gateway</dt><dd>OpenClaw</dd></div>
              <div><dt>Modelo</dt><dd>{modelName}</dd></div>
              <div><dt>Prompt</dt><dd>{config?.chat_prompt_version ?? config?.prompt_version ?? "N/D"}</dd></div>
              <div><dt>Modo</dt><dd>analysis_only</dd></div>
              <div><dt>Run ID</dt><dd>{run.id}</dd></div>
            </dl>
          </details>
        </aside>
      </section>
    </div>
  );
}

function AssistantAnalysis({
  result,
  language,
  onOpenView
}: {
  result: AIExecutionResult;
  language: LanguageMode;
  onOpenView?: (view: ViewKey) => void;
}) {
  const analysis = result.analysis;
  const decisions = firstRecordArray(
    analysis.decision_options,
    analysis.posibilidades_de_decision,
    analysis.strategic_decisions
  );
  const checks = firstRecordArray(
    analysis.technical_checks,
    analysis.acciones_tecnicas,
    analysis.technical_actions
  );
  const inferences = recordArray(analysis.inferences);
  const limitations = stringArray(analysis.limitations);
  const visibleLimitations = Array.from(
    new Set([...limitations, ...result.limitations].filter(Boolean))
  );
  const followUps = stringArray(analysis.follow_up_questions);
  const dashboardTargets = recordArray(analysis.dashboard_targets);
  const agentTrace = result.agent_trace ?? [];
  const validatedCount = numberValue(result.evidence_validation.validated_count);
  const requestedCount = numberValue(result.evidence_validation.requested_count);

  return (
    <div className="ai-analysis-detail">
      {decisions.length ? (
        <section>
          <h3>{language === "es" ? "Posibilidades de decisión" : "Decision options"}</h3>
          <div className="ai-decision-list">
            {decisions.slice(0, 4).map((item, index) => (
              <div key={`${stringValue(item.option)}-${index}`}>
                <span>{stringValue(item.priority) || `P${index + 1}`}</span>
                <p>
                  <strong>{stringValue(item.option) || stringValue(item.decision)}</strong>
                  {stringValue(item.rationale) || stringValue(item.why_now)
                    ? ` ${stringValue(item.rationale) || stringValue(item.why_now)}`
                    : ""}
                </p>
              </div>
            ))}
          </div>
        </section>
      ) : null}
      {checks.length || inferences.length ? (
        <div className="ai-analysis-columns">
          {checks.length ? (
            <section>
              <h3>{language === "es" ? "Validaciones técnicas" : "Technical checks"}</h3>
              {checks.slice(0, 4).map((item, index) => (
                <p key={`${stringValue(item.check) || stringValue(item.action)}-${index}`}>
                  <CheckCircle2 size={14} />
                  {stringValue(item.check) || stringValue(item.action)}
                  {stringValue(item.reason) || stringValue(item.validation_evidence)
                    ? `: ${stringValue(item.reason) || stringValue(item.validation_evidence)}`
                    : ""}
                </p>
              ))}
            </section>
          ) : null}
          {inferences.length ? (
            <section>
              <h3>{language === "es" ? "Inferencias" : "Inferences"}</h3>
              {inferences.slice(0, 4).map((item, index) => (
                <p key={`${stringValue(item.statement)}-${index}`}><CircleAlert size={14} />{stringValue(item.statement)} <em>{stringValue(item.confidence)}</em></p>
              ))}
            </section>
          ) : null}
        </div>
      ) : null}
      {dashboardTargets.length ? (
        <div className="ai-dashboard-targets">
          {dashboardTargets.slice(0, 5).map((item, index) => {
            const scope = stringValue(item.module) as AIChatScope;
            const target = moduleOptions.find((option) => option.scope === scope);
            if (!target) return null;
            return (
              <button key={`${scope}-${index}`} type="button" onClick={() => onOpenView?.(target.view)}>
                <span>{language === "es" ? target.labelEs : target.labelEn}</span>
                <ChevronRight size={14} />
              </button>
            );
          })}
        </div>
      ) : null}
      {agentTrace.length ? (
        <details className="ai-agent-trace">
          <summary>
            <BrainCircuit size={14} />
            {language === "es"
              ? `${agentTrace.length} etapas especializadas`
              : `${agentTrace.length} specialist stages`}
          </summary>
          <div>
            {agentTrace.map((agent) => (
              <span className={agent.status} key={`${result.id}-${agent.agent_id}`}>
                <i />
                <strong>{agent.label || agent.agent_id}</strong>
                <small>{agent.execution_mode.replace(/_/g, " ")}</small>
              </span>
            ))}
          </div>
        </details>
      ) : null}
      <footer className="ai-answer-validation">
        <span className={requestedCount > 0 && validatedCount === requestedCount ? "validated" : "limited"}>
          <ShieldCheck size={14} />
          {language === "es" ? `${validatedCount}/${requestedCount} referencias verificadas` : `${validatedCount}/${requestedCount} references verified`}
        </span>
        <span>
          {language === "es"
            ? "Análisis sustentado en la corrida"
            : "Run-grounded analysis"}
        </span>
      </footer>
      {visibleLimitations.length ? (
        <details className="ai-limitations">
          <summary>{language === "es" ? "Limitaciones de esta respuesta" : "Response limitations"}</summary>
          {visibleLimitations.map((item) => <p key={item}>{item}</p>)}
        </details>
      ) : null}
      {followUps.length ? (
        <div className="ai-follow-up">
          <strong>{language === "es" ? "Preguntas sugeridas" : "Suggested questions"}</strong>
          {followUps.slice(0, 3).map((item) => <span key={item}>{item}</span>)}
        </div>
      ) : null}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string | number }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function analysisText(analysis: Record<string, unknown>, language: LanguageMode): string {
  const answer = stringValue(analysis.answer);
  if (answer) return answer;
  const narrative = stringValue(analysis.narrative);
  if (narrative) return narrative;
  const summaries = firstRecordArray(
    analysis.resumen_ejecutivo,
    analysis.executive_summary,
    analysis.executiveImplications
  );
  const summaryText = summaries
    .map((item) => stringValue(item.finding) || stringValue(item.implication))
    .filter(Boolean)
    .slice(0, 4)
    .join(" ");
  if (summaryText) return summaryText;
  return language === "es"
    ? "El modelo devolvió una estructura sin resumen narrativo. Revisa el detalle trazable de la respuesta."
    : "The model returned structured data without a narrative summary. Review the traceable response details.";
}

function recordArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : [];
}

function firstRecordArray(...values: unknown[]): Record<string, unknown>[] {
  for (const value of values) {
    const rows = recordArray(value);
    if (rows.length) return rows;
  }
  return [];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function formatRisk(value?: number | null): string {
  return typeof value === "number" && Number.isFinite(value) ? `${Math.round(value * (value <= 1 ? 100 : 1))}%` : "N/D";
}

function formatTime(value: string, language: LanguageMode): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(language === "es" ? "es-CO" : "en-US", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function requestsReportGeneration(message: string): boolean {
  const normalized = message.toLocaleLowerCase();
  const hasAction = ["genera", "generar", "crear", "generate", "create"].some((token) => normalized.includes(token));
  const hasArtifact = ["informe", "reporte", "report"].some((token) => normalized.includes(token));
  return hasAction && hasArtifact;
}

function conversationKey(runId: string): string {
  return `cde-ai-conversation:${runId}`;
}

function loadConversation(runId: string): ChatMessage[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(conversationKey(runId)) ?? "[]");
    return Array.isArray(parsed) ? parsed.slice(-20) : [];
  } catch {
    return [];
  }
}

function saveConversation(runId: string, messages: ChatMessage[]) {
  try {
    localStorage.setItem(conversationKey(runId), JSON.stringify(messages.slice(-20)));
  } catch {
    // The assistant remains usable when browser storage is unavailable.
  }
}
