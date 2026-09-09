import { BrainCircuit, Waypoints } from "lucide-react";
import { useEffect, useState } from "react";
import type { LanguageMode, RunRecord, ViewKey } from "../types";
import { AIAssistantView } from "./AIAssistantView";
import { ScenarioDecisionView } from "./ScenarioDecisionView";

type DecisionWorkspaceTab = "scenarios" | "assistant";

export function DecisionWorkspaceView({
  run,
  language,
  initialTab = "scenarios",
  onGenerateReport,
  onOpenView
}: {
  run?: RunRecord;
  language: LanguageMode;
  initialTab?: DecisionWorkspaceTab;
  onGenerateReport: (runId: string) => void;
  onOpenView: (view: ViewKey) => void;
}) {
  const [tab, setTab] = useState<DecisionWorkspaceTab>(initialTab);

  useEffect(() => setTab(initialTab), [initialTab]);

  return (
    <div className="view-stack product-workspace decision-workspace-view">
      <section className="panel workspace-hero decision-workspace-header">
        <div>
          <span className="eyebrow">{language === "es" ? "Decisión sustentada" : "Evidence-supported decision"}</span>
          <h2>{language === "es" ? "Escenarios y asistente estratégico" : "Scenarios and strategic assistant"}</h2>
          <p>{language === "es" ? "Contrasta escenarios derivados de marcos con el análisis de la evidencia persistida, sin convertir hipótesis en hechos." : "Compare framework-derived scenarios with analysis of persisted evidence, without turning hypotheses into facts."}</p>
        </div>
        <div className="decision-workspace-tabs" role="tablist" aria-label={language === "es" ? "Vista de decisión" : "Decision view"}>
          <button type="button" role="tab" aria-selected={tab === "scenarios"} className={tab === "scenarios" ? "selected" : ""} onClick={() => setTab("scenarios")}><Waypoints size={17} />{language === "es" ? "Escenarios" : "Scenarios"}</button>
          <button type="button" role="tab" aria-selected={tab === "assistant"} className={tab === "assistant" ? "selected" : ""} onClick={() => setTab("assistant")}><BrainCircuit size={17} />{language === "es" ? "Asistente" : "Assistant"}</button>
        </div>
      </section>
      {tab === "scenarios" ? <ScenarioDecisionView run={run} language={language} /> : null}
      {tab === "assistant" ? <AIAssistantView run={run} language={language} onGenerateReport={onGenerateReport} onOpenView={onOpenView} /> : null}
    </div>
  );
}
