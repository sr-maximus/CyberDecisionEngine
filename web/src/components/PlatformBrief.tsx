import { BrainCircuit, Eye, FileText, LockKeyhole, ShieldCheck, TrendingUp } from "lucide-react";
import type { LanguageMode } from "../types";

const copy = {
  es: {
    author: "Modelo diseñado por Edwin Peñuela",
    title: "CyberDecisionEngine convierte ciberinteligencia en decisiones preventivas y predictivas.",
    body:
      "La plataforma esta enfocada en cyberinteligencia defensiva para organizaciones: recolecta señales abiertas/autorizadas, analiza riesgo tecnico, fraude, marca, TTP y controles, y muestra evidencia accionable para decidir rapido.",
    focus: "Enfoque: prediccion para prevencion, decision ejecutiva, trazabilidad tecnica y respuesta ante fraude/amenazas.",
    pillars: [
      {
        title: "Que busca",
        text: "Dominios, marca, grupo, conglomerado, fraude, phishing, CVE/KEV, TTP, SOCMINT publico y fuentes dark web autorizadas.",
        icon: Eye
      },
      {
        title: "Que brinda",
        text: "Tableros accionables, URL de evidencia, riesgo de marca, prediccion, postura, frameworks y reportes ejecutivo/tecnico.",
        icon: FileText
      },
      {
        title: "Para que sirve",
        text: "Priorizar decisiones de ciberseguridad, fraude, SOC, continuidad, cumplimiento, reputacion y respuesta preventiva.",
        icon: TrendingUp
      },
      {
        title: "Como protege",
        text: "Opera con scope autorizado, fuentes pasivas, datos trazables y sin inventar hallazgos cuando una fuente no entrega evidencia.",
        icon: LockKeyhole
      }
    ]
  },
  en: {
    author: "Model designed by Edwin Peñuela",
    title: "CyberDecisionEngine turns cyber intelligence into preventive and predictive decisions.",
    body:
      "The platform focuses on defensive cyber intelligence for organizations: it collects open/authorized signals, analyzes technical risk, fraud, brand, TTPs and controls, and shows actionable evidence for fast decisions.",
    focus: "Focus: prediction for prevention, executive decision-making, technical traceability and response to fraud/threats.",
    pillars: [
      {
        title: "What it searches",
        text: "Domains, brand, group, conglomerate, fraud, phishing, CVE/KEV, TTP, public SOCMINT and authorized dark web sources.",
        icon: Eye
      },
      {
        title: "What it provides",
        text: "Actionable dashboards, evidence URLs, brand risk, prediction, posture, frameworks and executive/technical reports.",
        icon: FileText
      },
      {
        title: "What it is for",
        text: "Prioritizing cybersecurity, fraud, SOC, continuity, compliance, reputation and preventive response decisions.",
        icon: TrendingUp
      },
      {
        title: "How it protects",
        text: "Operates with authorized scope, passive sources, traceable data and no invented findings when a source returns no evidence.",
        icon: LockKeyhole
      }
    ]
  }
};

export function PlatformBrief({ language }: { language: LanguageMode }) {
  const labels = copy[language];
  return (
    <section className="platform-brief panel">
      <div className="platform-brief-main">
        <ShieldCheck size={22} />
        <span>{labels.author}</span>
        <h2>{labels.title}</h2>
        <p>{labels.body}</p>
      </div>
      <div className="platform-pillars">
        {labels.pillars.map((pillar) => (
          <article key={pillar.title}>
            <pillar.icon size={18} />
            <strong>{pillar.title}</strong>
            <span>{pillar.text}</span>
          </article>
        ))}
      </div>
      <div className="platform-brief-model">
        <BrainCircuit size={20} />
        <p>{labels.focus}</p>
      </div>
    </section>
  );
}
