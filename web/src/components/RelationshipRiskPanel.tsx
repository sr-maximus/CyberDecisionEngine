import { Building2, ExternalLink, ScanSearch, ShieldQuestion, Swords } from "lucide-react";
import type { ReactNode } from "react";
import type {
  LanguageMode,
  RelationshipDomainAbuseRow,
  RelationshipRiskIntelligence,
  RelationshipThirdPartyRow,
  RunRecord
} from "../types";

interface RelationshipRiskPanelProps {
  run?: RunRecord;
  language: LanguageMode;
  mode?: "all" | "domain_abuse";
}

const copy = {
  es: {
    title: "Relaciones, terceros y dominios similares",
    attackTitle: "Ciberocupación y dominios similares observados",
    subtitle: "Lectura trazable de relaciones públicas; una declaración o similitud no se convierte por sí sola en riesgo.",
    thirdParties: "Terceros relacionados",
    competitors: "Contexto competitivo",
    domainAbuse: "Dominios similares",
    observed: "Observados",
    assessed: "Con señal evaluable",
    suspicious: "Con señal de abuso",
    represented: "Con evidencia pública",
    noData: "La corrida no contiene relaciones o dominios similares observados que puedan publicarse.",
    contextOnly: "Contexto sin riesgo validado",
    supported: "Señal respaldada",
    pending: "Requiere validación",
    records: "registros",
    sources: "fuentes",
    similarity: "similitud",
    target: "Objetivo parecido",
    evidence: "Abrir evidencia",
    more: "más",
    limitation: "No confirma compromiso, fraude ni control adversario. La decisión depende de evidencia validada y revisión humana."
  },
  en: {
    title: "Relationships, third parties and similar domains",
    attackTitle: "Observed cybersquatting and similar domains",
    subtitle: "Traceable reading of public relationships; a declaration or similarity does not become risk by itself.",
    thirdParties: "Related third parties",
    competitors: "Competitive context",
    domainAbuse: "Similar domains",
    observed: "Observed",
    assessed: "With assessable signal",
    suspicious: "With abuse signal",
    represented: "With public evidence",
    noData: "The run contains no publishable observed relationships or similar domains.",
    contextOnly: "Context without validated risk",
    supported: "Supported signal",
    pending: "Requires validation",
    records: "records",
    sources: "sources",
    similarity: "similarity",
    target: "Similar target",
    evidence: "Open evidence",
    more: "more",
    limitation: "This does not confirm compromise, fraud or adversary control. Decisions require validated evidence and human review."
  }
};

export function RelationshipRiskPanel({ run, language, mode = "all" }: RelationshipRiskPanelProps) {
  const labels = copy[language];
  const intelligence = run?.summary.metrics?.relationship_risk_intelligence as RelationshipRiskIntelligence | undefined;
  const thirdPartyRows = intelligence?.third_party?.rows ?? [];
  const domainRows = intelligence?.domain_abuse?.rows ?? [];
  const competitorRows = intelligence?.competitive_context?.rows ?? [];
  const hasData = mode === "domain_abuse"
    ? domainRows.length > 0
    : Boolean(thirdPartyRows.length || domainRows.length || competitorRows.length);

  return (
    <section className="panel relationship-risk-panel">
      <header className="relationship-risk-header">
        <div>
          <h2>{mode === "domain_abuse" ? labels.attackTitle : labels.title}</h2>
          <p>{labels.subtitle}</p>
        </div>
        <ShieldQuestion size={20} aria-hidden="true" />
      </header>

      {!hasData ? <div className="relationship-risk-empty">{labels.noData}</div> : null}

      {hasData ? (
        <div className={`relationship-risk-layout ${mode === "domain_abuse" ? "single" : ""}`}>
          {mode === "all" ? (
            <RelationshipColumn
              icon={<Building2 size={18} />}
              title={labels.thirdParties}
              summary={`${intelligence?.third_party.observed_count ?? 0} ${labels.observed} · ${intelligence?.third_party.assessed_count ?? 0} ${labels.assessed}`}
            >
              {thirdPartyRows.slice(0, 8).map((row) => (
                <ThirdPartyRow key={row.name} row={row} language={language} />
              ))}
            </RelationshipColumn>
          ) : null}

          <RelationshipColumn
            icon={<ScanSearch size={18} />}
            title={labels.domainAbuse}
            summary={`${domainRows.length} ${labels.observed} · ${intelligence?.domain_abuse.suspicious_signal_count ?? 0} ${labels.suspicious}`}
          >
            {domainRows.slice(0, mode === "domain_abuse" ? 20 : 8).map((row) => (
              <DomainAbuseRow key={`${row.candidate_domain}-${row.target_domain}`} row={row} language={language} />
            ))}
          </RelationshipColumn>

          {mode === "all" ? (
            <RelationshipColumn
              icon={<Swords size={18} />}
              title={labels.competitors}
              summary={`${intelligence?.competitive_context.represented_count ?? 0}/${intelligence?.competitive_context.declared_count ?? 0} ${labels.represented}`}
            >
              {competitorRows.slice(0, 8).map((row) => (
                <div className="relationship-risk-row" key={row.name}>
                  <div className="relationship-risk-row-title">
                    <strong>{row.name}</strong>
                    <span className={row.record_count ? "relationship-status supported" : "relationship-status context"}>
                      {row.record_count ? labels.supported : labels.contextOnly}
                    </span>
                  </div>
                  <small>{row.record_count} {labels.records}</small>
                  <EvidenceLinks urls={row.urls} language={language} />
                </div>
              ))}
            </RelationshipColumn>
          ) : null}
        </div>
      ) : null}

      <footer className="relationship-risk-limitation">{labels.limitation}</footer>
    </section>
  );
}

function RelationshipColumn({ icon, title, summary, children }: {
  icon: ReactNode;
  title: string;
  summary: string;
  children: ReactNode;
}) {
  return (
    <section className="relationship-risk-column">
      <header>
        <span>{icon}</span>
        <div><strong>{title}</strong><small>{summary}</small></div>
      </header>
      <div className="relationship-risk-list">{children}</div>
    </section>
  );
}

function ThirdPartyRow({ row, language }: { row: RelationshipThirdPartyRow; language: LanguageMode }) {
  const labels = copy[language];
  return (
    <div className="relationship-risk-row">
      <div className="relationship-risk-row-title">
        <strong>{row.name}</strong>
        <span className={row.risk_signal_count ? "relationship-status supported" : "relationship-status context"}>
          {row.risk_signal_count ? `${row.attention_score?.toFixed(0) ?? "N/D"}/100` : labels.contextOnly}
        </span>
      </div>
      <small>{row.record_count} {labels.records} · {row.source_count} {labels.sources}</small>
      <p>{row.what_it_means}</p>
      <EvidenceLinks urls={row.urls} language={language} />
    </div>
  );
}

function DomainAbuseRow({ row, language }: { row: RelationshipDomainAbuseRow; language: LanguageMode }) {
  const labels = copy[language];
  const similarity = Math.round((row.similarity <= 1 ? row.similarity * 100 : row.similarity));
  return (
    <div className="relationship-risk-row">
      <div className="relationship-risk-row-title">
        <strong>{row.candidate_domain}</strong>
        <span className={row.abuse_signal_count ? "relationship-status supported" : "relationship-status pending"}>
          {row.abuse_signal_count ? labels.supported : labels.pending}
        </span>
      </div>
      <small>{labels.target}: {row.target_domain} · {similarity}% {labels.similarity}</small>
      <p>{row.what_it_means}</p>
      <EvidenceLinks urls={row.urls} language={language} />
    </div>
  );
}

function EvidenceLinks({ urls, language }: { urls: string[]; language: LanguageMode }) {
  const labels = copy[language];
  if (!urls.length) return null;
  return (
    <div className="relationship-evidence-links">
      {urls.slice(0, 2).map((url, index) => (
        <a href={url} key={url} target="_blank" rel="noreferrer" title={url}>
          <ExternalLink size={13} /> {labels.evidence} {index + 1}
        </a>
      ))}
      {urls.length > 2 ? <small>+{urls.length - 2} {labels.more}</small> : null}
    </div>
  );
}
