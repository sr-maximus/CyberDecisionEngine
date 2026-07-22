import { Ban, CheckCircle2, ExternalLink, RotateCcw, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { LanguageMode, RunRecord, ThreatEvent, ViewKey, Finding } from "../types";
import { cleanEvidenceTitle, displaySourceName, publicEvidenceUrl } from "../utils/sourceLabels";

type EvidenceStatus = "pending" | "validated" | "false_positive";

interface EvidenceItem {
  id: string;
  title: string;
  category: string;
  domain: string;
  url: string;
  source: string;
}

const copy = {
  es: {
    title: "Evidencia URL de la corrida",
    sectionTitle: "Evidencia URL del módulo",
    subtitle: "URLs recolectadas para validar hallazgos, menciones y senales. Marca falso positivo para excluirlo en la lectura operativa.",
    sectionSubtitle: "Sólo URLs relacionadas con el menú actual. La evidencia global se conserva en el Tablero estratégico.",
    empty: "Esta corrida no tiene URLs de evidencia directa para validar.",
    sectionEmpty: "Este módulo no tiene URLs de evidencia directa en la corrida seleccionada.",
    evidence: "Evidencia",
    category: "Categoria",
    domain: "Dominio",
    source: "Origen",
    open: "Abrir URL",
    pending: "Pendiente",
    validated: "Validada",
    falsePositive: "Falso positivo",
    markValid: "Validar",
    markFalse: "Falso positivo",
    reset: "Pendiente",
    visible: "URLs visibles",
    events: "eventos recolectados",
    findings: "hallazgos"
  },
  en: {
    title: "Run URL evidence",
    sectionTitle: "Module URL evidence",
    subtitle: "Collected URLs for validating findings, mentions and signals. Mark false positive to exclude it from operational reading.",
    sectionSubtitle: "Only URLs related to the current menu. Global evidence remains in the Strategic Dashboard.",
    empty: "This run has no direct evidence URLs to validate.",
    sectionEmpty: "This module has no direct evidence URLs in the selected run.",
    evidence: "Evidence",
    category: "Category",
    domain: "Domain",
    source: "Origin",
    open: "Open URL",
    pending: "Pending",
    validated: "Validated",
    falsePositive: "False positive",
    markValid: "Validate",
    markFalse: "False positive",
    reset: "Pending",
    visible: "visible URLs",
    events: "collected records",
    findings: "findings"
  }
};

export function EvidenceLedger({ run, language, view = "dashboards" }: { run?: RunRecord; language: LanguageMode; view?: ViewKey }) {
  const t = copy[language];
  const isGlobal = view === "dashboards";
  const items = useMemo(() => buildEvidenceItems(run, language, view), [run, language, view]);
  const storageKey = run ? `cyberdecision.evidenceValidation.v1.${run.id}` : "";
  const [statuses, setStatuses] = useState<Record<string, EvidenceStatus>>({});

  useEffect(() => {
    if (!storageKey) {
      setStatuses({});
      return;
    }
    try {
      const raw = window.localStorage.getItem(storageKey);
      setStatuses(raw ? JSON.parse(raw) : {});
    } catch {
      setStatuses({});
    }
  }, [storageKey]);

  function setStatus(url: string, status: EvidenceStatus) {
    setStatuses((current) => {
      const next = { ...current, [url]: status };
      if (storageKey) window.localStorage.setItem(storageKey, JSON.stringify(next));
      return next;
    });
  }

  return (
    <section className="panel chart-card span-12 evidence-ledger scroll-card">
      <div className="panel-title-row compact">
        <div>
          <h2>{isGlobal ? t.title : t.sectionTitle}</h2>
          <p>{isGlobal ? t.subtitle : t.sectionSubtitle}</p>
        </div>
        <div className="evidence-ledger-summary">
          <ShieldCheck size={18} />
          <strong>{items.length}</strong>
          <span>{t.visible}</span>
          <em>{run?.summary.kpis.new_events ?? 0} {t.events} · {run?.summary.findings.length ?? 0} {t.findings}</em>
        </div>
      </div>
      {!items.length ? (
        <div className="chart-empty">{isGlobal ? t.empty : t.sectionEmpty}</div>
      ) : (
        <div className="evidence-ledger-list">
          {items.map((item) => {
            const status = statuses[item.url] ?? "pending";
            return (
              <article className={`evidence-ledger-row ${status}`} key={item.id}>
                <div className="evidence-ledger-main">
                  <strong>{item.title || item.url}</strong>
                  <a href={item.url} target="_blank" rel="noreferrer">
                    <ExternalLink size={13} />
                    <code>{item.url}</code>
                  </a>
                </div>
                <div className="evidence-ledger-meta">
                  <span>{t.category}: {item.category || "n/a"}</span>
                  <span>{t.domain}: {item.domain || "n/a"}</span>
                  <span>{t.source}: {item.source || "n/a"}</span>
                </div>
                <div className="evidence-ledger-actions" aria-label={t.evidence}>
                  <button className={status === "validated" ? "selected" : ""} onClick={() => setStatus(item.url, "validated")} title={t.markValid}>
                    <CheckCircle2 size={15} />
                    <span>{t.validated}</span>
                  </button>
                  <button className={status === "false_positive" ? "selected danger" : ""} onClick={() => setStatus(item.url, "false_positive")} title={t.markFalse}>
                    <Ban size={15} />
                    <span>{t.falsePositive}</span>
                  </button>
                  <button className={status === "pending" ? "selected neutral" : ""} onClick={() => setStatus(item.url, "pending")} title={t.reset}>
                    <RotateCcw size={15} />
                    <span>{t.pending}</span>
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function buildEvidenceItems(run: RunRecord | undefined, language: LanguageMode, view: ViewKey): EvidenceItem[] {
  const items = new Map<string, EvidenceItem>();
  const domains = run?.domains ?? [];
  for (const event of run?.summary.events ?? []) {
    if (!matchesEvidenceView(event, view)) continue;
    const url = publicEvidenceUrl(event.evidence_url) || "";
    if (!url || items.has(url)) continue;
    const domain = domains.find((item) => {
      const text = `${event.title} ${url}`.toLowerCase();
      return text.includes(item.toLowerCase());
    });
    items.set(url, {
      id: event.id || url,
      title: cleanEvidenceTitle(event.title),
      category: event.category,
      domain: domain || "",
      url,
      source: displaySourceName(event.source, language)
    });
  }
  for (const finding of run?.summary.findings ?? []) {
    if (!matchesFindingView(finding, view)) continue;
    for (const evidence of finding.evidence ?? []) {
      const url = publicEvidenceUrl(evidence) || "";
      if (!/^https?:\/\//i.test(url) || items.has(url)) continue;
      const domain = domains.find((item) => url.toLowerCase().includes(item.toLowerCase()));
      items.set(url, {
        id: `${finding.title}-${url}`,
        title: cleanEvidenceTitle(finding.title),
        category: finding.category,
        domain: domain || "",
        url,
        source: language === "en" ? "Finding evidence" : "Evidencia de hallazgo"
      });
    }
  }
  return [...items.values()];
}

function matchesEvidenceView(event: ThreatEvent, view: ViewKey): boolean {
  if (view === "dashboards") return true;
  const text = `${event.source} ${event.category} ${event.title} ${event.actor ?? ""} ${event.technique ?? ""} ${(event.tags ?? []).join(" ")}`.toLowerCase();
  const url = (event.evidence_url ?? "").toLowerCase();
  if (view === "attackSurface") return /external|surface|dns|whois|ssl|certificate|cert|subdomain|port|technology|http|domain|mx|spf|dmarc|tls/.test(`${text} ${url}`);
  if (view === "brand") return /brand|marca|fraud|fraude|farsa|phish|imperson|suplant|lookalike|homograph|reputation|reputaci|sentiment|cliente|customer/.test(`${text} ${url}`);
  if (view === "disinformation") return /disarm|disinfo|misinfo|fake|false|narrativ|influence|amplif|propaganda|coordinat|trust|confianza/.test(text);
  if (view === "osint") return /osint|public search|internet search|google|duckduckgo|common crawl|open web|search|dork|filetype|indexed|document|busqueda/.test(text) && !matchesEvidenceView(event, "socmint") && !matchesEvidenceView(event, "darkweb");
  if (view === "socmint") return /socmint|social|facebook|instagram|tiktok|linkedin|twitter|\bx\b|reddit|mention|mencion|hashtag|profile|account|usuario|narrativ/.test(`${text} ${url}`);
  if (view === "darkweb") return /dark|tor|onion|leak|filtraci|ransom|extortion|dump|paste|credential/.test(`${text} ${url}`);
  if (view === "frameworks") return /framework|nist|iso|pci|soc 2|gdpr|control|mitre|attack|defend|atlas|disarm|cve|kev|ttp|technique/.test(text);
  if (view === "scenarios") return /scenario|escenario|mitre|attack|defend|atlas|disarm|ttp|porter|pestel|risk|riesgo|decision|decisi/.test(text);
  return true;
}

function matchesFindingView(finding: Finding, view: ViewKey): boolean {
  if (view === "dashboards") return true;
  const text = `${finding.title} ${finding.category} ${finding.matrix_label} ${finding.owner} ${(finding.evidence ?? []).join(" ")} ${(finding.recommendations ?? []).join(" ")}`.toLowerCase();
  const fakeEvent: ThreatEvent = { id: "finding", title: text, category: finding.category, source: "finding", observed_at: new Date(0).toISOString(), evidence_url: "" };
  return matchesEvidenceView(fakeEvent, view);
}
