import { Ban, CheckCircle2, ExternalLink, RotateCcw, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { LanguageMode, RunRecord, ThreatEvent, ViewKey, Finding } from "../types";
import { cleanEvidenceTitle, displaySourceName, publicEvidenceUrl } from "../utils/sourceLabels";
import { reviewRunEvidence } from "../api";

type EvidenceStatus = "pending" | "validated" | "false_positive";

interface EvidenceItem {
  id: string;
  title: string;
  category: string;
  evidenceType: string;
  domain: string;
  url: string;
  source: string;
  status: EvidenceStatus;
  reviewable: boolean;
}

const copy = {
  es: {
    title: "Evidencia URL de la corrida",
    sectionTitle: "Evidencia URL del módulo",
    openIntelligenceTitle: "Evidencia OSINT y SOCMINT",
    subtitle: "URLs recolectadas para validar hallazgos, menciones y senales. Marca falso positivo para excluirlo en la lectura operativa.",
    sectionSubtitle: "Sólo URLs relacionadas con el menú actual. La evidencia global se conserva en el Tablero estratégico.",
    openIntelligenceSubtitle: "URLs públicas y sociales de la corrida, organizadas por tipo para su validación y trazabilidad.",
    empty: "Esta corrida no tiene URLs de evidencia directa para validar.",
    sectionEmpty: "Este módulo no tiene URLs de evidencia directa en la corrida seleccionada.",
    evidence: "Evidencia",
    category: "Categoria",
    type: "Tipo",
    allTypes: "Todos",
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
    findings: "hallazgos",
    readOnly: "Referencia sin registro persistido",
    saveError: "No fue posible guardar la validación. La corrida no fue modificada."
  },
  en: {
    title: "Run URL evidence",
    sectionTitle: "Module URL evidence",
    openIntelligenceTitle: "OSINT and SOCMINT evidence",
    subtitle: "Collected URLs for validating findings, mentions and signals. Mark false positive to exclude it from operational reading.",
    sectionSubtitle: "Only URLs related to the current menu. Global evidence remains in the Strategic Dashboard.",
    openIntelligenceSubtitle: "Public-web and social URLs from this run, organized by type for validation and traceability.",
    empty: "This run has no direct evidence URLs to validate.",
    sectionEmpty: "This module has no direct evidence URLs in the selected run.",
    evidence: "Evidence",
    category: "Category",
    type: "Type",
    allTypes: "All",
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
    findings: "findings",
    readOnly: "Reference without a persisted record",
    saveError: "The review could not be saved. The run was not modified."
  }
};

export function EvidenceLedger({ run, language, view = "dashboards" }: { run?: RunRecord; language: LanguageMode; view?: ViewKey }) {
  const t = copy[language];
  const isGlobal = view === "dashboards";
  const isOpenIntelligence = view === "osint" || view === "socmint";
  const items = useMemo(() => buildEvidenceItems(run, language, view), [run, language, view]);
  const typeCounts = useMemo(
    () => Object.entries(items.reduce<Record<string, number>>((counts, item) => {
      counts[item.evidenceType] = (counts[item.evidenceType] ?? 0) + 1;
      return counts;
    }, {})).sort((left, right) => right[1] - left[1]),
    [items]
  );
  const [statuses, setStatuses] = useState<Record<string, EvidenceStatus>>({});
  const [selectedType, setSelectedType] = useState("all");
  const [savingId, setSavingId] = useState<string | null>(null);
  const [saveError, setSaveError] = useState("");

  useEffect(() => {
    if (!run) {
      setStatuses({});
      setSaveError("");
      return;
    }
    setStatuses(Object.fromEntries(items.map((item) => [item.id, item.status])));
    if (selectedType !== "all" && !items.some((item) => item.evidenceType === selectedType)) setSelectedType("all");
  }, [run, items]);
  const visibleItems = selectedType === "all" ? items : items.filter((item) => item.evidenceType === selectedType);

  async function setStatus(item: EvidenceItem, status: EvidenceStatus) {
    if (!run || savingId || !item.reviewable) return;
    setSavingId(item.id);
    setSaveError("");
    try {
      await reviewRunEvidence(run.id, item.id, status);
      setStatuses((current) => ({ ...current, [item.id]: status }));
    } catch {
      setSaveError(t.saveError);
    } finally {
      setSavingId(null);
    }
  }

  return (
    <section className={`panel chart-card span-12 evidence-ledger scroll-card ${isGlobal ? "global" : "module"}`}>
      <div className="panel-title-row compact">
        <div>
          <h2>{isGlobal ? t.title : isOpenIntelligence ? t.openIntelligenceTitle : t.sectionTitle}</h2>
          <p>{isGlobal ? t.subtitle : isOpenIntelligence ? t.openIntelligenceSubtitle : t.sectionSubtitle}</p>
        </div>
        <div className="evidence-ledger-summary">
          <ShieldCheck size={18} />
          <strong>{items.length}</strong>
          <span>{t.visible}</span>
          <em>{run?.summary.kpis.new_events ?? 0} {t.events} · {run?.summary.findings.length ?? 0} {t.findings}</em>
        </div>
      </div>
      {saveError ? <p className="inline-error" role="alert">{saveError}</p> : null}
      {items.length ? (
        <div className="evidence-type-filters" aria-label={t.type}>
          <button className={selectedType === "all" ? "selected" : ""} onClick={() => setSelectedType("all")} type="button">
            <span>{t.allTypes}</span><strong>{items.length}</strong>
          </button>
          {typeCounts.map(([type, count]) => (
            <button className={selectedType === type ? "selected" : ""} key={type} onClick={() => setSelectedType(type)} type="button">
              <span>{evidenceTypeLabel(type, language)}</span><strong>{count}</strong>
            </button>
          ))}
        </div>
      ) : null}
      {!items.length ? (
        <div className="chart-empty">{isGlobal ? t.empty : t.sectionEmpty}</div>
      ) : (
        <div className="evidence-ledger-list">
          {visibleItems.map((item) => {
            const status = statuses[item.id] ?? item.status;
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
                  <span>{t.type}: {evidenceTypeLabel(item.evidenceType, language)}</span>
                  <span>{t.domain}: {item.domain || "n/a"}</span>
                  <span>{t.source}: {item.source || "n/a"}</span>
                </div>
                <div className="evidence-ledger-actions" aria-label={t.evidence}>
                  {item.reviewable ? (
                    <>
                      <button disabled={savingId === item.id} className={status === "validated" ? "selected" : ""} onClick={() => void setStatus(item, "validated")} title={t.markValid}>
                        <CheckCircle2 size={15} />
                        <span>{t.validated}</span>
                      </button>
                      <button disabled={savingId === item.id} className={status === "false_positive" ? "selected danger" : ""} onClick={() => void setStatus(item, "false_positive")} title={t.markFalse}>
                        <Ban size={15} />
                        <span>{t.falsePositive}</span>
                      </button>
                      <button disabled={savingId === item.id} className={status === "pending" ? "selected neutral" : ""} onClick={() => void setStatus(item, "pending")} title={t.reset}>
                        <RotateCcw size={15} />
                        <span>{t.pending}</span>
                      </button>
                    </>
                  ) : (
                    <span className="evidence-readonly">{t.readOnly}</span>
                  )}
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
  const eventsByUrl = new Map(
    (run?.summary.events ?? [])
      .map((event) => [publicEvidenceUrl(event.evidence_url) || "", event] as const)
      .filter(([url]) => Boolean(url))
  );
  for (const event of run?.summary.events ?? []) {
    if (!matchesEvidenceView(event, view)) continue;
    const url = publicEvidenceUrl(event.evidence_url) || "";
    if (!url || items.has(url)) continue;
    const scopeText = [
      event.title,
      url,
      event.asset ?? "",
      event.host ?? "",
      ...(event.tags ?? [])
    ].join(" ").toLowerCase();
    const domain = domains.find((item) => {
      return scopeText.includes(item.toLowerCase());
    });
    items.set(url, {
      id: event.canonical_id || event.id || url,
      title: cleanEvidenceTitle(event.title),
      category: event.category,
      evidenceType: event.evidence_type || "other",
      domain: domain || "",
      url,
      source: displaySourceName(event.source, language),
      status: evidenceReviewStatus(event.evidence_status),
      reviewable: Boolean(event.canonical_id || event.id)
    });
  }
  for (const finding of run?.summary.findings ?? []) {
    if (!matchesFindingView(finding, view)) continue;
    for (const evidence of finding.evidence ?? []) {
      const url = publicEvidenceUrl(evidence) || "";
      if (!/^https?:\/\//i.test(url) || items.has(url)) continue;
      const sourceEvent = eventsByUrl.get(url);
      const domain = domains.find((item) => url.toLowerCase().includes(item.toLowerCase()));
      items.set(url, {
        id: sourceEvent?.canonical_id || sourceEvent?.id || `${finding.title}-${url}`,
        title: cleanEvidenceTitle(finding.title),
        category: finding.category,
        evidenceType: sourceEvent?.evidence_type || "other",
        domain: domain || "",
        url,
        source: sourceEvent
          ? displaySourceName(sourceEvent.source, language)
          : language === "en"
            ? "Finding evidence"
            : "Evidencia de hallazgo",
        status: evidenceReviewStatus(sourceEvent?.evidence_status),
        reviewable: Boolean(sourceEvent?.canonical_id || sourceEvent?.id)
      });
    }
  }
  return [...items.values()];
}

function evidenceTypeLabel(type: string, language: LanguageMode): string {
  const labels: Record<string, [string, string]> = {
    document: ["Documentos y archivos", "Documents and files"],
    web_page: ["Páginas web", "Web pages"],
    news: ["Noticias y comunicados", "News and releases"],
    social_media: ["Redes sociales", "Social media"],
    technology_infrastructure: ["Tecnología e infraestructura", "Technology and infrastructure"],
    official_record: ["Registros oficiales", "Official records"],
    authorized_dark_web: ["Dark web autorizada", "Authorized dark web"],
    other: ["Otros registros", "Other records"]
  };
  return (labels[type] ?? labels.other)[language === "es" ? 0 : 1];
}

function evidenceReviewStatus(value?: string): EvidenceStatus {
  if (value === "validated" || value === "confirmed") return "validated";
  if (value === "false_positive" || value === "discarded") return "false_positive";
  return "pending";
}

function matchesEvidenceView(event: ThreatEvent, view: ViewKey): boolean {
  if (view === "dashboards") return true;
  const text = `${event.source} ${event.category} ${event.title} ${event.actor ?? ""} ${event.technique ?? ""} ${(event.tags ?? []).join(" ")}`.toLowerCase();
  const url = (event.evidence_url ?? "").toLowerCase();
  const combinedText = `${text} ${url}`;
  const isSocmint = /socmint|social|facebook|instagram|tiktok|linkedin|twitter|\bx\b|reddit|mention|mencion|hashtag|profile|account|usuario|narrativ/.test(combinedText);
  const isDarkweb = /dark|tor|onion|leak|filtraci|ransom|extortion|dump|paste|credential/.test(combinedText);
  const isOsint = /osint|public search|internet search|google|duckduckgo|common crawl|open web|search|dork|filetype|indexed|document|busqueda/.test(text);
  if (view === "attackSurface") return /external|surface|dns|whois|ssl|certificate|cert|subdomain|port|technology|http|domain|mx|spf|dmarc|tls/.test(`${text} ${url}`);
  if (view === "brand") return /brand|marca|fraud|fraude|farsa|estafa|scam|phish|imperson|suplant|lookalike|homograph|reputation|reputaci|sentiment|cliente|customer|empleo falso|oferta laboral falsa|fake job|recruitment scam/.test(`${text} ${url}`);
  if (view === "disinformation") return /disarm|disinfo|misinfo|fake|false|fals[oa]|narrativ|influence|amplif|propaganda|coordinat|trust|confianza|estafa|scam|suplant|imperson|empleo falso|oferta laboral falsa|fake job|recruitment scam/.test(text);
  if (view === "osint" || view === "socmint") return (isOsint || isSocmint) && !isDarkweb;
  if (view === "darkweb") return isDarkweb;
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
