import { Ban, CheckCircle2, ExternalLink, FileChartColumn, RotateCcw, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import type { LanguageMode, RunRecord, ThreatEvent, ViewKey, Finding } from "../types";
import { cleanEvidenceTitle, displaySourceName, publicEvidenceUrl } from "../utils/sourceLabels";
import { evidenceReviews } from "../utils/evidenceReviewQueue";
import { getRunEvidence } from "../api";

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
  reviewIds: string[];
}

const copy = {
  es: {
    title: "Evidencia URL de la corrida",
    sectionTitle: "Evidencia URL del módulo",
    openIntelligenceTitle: "Evidencia OSINT y SOCMINT",
    subtitle: "Evidencia de la corrida y resultado de la revisión analítica.",
    sectionSubtitle: "Sólo URLs relacionadas con el menú actual. La evidencia global se conserva en el Tablero estratégico.",
    openIntelligenceSubtitle: "URLs públicas y sociales de la corrida, organizadas por tipo para su validación y trazabilidad.",
    empty: "Esta corrida no tiene URLs de evidencia directa para validar.",
    sectionEmpty: "Este módulo no tiene URLs de evidencia directa en la corrida seleccionada.",
    evidence: "Evidencia",
    category: "Categoría",
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

export function EvidenceLedger({ run, language, view = "dashboards", onGenerateReport }: { run?: RunRecord; language: LanguageMode; view?: ViewKey; onGenerateReport?: (runId: string) => void }) {
  const t = copy[language];
  const isGlobal = view === "dashboards";
  const isOpenIntelligence = view === "osint" || view === "socmint";
  const [allEvents, setAllEvents] = useState<ThreatEvent[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    if (!run || run.status !== "completed") return;
    let active = true;
    setLoading(true);
    setLoadError(false);
    getRunEvidence(run.id).then((result) => { if (active) setAllEvents(result.events); })
      .catch(() => { if (active) setLoadError(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [run?.id, run?.updated_at, run?.status, reload]);
  const items = useMemo(() => buildEvidenceItems(run && allEvents ? { ...run, summary: { ...run.summary, events: allEvents } } : run, language, view), [run, allEvents, language, view]);
  const typeCounts = useMemo(
    () => Object.entries(items.reduce<Record<string, number>>((counts, item) => {
      counts[item.evidenceType] = (counts[item.evidenceType] ?? 0) + 1;
      return counts;
    }, {})).sort((left, right) => right[1] - left[1]),
    [items]
  );
  const [selectedType, setSelectedType] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState<EvidenceStatus | "all">("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const reviews = useSyncExternalStore(evidenceReviews.subscribe, () => evidenceReviews.snapshot(run?.id ?? ""));
  const savingCount = Object.values(reviews).filter((entry) => entry.state === "saving").length;
  const errorCount = Object.values(reviews).filter((entry) => entry.state === "error").length;

  useEffect(() => {
    if (selectedType !== "all" && !items.some((item) => item.evidenceType === selectedType)) setSelectedType("all");
  }, [run, items]);
  const currentStatus = (item: EvidenceItem): EvidenceStatus => reviews[item.id]?.status ?? item.status;
  const typedItems = selectedType === "all" ? items : items.filter((item) => item.evidenceType === selectedType);
  const statusCounts = typedItems.reduce((counts, item) => { counts[currentStatus(item)]++; return counts; }, { pending: 0, validated: 0, false_positive: 0 });
  const visibleItems = selectedStatus === "all" ? typedItems : typedItems.filter((item) => currentStatus(item) === selectedStatus);
  const selectable = visibleItems.filter((item) => item.reviewable);
  const selectedItems = items.filter((item) => selected.has(item.id) && item.reviewable);
  useEffect(() => { setSelected(new Set()); }, [selectedType, selectedStatus]);

  function setStatus(item: EvidenceItem, status: EvidenceStatus) {
    if (!run || !item.reviewable || run.status !== "completed") return;
    evidenceReviews.enqueueMany(run.id, item.reviewIds.map((evidence_id) => ({ evidence_id, status })));
  }

  function applySelected(status: EvidenceStatus) {
    if (!run || run.status !== "completed") return;
    evidenceReviews.enqueueMany(run.id, selectedItems.flatMap((item) => item.reviewIds.map((evidence_id) => ({ evidence_id, status }))));
    setSelected(new Set());
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
      {run && run.status !== "completed" ? <p role="status">{language === "es" ? "La revisión estará disponible cuando termine el análisis." : "Review becomes available when analysis completes."}</p> : null}
      {loading ? <p role="status">{language === "es" ? "Cargando el registro completo de evidencia..." : "Loading the complete evidence register..."}</p> : null}
      {loadError ? <p role="alert">{language === "es" ? "No se pudo cargar la lista completa." : "The complete list could not be loaded."} <button type="button" onClick={() => setReload((value) => value + 1)}><RotateCcw size={14} />{language === "es" ? "Reintentar" : "Retry"}</button></p> : null}
      {run ? <div className="evidence-review-outcome">
        <div><strong>{language === "es" ? "Resultado de la revisión" : "Review outcome"}</strong><p>{run.summary.kpis.validated_evidence ?? 0} {language === "es" ? "registros validados" : "validated records"} · {run.summary.kpis.validated_findings ?? 0} {language === "es" ? "hallazgos de riesgo sustentados" : "supported risk findings"}</p>
          {!run.summary.kpis.validated_findings ? <p>{language === "es" ? "La evidencia validada aún no sustenta un hallazgo de riesgo aplicable. Los datos de contexto se conservan en el análisis y el informe." : "Validated evidence does not yet support an applicable risk finding. Context remains in the analysis and report."}</p> : null}
        </div>
        {onGenerateReport ? <button type="button" className="primary-button" disabled={Boolean(savingCount || errorCount) || run.status !== "completed" || ["queued", "generating"].includes(run.report_status ?? "")} onClick={() => onGenerateReport(run.id)}><FileChartColumn size={17} />{language === "es" ? "Generar / actualizar informe" : "Generate / update report"}</button> : null}
      </div> : null}
      {savingCount > 0 ? <p role="status">{language === "es" ? `Guardando ${savingCount} ${savingCount === 1 ? "revisión" : "revisiones"} en segundo plano...` : `Saving ${savingCount} ${savingCount === 1 ? "review" : "reviews"} in the background...`}</p> : null}
      {errorCount > 0 ? <p role="alert">{language === "es" ? `${errorCount} ${errorCount === 1 ? "revisión" : "revisiones"} sin confirmar.` : `${errorCount} unconfirmed ${errorCount === 1 ? "review" : "reviews"}.`} <button type="button" onClick={() => {
        if (run) Object.entries(reviews).filter(([, entry]) => entry.state === "error").forEach(([id, entry]) => evidenceReviews.enqueue(run.id, id, entry.status));
      }}><RotateCcw size={14} />{language === "es" ? "Reintentar guardado" : "Retry saving"}</button></p> : null}
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
      <div className="evidence-type-filters" aria-label={language === "es" ? "Estado de revisión" : "Review status"}>
        {(["all", "validated", "false_positive", "pending"] as const).map((status) => <button type="button" key={status} aria-pressed={selectedStatus === status} className={selectedStatus === status ? "selected" : ""} onClick={() => setSelectedStatus(status)}><span>{status === "all" ? t.allTypes : status === "validated" ? t.validated : status === "false_positive" ? t.falsePositive : t.pending}</span><strong>{status === "all" ? typedItems.length : statusCounts[status]}</strong></button>)}
      </div>
      <div className="evidence-bulk-toolbar">
        <label><input type="checkbox" aria-label={language === "es" ? "Seleccionar todas las evidencias visibles" : "Select all visible evidence"} checked={selectable.length > 0 && selectable.every((item) => selected.has(item.id))} disabled={!selectable.length || loading || run?.status !== "completed"} onChange={(event) => setSelected(event.target.checked ? new Set(selectable.map((item) => item.id)) : new Set())} />{language === "es" ? "Seleccionar visibles" : "Select visible"}</label>
        <span>{selectedItems.length} {language === "es" ? "seleccionadas" : "selected"}</span>
        <div className="evidence-ledger-actions">
          <button type="button" disabled={!selectedItems.length} onClick={() => applySelected("validated")}><CheckCircle2 size={15} />{language === "es" ? "Validar selección" : "Validate selection"}</button>
          <button type="button" disabled={!selectedItems.length} onClick={() => applySelected("false_positive")}><Ban size={15} />{language === "es" ? "Marcar falsos positivos" : "Mark false positives"}</button>
          <button type="button" disabled={!selectedItems.length} onClick={() => applySelected("pending")}><RotateCcw size={15} />{language === "es" ? "Dejar pendientes" : "Mark pending"}</button>
        </div>
      </div>
      {!items.length ? (
        <div className="chart-empty">{isGlobal ? t.empty : t.sectionEmpty}</div>
      ) : !visibleItems.length ? (
        <div className="chart-empty">{language === "es" ? "Sin evidencias para estos filtros." : "No evidence matches these filters."}</div>
      ) : (
        <div className="evidence-ledger-list">
          {visibleItems.map((item) => {
            const review = reviews[item.id];
            const status = review?.status ?? item.status;
            return (
              <article className={`evidence-ledger-row ${status}`} key={item.id}>
                <div className="evidence-ledger-main">
                  {item.reviewable ? <input type="checkbox" aria-label={`${language === "es" ? "Seleccionar" : "Select"} ${item.title || item.url}`} checked={selected.has(item.id)} disabled={run?.status !== "completed"} onChange={(event) => setSelected((current) => { const next = new Set(current); if (event.target.checked) next.add(item.id); else next.delete(item.id); return next; })} /> : null}
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
                      <button type="button" aria-pressed={status === "validated"} disabled={run?.status !== "completed"} className={status === "validated" ? "selected" : ""} onClick={() => setStatus(item, "validated")} title={t.markValid}>
                        <CheckCircle2 size={15} />
                        <span>{t.validated}</span>
                      </button>
                      <button type="button" aria-pressed={status === "false_positive"} disabled={run?.status !== "completed"} className={status === "false_positive" ? "selected danger" : ""} onClick={() => setStatus(item, "false_positive")} title={t.markFalse}>
                        <Ban size={15} />
                        <span>{t.falsePositive}</span>
                      </button>
                      <button type="button" aria-pressed={status === "pending"} disabled={run?.status !== "completed"} className={status === "pending" ? "selected neutral" : ""} onClick={() => setStatus(item, "pending")} title={t.reset}>
                        <RotateCcw size={15} />
                        <span>{t.pending}</span>
                      </button>
                    </>
                  ) : (
                    <span className="evidence-readonly">{t.readOnly}</span>
                  )}
                </div>
                {review ? <small role={review.state === "error" ? "alert" : "status"}>{review.state === "error" ? (language === "es" ? "Guardado sin confirmar. Reintenta." : "Save unconfirmed. Please retry.") : review.state === "saving" ? (language === "es" ? "Guardando..." : "Saving...") : (language === "es" ? "Revisión guardada." : "Review saved.")}</small> : null}
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
      .map((event) => [publicEvidenceUrl(event.original_artifact_url) || publicEvidenceUrl(event.evidence_url) || "", event] as const)
      .filter(([url]) => Boolean(url))
  );
  for (const event of run?.summary.events ?? []) {
    if (!matchesEvidenceView(event, view)) continue;
    const url = publicEvidenceUrl(event.original_artifact_url) || publicEvidenceUrl(event.evidence_url) || "";
    if (!url) continue;
    const id = event.canonical_id || event.id || url;
    const existing = items.get(url);
    if (existing) {
      if ((event.canonical_id || event.id) && !existing.reviewIds.includes(id)) existing.reviewIds.push(id);
      if (existing.status !== evidenceReviewStatus(event.evidence_status, event.technical_validation)) existing.status = "pending";
      continue;
    }
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
      status: evidenceReviewStatus(event.evidence_status, event.technical_validation),
      reviewable: Boolean(event.canonical_id || event.id),
      reviewIds: event.canonical_id || event.id ? [id] : []
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
        status: evidenceReviewStatus(sourceEvent?.evidence_status, sourceEvent?.technical_validation),
        reviewable: Boolean(sourceEvent?.canonical_id || sourceEvent?.id),
        reviewIds: sourceEvent?.canonical_id || sourceEvent?.id ? [sourceEvent.canonical_id || sourceEvent.id] : []
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

function evidenceReviewStatus(value?: string, validation?: Record<string, unknown>): EvidenceStatus {
  const review = validation?.human_review as { status?: string } | undefined;
  if (review?.status === "pending" || review?.status === "validated" || review?.status === "false_positive") return review.status;
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
  const isOsint = /osint|public search|internet search|public index|open web|search|dork|filetype|indexed|document|busqueda|indice publico/.test(text);
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
