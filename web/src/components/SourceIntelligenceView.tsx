import { FileSearch, Globe2, LockKeyhole, RadioTower, Search } from "lucide-react";
import type { ReactNode } from "react";
import type { RunRecord } from "../types";
import { buildDashboardModel, buildDomainEvidence, buildExposureAudit, extractSearchQuery, sourceEvents } from "../utils/dashboard";
import { defaultDashboardFilters } from "../data/catalog";
import { BarRanking, LineChart } from "./ChartPrimitives";
import { SourceDiagnosticsPanel } from "./SourceDiagnosticsPanel";
import { cleanEvidenceText, cleanEvidenceTitle, displaySourceName, eventEvidenceUrl } from "../utils/sourceLabels";

export function SourceIntelligenceView({ run, channel, language }: { run?: RunRecord; channel: "osint" | "darkweb"; language: "es" | "en" }) {
  const events = sourceEvents(run, channel);
  const scopedRun = run ? { ...run, summary: { ...run.summary, events } } : undefined;
  const model = buildDashboardModel(scopedRun, defaultDashboardFilters);
  const isDarkweb = channel === "darkweb";
  const copy = sourceCopy[language];
  const channelCopy = copy[channel];
  const domainEvidence = buildDomainEvidence(run, events);
  const exposureAudit = buildExposureAudit(run, events, "osint");
  const queryEvidence = events.map((event) => ({ event, query: extractSearchQuery(event) })).filter((item) => item.query);

  if (!events.length) {
    return (
      <div className="view-stack">
        <section className="dashboard-grid source-dashboard-grid">
          <SourceDiagnosticsPanel run={run} channel={channel} language={language} className={isDarkweb ? "span-12 scroll-card" : "span-12"} />
          {isDarkweb ? <DarkWebSafetyPanel run={run} language={language} /> : null}
        </section>
      </div>
    );
  }

  return (
    <div className="view-stack">
      <section className="dashboard-kpis">
        <Metric icon={isDarkweb ? <LockKeyhole size={18} /> : <Globe2 size={18} />} label={copy.signals} value={String(events.length)} />
        <Metric icon={<RadioTower size={18} />} label={copy.sources} value={String(new Set(events.map((event) => displaySourceName(event.source, language))).size)} />
        <Metric icon={<Globe2 size={18} />} label={copy.actorsKpi} value={String(model.actors.length)} />
        <Metric icon={<RadioTower size={18} />} label={copy.ttps} value={String(model.ttpImpact.length)} />
      </section>

      <section className="dashboard-grid source-dashboard-grid">
        {isDarkweb ? <DarkWebSafetyPanel run={run} language={language} /> : null}
        <article className="panel chart-card span-8">
          <div className="panel-title-row compact">
            <div>
              <h2>{channelCopy.trend}</h2>
              <p>{channelCopy.subtitle}</p>
            </div>
          </div>
          <LineChart points={model.trend} language={language} />
        </article>
        <SourceDiagnosticsPanel run={run} channel={channel} language={language} className={isDarkweb ? "span-12 scroll-card" : "span-4"} />
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.categories}</h2>
              <p>{copy.categoriesSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.categories} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.actors}</h2>
              <p>{copy.actorsSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.actors} language={language} />
        </article>
        <article className="panel chart-card span-4 compact-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.ttp}</h2>
              <p>{copy.ttpSubtitle}</p>
            </div>
          </div>
          <BarRanking items={model.ttpImpact} language={language} />
        </article>
        {!isDarkweb ? (
          <article className="panel chart-card span-4 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.domainEvidence}</h2>
                <p>{copy.domainEvidenceSubtitle}</p>
              </div>
              <FileSearch size={18} />
            </div>
            <DomainEvidenceList items={domainEvidence} language={language} />
          </article>
        ) : null}
        {!isDarkweb ? (
          <article className="panel chart-card span-8 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.exposureAudit}</h2>
                <p>{copy.exposureAuditSubtitle}</p>
              </div>
              <Search size={18} />
            </div>
            <ExposureAuditList items={exposureAudit} language={language} />
          </article>
        ) : null}
        {!isDarkweb ? (
          <article className="panel chart-card span-4 scroll-card">
            <div className="panel-title-row compact">
              <div>
                <h2>{copy.queries}</h2>
                <p>{copy.queriesSubtitle}</p>
              </div>
            </div>
            <div className="query-list">
            {queryEvidence.map(({ event, query }) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{query}</strong>
                <span>{displaySourceName(event.source, language)}</span>
                {eventEvidenceUrl(event) ? <code className="signal-url">{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
              {!queryEvidence.length ? <span className="muted-empty">{copy.emptyQueries}</span> : null}
            </div>
          </article>
        ) : null}
        <article className={isDarkweb ? "panel chart-card span-12 scroll-card" : "panel chart-card span-8 scroll-card"}>
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.latest}</h2>
              <p>{copy.latestSubtitle}</p>
            </div>
          </div>
          <div className="headline-list">
            {events.map((event) => (
              <a key={event.id} href={eventEvidenceUrl(event) ?? "#"} target="_blank" rel="noreferrer">
                <strong>{displaySourceName(event.source, language)}</strong>
                <span>{cleanEvidenceTitle(event.title)}</span>
                {eventEvidenceUrl(event) ? <code className="signal-url">{eventEvidenceUrl(event)}</code> : null}
              </a>
            ))}
            {!events.length ? <span className="muted-empty">{copy.emptyLatest}</span> : null}
          </div>
        </article>
      </section>
    </div>
  );
}

const sourceCopy = {
  es: {
    signals: "Senales",
    sources: "Fuentes",
    actorsKpi: "Actores",
    ttps: "TTPs",
    categories: "Categorias",
    categoriesSubtitle: "Distribucion de senales analizadas",
    actors: "Actores y grupos",
    actorsSubtitle: "Priorizados por evidencia observada",
    ttp: "Impacto TTP",
    ttpSubtitle: "Tecnicas interpretadas desde la evidencia",
    domainEvidence: "Evidencia por dominio",
    domainEvidenceSubtitle: "Resultados abiertos ligados a dominios analizados",
    exposureAudit: "Auditoria defensiva de exposicion",
    exposureAuditSubtitle: "Dorks defensivos contados desde evidencia recolectada",
    queries: "Busquedas recolectadas",
    queriesSubtitle: "Consultas asociadas a registros OSINT",
    emptyQueries: "Sin metadatos de busqueda en los registros OSINT actuales.",
    latest: "Registros recientes",
    latestSubtitle: "Evidencia y menciones de la corrida actual",
    emptyLatest: "Sin registros fuente para mostrar.",
    osint: {
      trend: "Tendencia OSINT",
      subtitle: "Noticias, web abierta, vulnerabilidades, RSS tecnico y evidencia publica"
    },
    darkweb: {
      trend: "Tendencia Dark Web",
      subtitle: "Leaks, extorsion, ransomware e indices autorizados"
    },
    darkSafety: {
      title: "Revision temporal segura de dark web",
      subtitle: "Arquitectura para recoleccion autorizada y de bajo riesgo sin interaccion insegura con mercados",
      postureTitle: "Postura de recoleccion",
      posture: "El modo actual usa indices pasivos, fuentes publicas ransomware, importaciones redacted y verificaciones de Tor. No rastrea mercados ni compra datos.",
      boundaryTitle: "Limite de runtime",
      boundary: "La revision temporal Tor debe ejecutarse aislada, limitada en tiempo, sin credenciales, sin descargas, sin scripts y sin persistencia mas alla de metadatos normalizados.",
      legalTitle: "Control legal",
      legal: "Cada corrida requiere alcance autorizado y debe escalarse con legal, CTI y respuesta antes de acceso directo a dark web.",
      safeguards: [
        "Prioriza indices publicos ransomware e importaciones autorizadas/redacted antes de cualquier runtime Tor.",
        "No autenticar, transar, descargar payloads ni interactuar con mercados.",
        "Usar runtime temporal aislado solo cuando ALLOW_TOR y autorizacion legal sean explicitos.",
        "Guardar solo metadatos necesarios para decision: fuente, titulo, timestamp, URL/indice y categoria de riesgo."
      ],
      records: "registros",
      noWarning: "Sin alerta",
      empty: "Sin estado de conector dark web/Tor/ransomware en la corrida actual."
    },
    domainEvidenceEmpty: "Sin resultados OSINT ligados a dominio en la corrida actual.",
    signalsWord: "senales",
    noSource: "sin fuente",
    uncategorized: "sin categoria",
    exposureEmpty: "Sin dominios disponibles para auditoria de exposicion.",
    matchedRecords: "registros coincidentes"
  },
  en: {
    signals: "Signals",
    sources: "Sources",
    actorsKpi: "Actors",
    ttps: "TTPs",
    categories: "Categories",
    categoriesSubtitle: "Distribution from analysed signals",
    actors: "Actors and groups",
    actorsSubtitle: "Ranked by observed evidence",
    ttp: "TTP impact",
    ttpSubtitle: "Techniques interpreted from evidence",
    domainEvidence: "Domain evidence",
    domainEvidenceSubtitle: "Open results tied to analysed domains",
    exposureAudit: "Defensive exposure audit",
    exposureAuditSubtitle: "Defensive dorks counted from collected evidence",
    queries: "Collected search queries",
    queriesSubtitle: "Queries attached to OSINT records",
    emptyQueries: "No query metadata in current OSINT records.",
    latest: "Latest source records",
    latestSubtitle: "Evidence and mentions from current run",
    emptyLatest: "No source records to show.",
    osint: {
      trend: "OSINT trend",
      subtitle: "Open web, news, vulnerabilities, technical RSS and public evidence"
    },
    darkweb: {
      trend: "Dark Web trend",
      subtitle: "Leaks, extortion, ransomware and authorized indexes"
    },
    darkSafety: {
      title: "Safe temporary dark web review",
      subtitle: "Architecture for authorized, low-risk collection without unsafe marketplace interaction",
      postureTitle: "Collection posture",
      posture: "Current app mode uses passive indexes, ransomware public sources, redacted imports and Tor availability checks. It does not crawl or buy data.",
      boundaryTitle: "Runtime boundary",
      boundary: "Temporary Tor review should run isolated, time-limited, no credentials, no downloads, no scripts, no persistence beyond normalized metadata.",
      legalTitle: "Legal guardrail",
      legal: "Every run requires authorized scope and should be escalated through legal, CTI and incident response before direct dark web access.",
      safeguards: [
        "Prefer public ransomware indexes and authorized/redacted imports before any Tor runtime.",
        "Do not authenticate, transact, download payloads, or interact with marketplaces.",
        "Use temporary, isolated runtime only when ALLOW_TOR and legal authorization are explicit.",
        "Store only metadata needed for decision: source, title, timestamp, URL/index and risk category."
      ],
      records: "records",
      noWarning: "No warning",
      empty: "No dark web/Tor/ransomware connector status in the current run."
    },
    domainEvidenceEmpty: "No domain-linked OSINT results in the current run.",
    signalsWord: "signals",
    noSource: "no source",
    uncategorized: "uncategorized",
    exposureEmpty: "No domains available for exposure audit.",
    matchedRecords: "matched records"
  }
};

function DarkWebSafetyPanel({ run, language }: { run?: RunRecord; language: "es" | "en" }) {
  const copy = sourceCopy[language].darkSafety;
  const statuses = (run?.summary.source_statuses ?? []).filter((status) => /dark|tor|ransom|onion|leak/i.test(`${status.name} ${status.mode} ${status.warning ?? ""}`));
  return (
    <section className="panel chart-card span-12 scroll-card darkweb-safety">
      <div className="panel-title-row compact">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
        </div>
        <LockKeyhole size={18} />
      </div>
      <div className="safety-grid">
        <div>
          <strong>{copy.postureTitle}</strong>
          <p>{copy.posture}</p>
        </div>
        <div>
          <strong>{copy.boundaryTitle}</strong>
          <p>{copy.boundary}</p>
        </div>
        <div>
          <strong>{copy.legalTitle}</strong>
          <p>{copy.legal}</p>
        </div>
      </div>
      <div className="safety-list">
        {copy.safeguards.map((item) => <span key={item}>{item}</span>)}
      </div>
      <div className="source-status-mini">
        {statuses.map((status) => (
          <div key={`${status.name}-${status.status}`}>
            <strong>{displaySourceName(status.name, language)}</strong>
            <span>{status.status} | {status.records} {copy.records}</span>
            <em>{cleanEvidenceText(status.warning) || copy.noWarning}</em>
          </div>
        ))}
        {!statuses.length ? <div className="chart-empty">{copy.empty}</div> : null}
      </div>
    </section>
  );
}

function DomainEvidenceList({ items, language }: { items: ReturnType<typeof buildDomainEvidence>; language: "es" | "en" }) {
  const copy = sourceCopy[language];
  if (!items.length) return <div className="chart-empty">{copy.domainEvidenceEmpty}</div>;
  return (
    <div className="domain-evidence-list">
      {items.map((item) => (
        <div key={item.domain}>
          <strong>{item.domain}</strong>
          <span>{item.signals} {copy.signalsWord} | {item.sources.map((source) => displaySourceName(source, language)).join(", ") || copy.noSource}</span>
          <em>{item.categories.join(" / ") || copy.uncategorized}</em>
        </div>
      ))}
    </div>
  );
}

function ExposureAuditList({ items, language }: { items: ReturnType<typeof buildExposureAudit>; language: "es" | "en" }) {
  const copy = sourceCopy[language];
  if (!items.length) return <div className="chart-empty">{copy.exposureEmpty}</div>;
  return (
    <div className="exposure-audit-grid">
      {items.map((item) => (
        <div className={`exposure-audit-item ${item.tone}`} key={`${item.domain}-${item.label}`}>
          <strong>{item.label}</strong>
          <code>{item.query}</code>
          <span>{item.resultCount} {copy.matchedRecords}</span>
          <em>{item.intent}</em>
          {item.urls.length ? (
            <div className="exposure-url-list">
              {item.urls.map((url) => (
                <a href={url} target="_blank" rel="noreferrer" key={url}>{url}</a>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
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
