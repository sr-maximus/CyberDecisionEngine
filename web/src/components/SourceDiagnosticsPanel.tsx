import { AlertTriangle, CheckCircle2, CircleSlash2, RadioTower } from "lucide-react";
import type { LanguageMode, RunRecord, SourceStatus } from "../types";
import { cleanEvidenceText, statusDisplayName } from "../utils/sourceLabels";

export type SourceChannel = "osint" | "socmint" | "darkweb";

export function SourceDiagnosticsPanel({
  run,
  channel,
  language,
  className = ""
}: {
  run?: RunRecord;
  channel: SourceChannel;
  language: LanguageMode;
  className?: string;
}) {
  const copy = labels[language];
  const statuses = sourceStatusesForChannel(run, channel);
  const records = statuses.reduce((sum, item) => sum + item.records, 0);
  const issues = statuses.filter((item) => item.status !== "ok" || item.warning).length;

  return (
    <article className={`panel chart-card source-diagnostics ${className}`.trim()}>
      <div className="panel-title-row compact">
        <div>
          <h2>{copy[channel].title}</h2>
          <p>{copy[channel].subtitle}</p>
        </div>
        <RadioTower size={18} />
      </div>
      <div className="source-diagnostic-summary">
        <div>
          <span>{copy.connectors}</span>
          <strong>{statuses.length}</strong>
        </div>
        <div>
          <span>{copy.records}</span>
          <strong>{records}</strong>
        </div>
        <div>
          <span>{copy.issues}</span>
          <strong>{issues}</strong>
        </div>
      </div>
      <div className="source-status-mini">
        {statuses.map((status) => (
          <div className={`source-diagnostic-row ${status.status}`} key={`${channel}-${status.name}-${status.mode}`}>
            {iconForStatus(status)}
            <div>
              <strong>{statusDisplayName(status, language)}</strong>
              <span>{status.status} | {status.records} {copy.recordsLower}</span>
              <em title={cleanEvidenceText(status.warning) || copy.noWarning}>{cleanEvidenceText(status.warning) || copy.noWarning}</em>
            </div>
          </div>
        ))}
        {!statuses.length ? <div className="chart-empty">{copy[channel].empty}</div> : null}
      </div>
      <p className="diagnostic-note">{copy[channel].note}</p>
    </article>
  );
}

export function sourceStatusesForChannel(run: RunRecord | undefined, channel: SourceChannel): SourceStatus[] {
  const statuses = run?.summary.source_statuses ?? [];
  if (channel === "socmint") {
    return statuses.filter((status) => /socmint|social|reddit|facebook|instagram|tiktok|\bx\b/i.test(statusText(status)));
  }
  if (channel === "darkweb") {
    return statuses.filter((status) => /dark|tor|ransom|onion|leak/i.test(statusText(status)));
  }
  return statuses.filter((status) => {
    const text = statusText(status);
    return !/sqlite|cache|socmint|social|reddit|facebook|instagram|tiktok|\bx\b|dark|tor|ransom|onion|leak/i.test(text);
  });
}

function statusText(status: SourceStatus): string {
  return `${status.name} ${status.status} ${status.mode} ${status.warning ?? ""}`;
}

function iconForStatus(status: SourceStatus) {
  if (["ok", "searched", "configured"].includes(status.status)) return <CheckCircle2 size={17} />;
  if (status.status === "disabled" || status.status === "skipped") return <CircleSlash2 size={17} />;
  return <AlertTriangle size={17} />;
}

const labels = {
  es: {
    connectors: "Conectores",
    records: "Registros",
    recordsLower: "registros",
    issues: "Alertas",
    noWarning: "Sin advertencias de la fuente.",
    osint: {
      title: "Estado de fuentes OSINT",
      subtitle: "Conectores abiertos, busquedas y fuentes tecnicas usadas en esta corrida",
      empty: "No hay estado de conectores OSINT en la corrida actual.",
      note: "Si hay cero registros, la plataforma no inventa resultados; revisa rango temporal, dominios, fuentes o limites de proveedor."
    },
    socmint: {
      title: "Estado de fuentes SOCMINT",
      subtitle: "Menciones publicas y busquedas sociales autorizadas",
      empty: "No hay estado SOCMINT en esta corrida. Valida que la fuente publica este habilitada y que existan palabras clave.",
      note: "SOCMINT usa fuentes publicas permitidas. Si Reddit u otra fuente limita la respuesta, el estado queda registrado aqui."
    },
    darkweb: {
      title: "Estado Dark Web / ransomware",
      subtitle: "Indices publicos, importaciones autorizadas y limites de Tor",
      empty: "No hay estado Dark Web/Tor/ransomware en esta corrida.",
      note: "Dark Web se mantiene en modo pasivo y autorizado. Sin coincidencias no se muestran nodos ni resultados inventados."
    }
  },
  en: {
    connectors: "Connectors",
    records: "Records",
    recordsLower: "records",
    issues: "Alerts",
    noWarning: "No source warning.",
    osint: {
      title: "OSINT source status",
      subtitle: "Open connectors, searches and technical sources used in this run",
      empty: "No OSINT connector status in the current run.",
      note: "If there are zero records, the platform does not invent results; review time range, domains, sources or provider limits."
    },
    socmint: {
      title: "SOCMINT source status",
      subtitle: "Public mentions and authorized social searches",
      empty: "No SOCMINT status in this run. Validate that the public source is enabled and keywords exist.",
      note: "SOCMINT uses allowed public sources. If Reddit or another source limits the response, the status is recorded here."
    },
    darkweb: {
      title: "Dark Web / ransomware status",
      subtitle: "Public indexes, authorized imports and Tor boundaries",
      empty: "No Dark Web/Tor/ransomware status in the current run.",
      note: "Dark Web remains passive and authorized. Without matches, no invented nodes or results are shown."
    }
  }
};
