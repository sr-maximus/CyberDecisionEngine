import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  ExternalLink,
  KeyRound,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  ShieldCheck
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getCTIKnowledgeManifest,
  rollbackCTIKnowledge,
  syncCTIKnowledge
} from "../api";
import type {
  CTIKnowledgeManifest,
  CTIKnowledgeOperationResult,
  CTIKnowledgeSource,
  LanguageMode
} from "../types";

interface KnowledgeCatalogAdminPanelProps {
  language: LanguageMode;
  canAdminister: boolean;
}

type Operation = "refresh" | "sync" | "rollback" | null;

const copy = {
  es: {
    eyebrow: "Conocimiento de referencia",
    title: "Catálogos CTI y MITRE",
    description: "Controla las versiones locales que sustentan actores, campañas, TTP y mapeos defensivos. Estas fuentes no alteran la evidencia recolectada.",
    ready: "Catálogo operativo",
    degraded: "Catálogo con atención pendiente",
    mandatory: "obligatorias disponibles",
    records: "registros",
    sources: "fuentes",
    refresh: "Comprobar estado",
    sync: "Actualizar seleccionadas",
    rollback: "Recuperar copia anterior",
    selectAll: "Seleccionar descargables",
    clear: "Limpiar selección",
    adminKey: "Clave administrativa temporal",
    keyHelp: "La clave se mantiene sólo durante esta vista; no se guarda en el navegador.",
    permission: "Tu rol puede consultar el estado, pero sólo un administrador puede actualizar o recuperar catálogos.",
    selectRequired: "Selecciona al menos una fuente descargable.",
    keyRequired: "Ingresa la clave administrativa configurada en el servidor.",
    refreshed: "Estado de catálogos actualizado.",
    synced: "Fuentes seleccionadas actualizadas y verificadas.",
    rolledBack: "Se restauró la última copia válida de las fuentes seleccionadas.",
    status: {
      active: "Activa",
      last_known_good: "Copia válida",
      missing: "Faltante",
      reference: "Referencia externa"
    }
  },
  en: {
    eyebrow: "Reference knowledge",
    title: "CTI and MITRE catalogs",
    description: "Control the local versions supporting actors, campaigns, TTPs and defensive mappings. These sources do not alter collected evidence.",
    ready: "Catalog operational",
    degraded: "Catalog needs attention",
    mandatory: "mandatory sources available",
    records: "records",
    sources: "sources",
    refresh: "Check status",
    sync: "Update selected",
    rollback: "Restore previous copy",
    selectAll: "Select downloadable",
    clear: "Clear selection",
    adminKey: "Temporary administrator key",
    keyHelp: "The key remains only in this view and is never stored in the browser.",
    permission: "Your role can inspect status, but only an administrator can update or restore catalogs.",
    selectRequired: "Select at least one downloadable source.",
    keyRequired: "Enter the administrator key configured on the server.",
    refreshed: "Catalog status refreshed.",
    synced: "Selected sources updated and verified.",
    rolledBack: "The last valid copy was restored for the selected sources.",
    status: {
      active: "Active",
      last_known_good: "Valid copy",
      missing: "Missing",
      reference: "External reference"
    }
  }
};

function formatCount(value: number, language: LanguageMode): string {
  return new Intl.NumberFormat(language === "es" ? "es-CO" : "en-US").format(value);
}

function operationManifest(result: CTIKnowledgeOperationResult): CTIKnowledgeManifest | null {
  if (result.manifest) return result.manifest;
  if (result.sources && result.schema_version && result.generated_at && result.status) {
    return result as CTIKnowledgeManifest;
  }
  return null;
}

function sourceAttention(source: CTIKnowledgeSource): boolean {
  return source.status === "missing" || source.status === "last_known_good";
}

export function KnowledgeCatalogAdminPanel({ language, canAdminister }: KnowledgeCatalogAdminPanelProps) {
  const labels = copy[language];
  const [manifest, setManifest] = useState<CTIKnowledgeManifest | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [adminKey, setAdminKey] = useState("");
  const [operation, setOperation] = useState<Operation>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadManifest = useCallback(async (announce = false) => {
    setOperation("refresh");
    setError(null);
    try {
      const next = await getCTIKnowledgeManifest();
      setManifest(next);
      setSelected((current) => current.filter((sourceId) => next.sources.some((source) => source.source_id === sourceId && source.download)));
      if (announce) setMessage(labels.refreshed);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setOperation(null);
    }
  }, [labels.refreshed]);

  useEffect(() => {
    void loadManifest(false);
  }, [loadManifest]);

  const downloadable = useMemo(() => manifest?.sources.filter((source) => source.download) ?? [], [manifest]);
  const recordCount = useMemo(
    () => manifest?.sources.reduce((total, source) => total + (source.record_count || 0), 0) ?? 0,
    [manifest]
  );

  function toggleSource(sourceId: string) {
    setSelected((current) => current.includes(sourceId)
      ? current.filter((candidate) => candidate !== sourceId)
      : [...current, sourceId]);
    setMessage(null);
    setError(null);
  }

  function validateOperation(): boolean {
    if (!selected.length) {
      setError(labels.selectRequired);
      return false;
    }
    if (!adminKey.trim()) {
      setError(labels.keyRequired);
      return false;
    }
    return true;
  }

  async function runOperation(kind: Exclude<Operation, "refresh" | null>) {
    if (!validateOperation()) return;
    setOperation(kind);
    setError(null);
    setMessage(null);
    try {
      const result = kind === "sync"
        ? await syncCTIKnowledge(selected, adminKey)
        : await rollbackCTIKnowledge(selected, adminKey);
      const next = operationManifest(result) ?? await getCTIKnowledgeManifest();
      setManifest(next);
      setMessage(kind === "sync" ? labels.synced : labels.rolledBack);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setOperation(null);
    }
  }

  return (
    <article className="panel chart-card knowledge-admin-panel">
      <div className="panel-title-row compact knowledge-admin-header">
        <div>
          <span className="panel-eyebrow">{labels.eyebrow}</span>
          <h2>{labels.title}</h2>
          <p>{labels.description}</p>
        </div>
        <Database size={20} />
      </div>

      <div className="knowledge-admin-summary" aria-live="polite">
        <div className={manifest?.status === "ready" ? "ok" : "warn"}>
          {manifest?.status === "ready" ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span>{manifest?.status === "ready" ? labels.ready : labels.degraded}</span>
        </div>
        <strong>{manifest ? `${manifest.mandatory_usable_count}/${manifest.mandatory_count}` : "-"}</strong>
        <span>{labels.mandatory}</span>
        <strong>{formatCount(recordCount, language)}</strong>
        <span>{labels.records}</span>
        <strong>{manifest?.sources.length ?? "-"}</strong>
        <span>{labels.sources}</span>
      </div>

      <div className="knowledge-admin-toolbar">
        <button type="button" className="secondary-button compact" onClick={() => void loadManifest(true)} disabled={operation !== null}>
          <RefreshCw size={15} className={operation === "refresh" ? "spin" : ""} />
          <span>{labels.refresh}</span>
        </button>
        <button type="button" className="secondary-button compact" onClick={() => setSelected(downloadable.map((source) => source.source_id))} disabled={!downloadable.length || operation !== null}>
          <ShieldCheck size={15} />
          <span>{labels.selectAll}</span>
        </button>
        <button type="button" className="secondary-button compact" onClick={() => setSelected([])} disabled={!selected.length || operation !== null}>
          <span>{labels.clear}</span>
        </button>
      </div>

      <div className="knowledge-source-list" role="list">
        {(manifest?.sources ?? []).map((source) => (
          <div className={`knowledge-source-row ${sourceAttention(source) ? "attention" : ""}`.trim()} key={source.source_id} role="listitem">
            <input
              type="checkbox"
              checked={selected.includes(source.source_id)}
              onChange={() => toggleSource(source.source_id)}
              disabled={!source.download || !canAdminister || operation !== null}
              aria-label={`${source.name}: ${labels.status[source.status]}`}
            />
            <span className={`knowledge-source-status ${source.status}`} aria-hidden="true" />
            <span className="knowledge-source-identity">
              <strong>{source.name}</strong>
              <small>{source.family}{source.version ? ` | ${source.version}` : ""}</small>
            </span>
            <span className="knowledge-source-count">{formatCount(source.record_count, language)}</span>
            <em className={`knowledge-source-badge ${source.status}`}>{labels.status[source.status]}</em>
            {source.url ? (
              <a href={source.url} target="_blank" rel="noreferrer" title={source.url} aria-label={`${source.name}: ${source.url}`}>
                <ExternalLink size={15} />
              </a>
            ) : <span className="knowledge-source-link-placeholder" />}
          </div>
        ))}
      </div>

      <div className="knowledge-admin-actions">
        <label className="field-control knowledge-admin-key">
          <span><KeyRound size={14} /> {labels.adminKey}</span>
          <input
            value={adminKey}
            onChange={(event) => setAdminKey(event.target.value)}
            type="password"
            autoComplete="off"
            disabled={!canAdminister || operation !== null}
          />
          <small>{canAdminister ? labels.keyHelp : labels.permission}</small>
        </label>
        <button type="button" className="primary-button" onClick={() => void runOperation("sync")} disabled={!canAdminister || operation !== null}>
          {operation === "sync" ? <LoaderCircle size={17} className="spin" /> : <Download size={17} />}
          <span>{labels.sync}</span>
        </button>
        <button type="button" className="secondary-button" onClick={() => void runOperation("rollback")} disabled={!canAdminister || operation !== null}>
          {operation === "rollback" ? <LoaderCircle size={17} className="spin" /> : <RotateCcw size={17} />}
          <span>{labels.rollback}</span>
        </button>
      </div>

      {message ? <div className="settings-operation-message ok" role="status"><CheckCircle2 size={16} /><span>{message}</span></div> : null}
      {error ? <div className="settings-operation-message error" role="alert"><AlertTriangle size={16} /><span>{error}</span></div> : null}
    </article>
  );
}
