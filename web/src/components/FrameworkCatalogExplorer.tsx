import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { AlertTriangle, Boxes, ExternalLink, Layers3, Loader2, Search, ShieldCheck } from "lucide-react";
import { getCTIFrameworkCatalog, getCTIFrameworkFamily } from "../api";
import type {
  CTIFrameworkCatalog,
  CTIFrameworkEntity,
  CTIFrameworkFamily,
  CTIFrameworkTechnique,
  LanguageMode
} from "../types";

interface RunTechnique {
  technique_id: string;
  name: string;
  state: string;
  evidence_ids?: string[];
  evidence_urls?: string[];
  d3fend?: Array<{ id: string; name?: string }>;
}

interface RunEntity {
  name: string;
  state: string;
}

interface RunCTIContext {
  techniques: RunTechnique[];
  actors: RunEntity[];
  campaigns: RunEntity[];
}

const entityPalette = ["#0f8f83", "#246fa8", "#c06c0b", "#7b61a8", "#2f855a", "#b64f62", "#397f93", "#8b6d1d"];

function entityColor(value: string): string {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0;
  return entityPalette[Math.abs(hash) % entityPalette.length];
}

function techniqueId(row: CTIFrameworkTechnique): string {
  return String(row.technique_id || row.id || "N/D");
}

function entityTypeLabel(value: string, language: LanguageMode): string {
  const labels: Record<string, [string, string]> = {
    threat_group: ["Grupo", "Group"],
    threat_actor: ["Actor", "Actor"],
    campaign: ["Campaña", "Campaign"],
    malware: ["Malware", "Malware"],
    tool: ["Herramienta", "Tool"]
  };
  return labels[value]?.[language === "es" ? 0 : 1] ?? value.replace(/_/g, " ");
}

export function FrameworkCatalogExplorer({ cti, language }: { cti: RunCTIContext; language: LanguageMode }) {
  const [catalog, setCatalog] = useState<CTIFrameworkCatalog | null>(null);
  const [familyId, setFamilyId] = useState("attack-enterprise");
  const [family, setFamily] = useState<CTIFrameworkFamily | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    getCTIFrameworkCatalog()
      .then((payload) => { if (active) setCatalog(payload); })
      .catch((exc) => { if (active) setError(exc instanceof Error ? exc.message : String(exc)); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getCTIFrameworkFamily(familyId)
      .then((payload) => { if (active) setFamily(payload); })
      .catch((exc) => { if (active) setError(exc instanceof Error ? exc.message : String(exc)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [familyId]);

  return (
    <div className="framework-explorer">
      <div className="framework-family-tabs" role="tablist" aria-label={language === "es" ? "Familias de conocimiento" : "Knowledge families"}>
        {(catalog?.families ?? []).map((row) => (
          <button
            type="button"
            role="tab"
            aria-selected={row.id === familyId}
            className={row.id === familyId ? "selected" : ""}
            key={row.id}
            onClick={() => setFamilyId(row.id)}
          >
            <span>{row.short_name}</span>
            <small>{row.counts.items || row.counts.techniques || row.counts.relationships}</small>
          </button>
        ))}
      </div>

      {loading ? <div className="framework-loading"><Loader2 className="spin" size={20} />{language === "es" ? "Cargando catálogo verificado..." : "Loading verified catalog..."}</div> : null}
      {error ? <div className="framework-error"><AlertTriangle size={18} />{error}</div> : null}
      {!loading && family ? (
        <>
          <header className="framework-family-header">
            <div>
              <h3>{family.name}</h3>
              <p>{family.description}</p>
            </div>
            <div className="framework-family-stats">
              <span><strong>{family.counts.tactics}</strong>{language === "es" ? "tácticas" : "tactics"}</span>
              <span><strong>{family.counts.items}</strong>{language === "es" ? "elementos" : "items"}</span>
              <span><strong>{family.counts.entities}</strong>{language === "es" ? "entidades" : "entities"}</span>
              <a href={family.source_url} target="_blank" rel="noreferrer" title={language === "es" ? "Abrir fuente oficial" : "Open official source"}><ExternalLink size={15} /></a>
            </div>
          </header>
          {family.status !== "active" ? <MissingFamily family={family} language={language} /> : null}
          {family.status === "active" && (family.view_type === "matrix" || family.view_type === "defensive_matrix") ? <MatrixFamilyView family={family} cti={cti} language={language} /> : null}
          {family.status === "active" && family.view_type === "relationship_model" ? <RelationshipFamilyView family={family} language={language} /> : null}
          {family.status === "active" && family.view_type === "hierarchy" ? <HierarchyFamilyView family={family} language={language} /> : null}
          {family.status === "active" && family.view_type === "maturity" ? <MaturityFamilyView family={family} language={language} /> : null}
        </>
      ) : null}
    </div>
  );
}

function MissingFamily({ family, language }: { family: CTIFrameworkFamily; language: LanguageMode }) {
  return <div className="framework-error"><AlertTriangle size={18} /><span>{language === "es" ? "El catálogo local no está disponible. Sincronízalo desde Configuración antes de usarlo." : "The local catalog is unavailable. Synchronize it from Settings before use."} {family.error}</span></div>;
}

function MatrixFamilyView({ family, cti, language }: { family: CTIFrameworkFamily; cti: RunCTIContext; language: LanguageMode }) {
  const [query, setQuery] = useState("");
  const [entityQuery, setEntityQuery] = useState("");
  const [selectedEntityIds, setSelectedEntityIds] = useState<string[]>([]);
  const [selectedTechniqueId, setSelectedTechniqueId] = useState("");
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>([]);
  const [relatedOnly, setRelatedOnly] = useState(false);
  const runById = useMemo(() => new Map(cti.techniques.map((row) => [row.technique_id.toUpperCase(), row])), [cti.techniques]);
  const runEntityNames = useMemo(() => new Set([...cti.actors, ...cti.campaigns].map((row) => row.name.toLocaleLowerCase())), [cti.actors, cti.campaigns]);
  const entities = useMemo(() => [...family.entities].sort((left, right) => {
    const leftRun = runEntityNames.has(left.name.toLocaleLowerCase()) ? 1 : 0;
    const rightRun = runEntityNames.has(right.name.toLocaleLowerCase()) ? 1 : 0;
    return rightRun - leftRun || left.name.localeCompare(right.name);
  }), [family.entities, runEntityNames]);
  const visibleEntities = entities.filter((row) => {
    const needle = entityQuery.trim().toLocaleLowerCase();
    return !needle || `${row.name} ${row.entity_id} ${row.entity_type} ${(row.aliases ?? []).join(" ")}`.toLocaleLowerCase().includes(needle);
  });
  const selectedIds = useMemo(() => new Set(selectedEntityIds), [selectedEntityIds]);
  const selectedTechniqueIds = useMemo(() => new Set(
    entities.filter((row) => selectedIds.has(row.entity_id)).flatMap((row) => row.technique_ids)
  ), [entities, selectedIds]);
  const platforms = useMemo(
    () => [...new Set(family.techniques.flatMap((row) => row.platforms ?? []))].sort((left, right) => left.localeCompare(right)),
    [family.techniques]
  );
  const platformFilter = useMemo(() => new Set(selectedPlatforms), [selectedPlatforms]);
  const needle = query.trim().toLocaleLowerCase();
  const techniqueVisible = (row: CTIFrameworkTechnique) => {
    const id = techniqueId(row);
    if (selectedIds.size && !selectedTechniqueIds.has(id)) return false;
    if (platformFilter.size && !(row.platforms ?? []).some((platform) => platformFilter.has(platform))) return false;
    if (relatedOnly && !runById.has(id.toUpperCase()) && !selectedTechniqueIds.has(id)) return false;
    return !needle || `${id} ${row.name} ${row.description || ""}`.toLocaleLowerCase().includes(needle);
  };
  const tacticRows = family.tactics.map((tactic) => ({ ...tactic, techniques: tactic.techniques.filter(techniqueVisible) }));
  const visibleTactics = relatedOnly ? tacticRows.filter((row) => row.techniques.length) : tacticRows;
  const selectedTechnique = family.techniques.find((row) => techniqueId(row) === selectedTechniqueId);
  const visibleTechniqueCount = new Set(visibleTactics.flatMap((row) => row.techniques.map(techniqueId))).size;

  useEffect(() => {
    setSelectedEntityIds([]);
    setSelectedTechniqueId("");
    setSelectedPlatforms([]);
    setQuery("");
    setEntityQuery("");
    setRelatedOnly(false);
  }, [family.id]);

  function toggleEntity(entityId: string) {
    setSelectedEntityIds((current) => current.includes(entityId) ? current.filter((item) => item !== entityId) : [...current, entityId]);
  }

  function togglePlatform(platform: string) {
    setSelectedPlatforms((current) => current.includes(platform) ? current.filter((item) => item !== platform) : [...current, platform]);
  }

  return (
    <>
      <section className="framework-matrix-controls">
        <div className="framework-control-copy">
          <strong>{language === "es" ? "Exploración bidireccional" : "Bidirectional exploration"}</strong>
          <span>{language === "es" ? "Selecciona una entidad para ver todo su repertorio documentado; abre una técnica para ver todas las entidades relacionadas." : "Select an entity to see its complete documented repertoire; open a technique to see every related entity."}</span>
        </div>
        <label className="framework-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={language === "es" ? "Buscar técnica o descripción" : "Search technique or description"} /></label>
        <div className="framework-view-toggle">
          <button type="button" className={!relatedOnly ? "selected" : ""} onClick={() => setRelatedOnly(false)}>{language === "es" ? "Matriz completa" : "Full matrix"}</button>
          <button type="button" className={relatedOnly ? "selected" : ""} onClick={() => setRelatedOnly(true)}>{language === "es" ? "Solo relacionadas" : "Related only"}</button>
        </div>
        <div className="framework-result-count"><strong>{visibleTechniqueCount}</strong> {language === "es" ? "técnicas visibles" : "visible techniques"}</div>
      </section>

      {platforms.length ? (
        <section className="framework-platform-filter" aria-label={language === "es" ? "Filtrar por plataforma" : "Filter by platform"}>
          <div>
            <strong>{language === "es" ? "Plataformas" : "Platforms"}</strong>
            <span>{language === "es" ? "Cobertura oficial del dominio seleccionado; admite selección múltiple." : "Official coverage for the selected domain; multiple selection is supported."}</span>
          </div>
          <div className="framework-platform-options">
            <button type="button" className={!selectedPlatforms.length ? "selected" : ""} aria-pressed={!selectedPlatforms.length} onClick={() => setSelectedPlatforms([])}>{language === "es" ? "Todas" : "All"}</button>
            {platforms.map((platform) => (
              <button type="button" key={platform} className={platformFilter.has(platform) ? "selected" : ""} aria-pressed={platformFilter.has(platform)} onClick={() => togglePlatform(platform)}>{platform}</button>
            ))}
          </div>
        </section>
      ) : null}

      {entities.length ? (
        <section className="framework-entity-filter">
          <div className="framework-entity-filter-heading">
            <label className="framework-search"><Search size={14} /><input value={entityQuery} onChange={(event) => setEntityQuery(event.target.value)} placeholder={language === "es" ? "Buscar actor, grupo, campaña, malware o herramienta" : "Search actor, group, campaign, malware or tool"} /></label>
            <button type="button" className={!selectedEntityIds.length ? "selected" : ""} onClick={() => setSelectedEntityIds([])}>{language === "es" ? "Todas las entidades" : "All entities"}</button>
          </div>
          <div className="framework-entity-options">
            {visibleEntities.map((entity) => {
              const color = entityColor(entity.entity_id);
              const isRun = runEntityNames.has(entity.name.toLocaleLowerCase());
              return (
                <button type="button" key={entity.entity_id} aria-pressed={selectedIds.has(entity.entity_id)} className={selectedIds.has(entity.entity_id) ? "selected" : ""} style={{ "--entity-color": color } as CSSProperties} onClick={() => toggleEntity(entity.entity_id)}>
                  <i /><span><strong>{entity.name}</strong><small>{entityTypeLabel(entity.entity_type, language)} · {entity.technique_ids.length} TTP{isRun ? ` · ${language === "es" ? "en corrida" : "in run"}` : ""}</small></span>
                </button>
              );
            })}
          </div>
        </section>
      ) : null}

      {selectedTechnique ? <TechniqueInspection row={selectedTechnique} run={runById.get(techniqueId(selectedTechnique).toUpperCase())} language={language} onClose={() => setSelectedTechniqueId("")} /> : null}

      <div className="framework-matrix-viewport" tabIndex={0} aria-label={family.name}>
        <div className="framework-matrix-board" style={{ "--framework-columns": Math.max(1, visibleTactics.length) } as CSSProperties}>
          {visibleTactics.map((tactic) => (
            <article className="framework-tactic-column" key={tactic.id}>
              <header><strong>{tactic.name}</strong><span>{tactic.techniques.length} {family.view_type === "defensive_matrix" ? (language === "es" ? "defensas" : "defenses") : "TTP"}</span></header>
              <div>
                {!tactic.techniques.length ? <span className="framework-empty-cell">{language === "es" ? "Sin relación para el filtro" : "No relation for this filter"}</span> : null}
                {tactic.techniques.map((row) => {
                  const id = techniqueId(row);
                  const run = runById.get(id.toUpperCase());
                  const owners = row.entities ?? [];
                  return (
                    <button type="button" className={`framework-technique${run ? " run-supported" : ""}${selectedTechniqueId === id ? " selected" : ""}`} key={`${tactic.id}-${id}`} onClick={() => setSelectedTechniqueId(id)}>
                      <span><strong>{id}</strong><small>{row.name}</small></span>
                      <span className="framework-technique-owners">
                        {owners.slice(0, 6).map((owner) => <i key={owner.entity_id} title={`${owner.name} · ${entityTypeLabel(owner.entity_type, language)}`} style={{ background: entityColor(owner.entity_id) }} />)}
                        {owners.length > 6 ? <b>+{owners.length - 6}</b> : null}
                      </span>
                      <em>{run ? (language === "es" ? "Corrida" : "Run") : (language === "es" ? "Referencia" : "Reference")}</em>
                    </button>
                  );
                })}
              </div>
            </article>
          ))}
        </div>
      </div>
    </>
  );
}

function TechniqueInspection({ row, run, language, onClose }: { row: CTIFrameworkTechnique; run?: RunTechnique; language: LanguageMode; onClose: () => void }) {
  const id = techniqueId(row);
  return (
    <aside className="framework-technique-inspection">
      <div>
        <span className="eyebrow">{run ? (language === "es" ? "Sustentada por la corrida" : "Supported by run") : (language === "es" ? "Conocimiento de referencia" : "Reference knowledge")}</span>
        <h4>{id} · {row.name}</h4>
        <p>{row.description || (language === "es" ? "Sin descripción local." : "No local description.")}</p>
      </div>
      <dl>
        <div><dt>{language === "es" ? "Entidades relacionadas" : "Related entities"}</dt><dd>{row.entities?.length ?? 0}</dd></div>
        <div><dt>{language === "es" ? "Evidencias de corrida" : "Run evidence"}</dt><dd>{Math.max(run?.evidence_ids?.length ?? 0, run?.evidence_urls?.length ?? 0)}</dd></div>
        <div><dt>D3FEND</dt><dd>{run?.d3fend?.length ?? row.related_attack_techniques?.length ?? 0}</dd></div>
      </dl>
      <div className="framework-inspection-entities">
        {(row.entities ?? []).map((entity) => <span key={entity.entity_id} style={{ "--entity-color": entityColor(entity.entity_id) } as CSSProperties}><i />{entity.name}<small>{entityTypeLabel(entity.entity_type, language)}</small></span>)}
      </div>
      <div className="framework-inspection-actions">
        {row.url ? <a href={row.url} target="_blank" rel="noreferrer"><ExternalLink size={14} />{language === "es" ? "Fuente oficial" : "Official source"}</a> : null}
        <button type="button" onClick={onClose}>{language === "es" ? "Cerrar detalle" : "Close detail"}</button>
      </div>
    </aside>
  );
}

interface RelationshipItem { id: string; name: string; description?: string; category?: string; cwes?: string[]; cves?: string[] }

function RelationshipFamilyView({ family, language }: { family: CTIFrameworkFamily; language: LanguageMode }) {
  const collections = family.collections as { properties?: RelationshipItem[]; threats?: RelationshipItem[]; mitigations?: RelationshipItem[] };
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const all = [...(collections.properties ?? []), ...(collections.threats ?? []), ...(collections.mitigations ?? [])];
  const byId = new Map(all.map((row) => [row.id, row]));
  const needle = query.trim().toLocaleLowerCase();
  const selected = byId.get(selectedId);
  const links = family.relationships.filter((row) => row.source === selectedId || row.target === selectedId);
  const columns: Array<[string, RelationshipItem[], string]> = [
    [language === "es" ? "Propiedades del dispositivo" : "Device properties", collections.properties ?? [], "property"],
    [language === "es" ? "Amenazas" : "Threats", collections.threats ?? [], "threat"],
    [language === "es" ? "Mitigaciones" : "Mitigations", collections.mitigations ?? [], "mitigation"]
  ];
  return (
    <>
      <label className="framework-search framework-wide-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={language === "es" ? "Buscar propiedad, amenaza, CWE, CVE o mitigación" : "Search property, threat, CWE, CVE or mitigation"} /></label>
      {selected ? <aside className="framework-relationship-detail"><div><span className="eyebrow">{selected.id} · {selected.category}</span><h4>{selected.name}</h4><p>{selected.description}</p></div><div className="framework-related-links">{links.map((link, index) => { const other = byId.get(link.source === selectedId ? link.target : link.source); return other ? <button type="button" onClick={() => setSelectedId(other.id)} key={`${link.source}-${link.target}-${index}`}><strong>{other.id}</strong><span>{other.name}</span><small>{link.type}</small></button> : null; })}</div></aside> : null}
      <div className="framework-relationship-grid">
        {columns.map(([title, rows, kind]) => (
          <section key={kind}><header><Layers3 size={16} /><div><strong>{title}</strong><span>{rows.length}</span></div></header><div>{rows.filter((row) => !needle || `${row.id} ${row.name} ${row.category || ""} ${(row.cwes ?? []).join(" ")} ${(row.cves ?? []).join(" ")}`.toLocaleLowerCase().includes(needle)).map((row) => <button type="button" className={row.id === selectedId ? "selected" : ""} onClick={() => setSelectedId(row.id)} key={row.id}><strong>{row.id}</strong><span>{row.name}</span><small>{row.category}</small></button>)}</div></section>
        ))}
      </div>
    </>
  );
}

function HierarchyFamilyView({ family, language }: { family: CTIFrameworkFamily; language: LanguageMode }) {
  const [query, setQuery] = useState("");
  const needle = query.trim().toLocaleLowerCase();
  const rows = family.techniques.filter((row) => !needle || `${techniqueId(row)} ${row.name} ${row.abstraction || ""} ${(row.related ?? []).map((item) => item.id).join(" ")}`.toLocaleLowerCase().includes(needle));
  const groups = new Map<string, CTIFrameworkTechnique[]>();
  rows.forEach((row) => groups.set(row.abstraction || "Unclassified", [...(groups.get(row.abstraction || "Unclassified") ?? []), row]));
  return (
    <>
      <label className="framework-search framework-wide-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={language === "es" ? "Buscar ID, nombre o relación" : "Search ID, name or relationship"} /></label>
      <div className="framework-hierarchy">
        {[...groups.entries()].map(([group, items]) => <section key={group}><header><Boxes size={16} /><strong>{group}</strong><span>{items.length}</span></header><div>{items.map((row) => <details key={techniqueId(row)}><summary><span><strong>{techniqueId(row)}</strong><small>{row.name}</small></span><em>{row.status}</em></summary><div><p>{language === "es" ? "Relaciones" : "Relationships"}: {(row.related ?? []).length}</p><div className="framework-related-chips">{(row.related ?? []).map((related) => <span key={`${related.id}-${related.relation}`}>{related.id} · {related.relation}</span>)}</div>{row.url ? <a href={row.url} target="_blank" rel="noreferrer"><ExternalLink size={13} />{language === "es" ? "Definición oficial" : "Official definition"}</a> : null}</div></details>)}</div></section>)}
      </div>
    </>
  );
}

interface InformLevel { uid?: string; question?: string; level?: string; level_id?: number; impact?: number; complexity?: number; points?: number }
interface InformComponent { id: string; name: string; weight?: number; levels: InformLevel[] }
interface InformDimension { id: string; name: string; weight?: number; components: InformComponent[] }

function MaturityFamilyView({ family, language }: { family: CTIFrameworkFamily; language: LanguageMode }) {
  const dimensions = ((family.collections as { dimensions?: InformDimension[] }).dimensions ?? []);
  return (
    <div className="framework-maturity-grid">
      {dimensions.map((dimension) => <section key={dimension.id}><header><ShieldCheck size={18} /><div><strong>{dimension.name}</strong><span>{language === "es" ? "Peso" : "Weight"}: {dimension.weight ?? "N/D"}</span></div></header><div>{dimension.components.map((component) => <details key={component.id}><summary><span><strong>{component.name}</strong><small>{component.levels.length} {language === "es" ? "niveles evaluables" : "assessable levels"}</small></span><em>{component.weight ?? "N/D"}</em></summary><div>{component.levels.map((level) => <article key={`${level.uid}-${level.level_id}`}><strong>{level.uid} · {level.level}</strong><p>{level.question}</p><small>{language === "es" ? "Impacto" : "Impact"} {level.impact ?? "N/D"} · {language === "es" ? "Complejidad" : "Complexity"} {level.complexity ?? "N/D"}</small></article>)}</div></details>)}</div></section>)}
    </div>
  );
}
