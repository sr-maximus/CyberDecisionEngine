import { AlertTriangle, BadgeCheck, Globe2, KeyRound, Loader2, RadioTower, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { getAttackSurface } from "../api";
import type { AttackSurfaceDomain, AttackSurfaceResponse, LanguageMode, RunRecord } from "../types";
import { formatDateTime } from "../utils/format";
import { cleanEvidenceText, cleanEvidenceTitle } from "../utils/sourceLabels";

interface AttackSurfaceViewProps {
  run?: RunRecord;
  competitorDomains: string[];
  language: LanguageMode;
}

const labels = {
  es: {
    title: "Superficie de Ataque",
    subtitle: "WHOIS/RDAP, DNS y certificado TLS desde consultas pasivas y seguras.",
    ownRisk: "Riesgo propio",
    competitorRisk: "Riesgo competencia",
    certErrors: "Certificados con alerta",
    rdapErrors: "RDAP/WHOIS con alerta",
    toolFindings: "Alertas externas",
    refresh: "Escanear superficie",
    empty: "Ejecuta o selecciona un analisis con dominios para consultar superficie de ataque.",
    loading: "Consultando DNS, TLS y RDAP...",
    queryError: "No se pudo consultar la superficie de ataque",
    own: "Propio",
    competitor: "Competencia",
    comparison: "Comparativo propio vs competencia",
    details: "Inventario técnico por dominio",
    domains: "Dominios",
    avgRisk: "Riesgo promedio",
    delta: "Diferencia",
    noCompetitors: "Sin dominios de competencia declarados.",
    better: "Propio por debajo de competencia",
    worse: "Propio por encima de competencia",
    aligned: "Propio y competencia alineados",
    inspected: "dominios revisados con evidencia pasiva y ASM.",
    registrar: "Registrador",
    certificate: "Certificado",
    dns: "DNS",
    nameservers: "Name servers",
    subdomains: "Subdominios",
    webAssets: "Servicios web",
    toolStatus: "Validación",
    findings: "Hallazgos",
    expires: "Vence",
    noData: "Sin dato",
    validated: "validado",
    issue: "alerta"
  },
  en: {
    title: "Attack Surface",
    subtitle: "Passive and safe WHOIS/RDAP, DNS and TLS certificate checks.",
    ownRisk: "Owned risk",
    competitorRisk: "Competitor risk",
    certErrors: "Certificate alerts",
    rdapErrors: "RDAP/WHOIS alerts",
    toolFindings: "External alerts",
    refresh: "Scan surface",
    empty: "Run or select an analysis with domains to query attack surface.",
    loading: "Querying DNS, TLS and RDAP...",
    queryError: "Unable to query attack surface",
    own: "Owned",
    competitor: "Competitor",
    comparison: "Owned vs competitor benchmark",
    details: "Technical inventory by domain",
    domains: "Domains",
    avgRisk: "Average risk",
    delta: "Delta",
    noCompetitors: "No competitor domains declared.",
    better: "Owned score below competitor",
    worse: "Owned score above competitor",
    aligned: "Owned and competitor are aligned",
    inspected: "domains inspected with passive and ASM evidence.",
    registrar: "Registrar",
    certificate: "Certificate",
    dns: "DNS",
    nameservers: "Name servers",
    subdomains: "Subdomains",
    webAssets: "Web services",
    toolStatus: "Validation",
    findings: "Findings",
    expires: "Expires",
    noData: "No data",
    validated: "validated",
    issue: "alert"
  }
};

type AttackSurfaceCopy = (typeof labels)[keyof typeof labels];

export function AttackSurfaceView({ run, competitorDomains, language }: AttackSurfaceViewProps) {
  const copy = labels[language];
  const domains = useMemo(() => run?.domains ?? [], [run]);
  const competitors = useMemo(() => run?.request.competitor_domains ?? competitorDomains, [competitorDomains, run]);
  const [surface, setSurface] = useState<AttackSurfaceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const surfaceCacheKey = useMemo(() => {
    if (!domains.length) return "";
    return `cyberdecision.attackSurface.v1.${run?.id ?? "draft"}.${domains.join("|")}.${competitors.join("|")}`;
  }, [competitors, domains, run?.id]);

  async function refresh(force = false) {
    if (!domains.length) return;
    if (!force && surfaceCacheKey) {
      const cached = readSurfaceCache(surfaceCacheKey);
      if (cached) {
        setSurface(cached);
        setError(null);
        return;
      }
    }
    setLoading(true);
    setError(null);
    try {
      const nextSurface = await getAttackSurface(domains, competitors);
      setSurface(nextSurface);
      if (surfaceCacheKey) window.localStorage.setItem(surfaceCacheKey, JSON.stringify(nextSurface));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : copy.queryError);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!surfaceCacheKey) return;
    const cached = readSurfaceCache(surfaceCacheKey);
    if (cached) {
      setSurface(cached);
      setError(null);
      return;
    }
    refresh(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [surfaceCacheKey]);

  if (!domains.length) {
    return (
      <section className="panel chart-card empty-panel">
        <Globe2 size={24} />
        <h2>{copy.title}</h2>
        <p>{copy.empty}</p>
      </section>
    );
  }

  const rows = surface?.domains ?? [];
  const ownRiskMetric = surface ? surface.summary.own_avg_risk.toFixed(1) : "--";
  const competitorRiskMetric = surface && surface.summary.competitor_count > 0 ? surface.summary.competitor_avg_risk.toFixed(1) : "--";
  const certErrorsMetric = surface ? String(surface.summary.cert_errors) : "--";
  const toolFindingsMetric = surface ? String(surface.summary.tool_findings ?? 0) : "--";

  return (
    <div className="view-stack">
      <section className="attack-surface-hero panel">
        <div>
          <span>CyberDecisionEngine</span>
          <h2>{copy.title}</h2>
          <p>{copy.subtitle}</p>
          <em>{surface ? formatDateTime(surface.generated_at) : copy.loading}</em>
        </div>
        <button className="primary-button" onClick={() => refresh(true)} disabled={loading}>
          {loading ? <Loader2 className="spin" size={17} /> : <RadioTower size={17} />}
          <span>{copy.refresh}</span>
        </button>
      </section>

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="dashboard-kpis">
        <Metric icon={<ShieldAlert size={18} />} label={copy.ownRisk} value={ownRiskMetric} />
        <Metric icon={<Globe2 size={18} />} label={copy.competitorRisk} value={competitorRiskMetric} />
        <Metric icon={<KeyRound size={18} />} label={copy.certErrors} value={certErrorsMetric} />
        <Metric icon={<AlertTriangle size={18} />} label={copy.toolFindings} value={toolFindingsMetric} />
      </section>

      <section className="dashboard-grid attack-surface-grid">
        <article className="panel chart-card span-4 benchmark-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.comparison}</h2>
              <p>{copy.subtitle}</p>
            </div>
          </div>
          <AttackSurfaceBenchmark summary={surface?.summary} loading={loading} language={language} />
        </article>

        <article className="panel chart-card span-8 scroll-card surface-details-card">
          <div className="panel-title-row compact">
            <div>
              <h2>{copy.details}</h2>
              <p>
                {rows.length} {copy.inspected}
              </p>
            </div>
          </div>
          <div className="surface-domain-grid">
            {rows.map((row) => (
              <DomainSurfaceCard key={`${row.scope}-${row.domain}`} row={row} language={language} />
            ))}
            {loading && !rows.length ? <div className="chart-empty">{copy.loading}</div> : null}
          </div>
        </article>
      </section>
    </div>
  );
}

function AttackSurfaceBenchmark({
  summary,
  loading,
  language
}: {
  summary?: AttackSurfaceResponse["summary"];
  loading: boolean;
  language: LanguageMode;
}) {
  const copy = labels[language];
  if (loading && !summary) {
    return <div className="chart-empty">{copy.loading}</div>;
  }
  if (!summary) {
    return <div className="chart-empty">{copy.noData}</div>;
  }

  const hasCompetitor = summary.competitor_count > 0;
  const delta = hasCompetitor ? summary.own_avg_risk - summary.competitor_avg_risk : 0;
  const deltaLabel = !hasCompetitor
    ? copy.noCompetitors
    : Math.abs(delta) < 0.1
      ? copy.aligned
      : delta < 0
        ? copy.better
        : copy.worse;

  return (
    <div className="surface-benchmark">
      <BenchmarkRow
        label={copy.ownRisk}
        count={summary.own_count}
        score={summary.own_avg_risk}
        tone={tone(summary.own_avg_risk)}
        copy={copy}
      />
      <BenchmarkRow
        label={copy.competitorRisk}
        count={summary.competitor_count}
        score={hasCompetitor ? summary.competitor_avg_risk : null}
        tone={tone(summary.competitor_avg_risk)}
        copy={copy}
        muted={!hasCompetitor}
      />
      <div className={`surface-benchmark-delta ${!hasCompetitor ? "muted" : delta > 0 ? "negative" : delta < 0 ? "positive" : ""}`}>
        <span>{copy.delta}</span>
        <strong>{hasCompetitor ? `${delta > 0 ? "+" : ""}${delta.toFixed(1)}` : "--"}</strong>
        <p>{deltaLabel}</p>
      </div>
    </div>
  );
}

function BenchmarkRow({
  label,
  count,
  score,
  tone,
  copy,
  muted = false
}: {
  label: string;
  count: number;
  score: number | null;
  tone: "low" | "medium" | "high" | "critical";
  copy: AttackSurfaceCopy;
  muted?: boolean;
}) {
  const value = score ?? 0;
  return (
    <div className={`surface-benchmark-row ${tone} ${muted ? "muted" : ""}`}>
      <div>
        <strong>{label}</strong>
        <span>
          {count} {copy.domains}
        </span>
      </div>
      <b>{score === null ? "--" : score.toFixed(1)}</b>
      <i aria-label={`${copy.avgRisk}: ${score === null ? copy.noData : score.toFixed(1)}`}>
        <em style={{ width: `${Math.max(4, Math.min(100, value))}%` }} />
      </i>
    </div>
  );
}

function DomainSurfaceCard({ row, language }: { row: AttackSurfaceDomain; language: LanguageMode }) {
  const copy = labels[language];
  const certOk = row.certificate.status === "ok";
  const rdapOk = row.rdap.status === "ok";
  const toolSurface = row.tool_surface;
  const subdomainCount = toolSurface?.subdomains?.length ?? 0;
  const webAssetCount = toolSurface?.web_assets?.length ?? 0;
  const actionableFindings = (toolSurface?.findings ?? []).filter((finding) => finding.severity !== "info");
  const findingCount = actionableFindings.length;
  const toolsOk = (toolSurface?.tool_runs ?? []).filter((tool) => ["ok", "empty", "disabled"].includes(tool.status)).length;
  const toolsTotal = toolSurface?.tool_runs?.length ?? 0;
  return (
    <article className={`surface-domain-card ${row.scope} ${tone(row.risk_score)}`}>
      <div className="surface-card-head">
        <div>
          <strong>{row.domain}</strong>
          <span>{row.scope === "own" ? copy.own : copy.competitor}</span>
        </div>
        <b>{row.risk_score}</b>
      </div>
      <div className="surface-facts">
        <Fact icon={certOk ? <BadgeCheck size={16} /> : <AlertTriangle size={16} />} label={copy.certificate}>
          {certOk ? `${row.certificate.issuer || copy.noData} | ${copy.expires}: ${row.certificate.days_remaining ?? copy.noData}d` : row.certificate.error ?? copy.issue}
        </Fact>
        <Fact icon={<Globe2 size={16} />} label={copy.dns}>
          {row.dns.addresses.slice(0, 3).join(", ") || row.dns.error || copy.noData}
        </Fact>
        <Fact icon={rdapOk ? <BadgeCheck size={16} /> : <AlertTriangle size={16} />} label={copy.registrar}>
          {row.rdap.registrar || row.rdap.handle || row.rdap.error || copy.noData}
        </Fact>
        <Fact icon={<RadioTower size={16} />} label={copy.nameservers}>
          {row.rdap.nameservers.slice(0, 3).join(", ") || copy.noData}
        </Fact>
        <Fact icon={<Globe2 size={16} />} label={copy.subdomains}>
          {subdomainCount ? toolSurface?.subdomains.slice(0, 4).join(", ") : cleanEvidenceText(toolSurface?.warning) || copy.noData}
        </Fact>
        <Fact icon={<RadioTower size={16} />} label={copy.webAssets}>
          {webAssetCount
            ? toolSurface?.web_assets
                .slice(0, 3)
                .map((asset) => asset.host || asset.url)
                .filter(Boolean)
                .join(", ")
            : copy.noData}
        </Fact>
        <Fact icon={findingCount ? <AlertTriangle size={16} /> : <BadgeCheck size={16} />} label={copy.findings}>
          {findingCount
            ? (
                <span className="surface-finding-list">
                  {actionableFindings.slice(0, 4).map((finding) => (
                    <span key={`${finding.asset}-${finding.title}`}>
                      <strong>{finding.severity}</strong>
                      {cleanEvidenceTitle(finding.title)}
                      {finding.asset || finding.url ? <code>{finding.url || finding.asset}</code> : null}
                    </span>
                  ))}
                </span>
              )
            : copy.validated}
        </Fact>
        <Fact icon={<BadgeCheck size={16} />} label={copy.toolStatus}>
          {toolsTotal ? `${toolsOk}/${toolsTotal} ${copy.validated}` : toolSurface?.status || copy.noData}
        </Fact>
      </div>
    </article>
  );
}

function readSurfaceCache(key: string): AttackSurfaceResponse | null {
  try {
    const cached = window.localStorage.getItem(key);
    return cached ? JSON.parse(cached) as AttackSurfaceResponse : null;
  } catch {
    return null;
  }
}

function Fact({ icon, label, children }: { icon: ReactNode; label: string; children: ReactNode }) {
  return (
    <div className="surface-fact">
      {icon}
      <span>{label}</span>
      <p>{children}</p>
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

function tone(value: number): "low" | "medium" | "high" | "critical" {
  if (value >= 70) return "critical";
  if (value >= 45) return "high";
  if (value >= 20) return "medium";
  return "low";
}
