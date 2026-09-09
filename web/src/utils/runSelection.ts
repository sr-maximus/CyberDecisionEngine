import type { RunRecord } from "../types";

function normalizedSubject(run: RunRecord): string {
  const explicitSubject = run.request.organization_name?.trim()
    || run.request.person_name?.trim()
    || run.request.legal_name?.trim();
  if (explicitSubject) return explicitSubject.toLocaleLowerCase();
  return [...run.domains]
    .map((domain) => domain.trim().toLocaleLowerCase())
    .filter(Boolean)
    .sort()
    .join("|");
}

function hasDecisionData(run: RunRecord): boolean {
  const kpis = run.summary.kpis;
  return Boolean(
    run.report
      || (kpis.unique_records ?? kpis.new_events) > 0
      || (kpis.validated_evidence ?? 0) > 0
      || run.summary.findings.length > 0
  );
}

export function runCompletenessScore(run: RunRecord): number {
  const kpis = run.summary.kpis;
  const uniqueRecords = Math.max(0, kpis.unique_records ?? kpis.new_events ?? 0);
  const validatedEvidence = Math.max(0, kpis.validated_evidence ?? 0);
  const findings = Math.max(0, kpis.validated_findings ?? run.summary.findings.length);
  const productiveSources = Math.max(0, kpis.productive_sources ?? kpis.healthy_sources ?? 0);
  const lookbackDays = Math.max(0, run.request.lookback_days || run.request.lookback_hours / 24 || 0);

  return (
    run.domains.length * 120
    + Math.log1p(uniqueRecords) * 100
    + validatedEvidence * 60
    + findings * 80
    + productiveSources * 20
    + Math.min(365, lookbackDays) * 2
    + (run.request.mode === "deep" ? 400 : 0)
    + (run.request.allow_tor ? 100 : 0)
    + (run.report?.final ? 40 : 0)
  );
}

export function preferredCompletedRun(runs: RunRecord[]): RunRecord | undefined {
  const completed = runs.filter((run) => run.status === "completed" && hasDecisionData(run));
  if (!completed.length) return undefined;

  const latestSubject = normalizedSubject(completed[0]);
  return completed
    .filter((run) => normalizedSubject(run) === latestSubject)
    .sort((left, right) => {
      const scoreDifference = runCompletenessScore(right) - runCompletenessScore(left);
      if (scoreDifference !== 0) return scoreDifference;
      return Date.parse(right.updated_at) - Date.parse(left.updated_at);
    })[0];
}

export function preferredRunForDisplay(runs: RunRecord[]): RunRecord | undefined {
  return runs.find((run) => run.status === "running" || run.status === "queued")
    ?? preferredCompletedRun(runs)
    ?? runs[0];
}

export function preferredRunIdsBySubject(runs: RunRecord[]): Set<string> {
  const bestBySubject = new Map<string, RunRecord>();
  for (const run of runs) {
    if (run.status !== "completed" || !hasDecisionData(run)) continue;
    const subject = normalizedSubject(run);
    const current = bestBySubject.get(subject);
    if (!current || runCompletenessScore(run) > runCompletenessScore(current)) {
      bestBySubject.set(subject, run);
    }
  }
  return new Set([...bestBySubject.values()].map((run) => run.id));
}
