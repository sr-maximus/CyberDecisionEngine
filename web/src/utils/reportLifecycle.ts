import type { RunRecord } from "../types";

export function hasReadyReport(run: RunRecord | undefined): boolean {
  return Boolean(
    run?.report
      && run.report_status === "ready"
      && run.report.final
      && run.report.validation_status !== "rejected"
  );
}
