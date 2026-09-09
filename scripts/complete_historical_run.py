"""Finite, resumable local deployment and historical-analysis workflow."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
API = "http://localhost:8000"


def api(path, payload=None):
    request = Request(API + path, data=None if payload is None else json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def write_json(path, payload):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def historical_request(source, start, end):
    request = dict(source["request"])
    if not request.get("authorized_scope"):
        raise ValueError("The source run does not declare an authorized scope")
    request.update(analysis_window="custom", analysis_start_date=start, analysis_end_date=end,
                   lookback_days=(date.fromisoformat(end) - date.fromisoformat(start)).days + 1,
                   scan_time_budget_minutes=0, report_display_at=None)
    return request


def matching_runs(runs, request, since):
    return [run for run in runs if run.get("created_at", "") >= since
            and run.get("request", {}).get("analysis_start_date") == request["analysis_start_date"]
            and run.get("request", {}).get("analysis_end_date") == request["analysis_end_date"]
            and run.get("request", {}).get("organization_name") == request.get("organization_name")
            and sorted(run.get("request", {}).get("domains", [])) == sorted(request.get("domains", []))]


def busy_runs(runs):
    return [run for run in runs if run.get("status") in {"running", "queued"}
            or run.get("report_status") in {"queued", "generating"}]


def wait_for(read, ready, seconds, label):
    deadline = time.monotonic() + seconds
    previous = None
    while time.monotonic() < deadline:
        try:
            value = read()
        except (OSError, ValueError) as exc:
            message = f"{label}: temporary response unavailable ({type(exc).__name__})"
        else:
            if ready(value):
                return value
            if isinstance(value, dict):
                message = f"{label}: {value.get('status', '')} {value.get('stage', '')}"
            else:
                message = f"{label}: waiting for {len(busy_runs(value))} active jobs"
        if message != previous:
            print(message, flush=True)
            previous = message
        time.sleep(30)
    raise TimeoutError(f"{label}: safety waiting period exhausted; no active run was cancelled")


def compose(*args):
    subprocess.run(["/usr/local/bin/docker", "compose", *args], cwd=ROOT, check=True, timeout=3600)


def complete(source_id, start, end):
    directory = ROOT / "data" / "recovery" / source_id / f"{start}_{end}"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "workflow.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = directory / "workflow.json"
        state = json.loads(state_path.read_text()) if state_path.exists() else {}

        def save(**changes):
            state.update(changes, updated_at=datetime.now(timezone.utc).isoformat())
            write_json(state_path, state)

        try:
            if state.get("phase") == "completed":
                print(json.dumps(state["result"], ensure_ascii=False), flush=True)
                return
            if "request" not in state:
                source = api(f"/api/runs/{source_id}")
                write_json(directory / "original-run.json", source)
                save(source_run_id=source_id, request=historical_request(source, start, end),
                     phase="prepared", started_at=datetime.now(timezone.utc).isoformat())
            if not state.get("images_built"):
                compose("build", "api", "web", "spiderfoot")
                save(images_built=True, phase="waiting_for_existing_work")
            if not state.get("deployed"):
                wait_for(lambda: api("/api/runs/status"), lambda rows: not busy_runs(rows),
                         48 * 3600, "Preserving existing collection and reports")
                write_json(directory / "original-run-final.json", api(f"/api/runs/{source_id}"))
                # Recheck immediately before touching services; never cancel a busy run.
                if busy_runs(api("/api/runs/status")):
                    raise RuntimeError("New work started before deployment; resume after it completes")
                compose("up", "-d", "--no-deps", "api", "web", "spiderfoot")
                wait_for(lambda: api("/api/health"), lambda value: bool(value), 300, "API health")
                schema = api("/openapi.json")["components"]["schemas"]["DomainAnalysisRequest"]["properties"]
                if not {"analysis_start_date", "analysis_end_date"} <= schema.keys():
                    raise RuntimeError("Deployed API does not support the requested calendar period")
                save(deployed=True, phase="deployed")
            if not state.get("run_id"):
                candidates = matching_runs(api("/api/runs/status"), state["request"], state["started_at"])
                if len(candidates) > 1:
                    raise RuntimeError("Multiple historical runs match; refusing to choose or create another")
                if candidates:
                    run = candidates[0]
                elif state.get("submission_started"):
                    raise RuntimeError("Previous submission is uncertain; refusing duplicate collection")
                else:
                    save(submission_started=True, phase="submitting")
                    run = api("/api/analysis", state["request"])
                save(run_id=run["id"], phase="collecting")
                print(f"Historical analysis started: {run['id']} ({start} to {end}, undated evidence included)", flush=True)
            run_id = state["run_id"]
            read_run = lambda: next(row for row in api("/api/runs/status") if row["id"] == run_id)
            run = wait_for(read_run, lambda value: value["status"] in {"completed", "failed"},
                           49 * 3600, "Historical analysis")
            if run["status"] != "completed":
                raise RuntimeError(f"Historical analysis failed: {run.get('error')}")
            actual = api(f"/api/runs/{run_id}")
            write_json(directory / "historical-result.json", actual)
            if (actual["request"].get("analysis_start_date"), actual["request"].get("analysis_end_date")) != (start, end):
                raise RuntimeError("The completed analysis has a different calendar period")
            context = json.loads((ROOT / "data" / "web_runs" / run_id / "context.json").read_text())
            period = context.get("metrics", {}).get("analysis_period", {})
            if (period.get("start_date"), period.get("end_date")) != (start, end):
                raise RuntimeError("Persisted evidence does not confirm the requested calendar period")
            if period.get("included_records") != len(context.get("raw_events", [])):
                raise RuntimeError("Historical evidence count does not reconcile")
            save(phase="reporting")
            api(f"/api/runs/{run_id}/report", {"language": state["request"].get("language", "es"), "review_mode": "manual"})
            run = wait_for(read_run, lambda value: value.get("report_status") in {"ready", "failed"},
                           3 * 3600, "Historical reports")
            if run.get("report_status") != "ready":
                raise RuntimeError(f"Report generation failed: {run.get('report_error')}")
            report = run.get("report") or {}
            if report.get("validation_status") == "rejected":
                raise RuntimeError("The generated report did not pass its validation gates")
            for field in ("url", "technical_url"):
                url = report.get(field, "")
                if not url.startswith("/reports/"):
                    raise RuntimeError(f"Missing local report: {field}")
                with urlopen(API + url, timeout=60) as response:
                    html = response.read().decode("utf-8")
                if start not in html or end not in html:
                    raise RuntimeError(f"Report does not display the requested period: {field}")
            result = {"run_id": run_id, "period": f"{start} to {end} inclusive UTC", "undated_included": True,
                      "evidence_period_counts": period, "report": report,
                      "completed_at": datetime.now(timezone.utc).isoformat()}
            save(phase="completed", result=result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
        except Exception as exc:
            save(error=str(exc))
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{12}", args.source_run):
        parser.error("Invalid run identifier")
    if not date.fromisoformat(args.start) <= date.fromisoformat(args.end) <= datetime.now(timezone.utc).date():
        parser.error("Invalid calendar period")
    complete(args.source_run, args.start, args.end)
