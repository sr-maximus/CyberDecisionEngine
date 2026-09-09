"""Install the evidence-review correction without interrupting active analyses."""
from complete_historical_run import api, busy_runs, compose, wait_for


if __name__ == "__main__":
    compose("build", "api", "web")
    wait_for(lambda: api("/api/runs/status"), lambda rows: not busy_runs(rows),
             52 * 3600, "Waiting to install evidence-review correction")
    if busy_runs(api("/api/runs/status")):
        raise RuntimeError("New work started; installation deferred to avoid interruption")
    compose("up", "-d", "--no-deps", "api", "web")
    wait_for(lambda: api("/api/health"), lambda value: bool(value), 300, "API health")
    print("Evidence-review correction installed; no analyses were cancelled.", flush=True)
