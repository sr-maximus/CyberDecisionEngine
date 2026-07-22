import json

from cyberdeck.reporting.html_report import prepare_context_for_report
from cyberdeck.schemas import OrganizationProfile, RunContext, SourceStatus
from scripts import regenerate_persisted_reports as regeneration


def test_output_run_summary_uses_the_same_snapshot_as_reports(tmp_path, monkeypatch):
    context = RunContext(
        organization=OrganizationProfile(
            name="Example Org",
            sector="Technology",
            country="CO",
            author="test",
            authorized_scope=True,
            primary_domains=["example.org"],
        ),
        mode="snapshot",
        lookback_days=30,
        source_statuses=[
            SourceStatus(name="productive", status="ok", records=2),
            SourceStatus(name="disabled", status="disabled", records=0),
        ],
    )
    prepared = prepare_context_for_report(context, run_id="run-sync")

    project_root = tmp_path
    rendered = project_root / "reports" / "web" / "run-sync-example-org.html"
    rendered.parent.mkdir(parents=True)
    rendered.write_text("<html></html>", encoding="utf-8")
    rendered.with_name(f"{rendered.stem}_validation.json").write_text(
        json.dumps({"status": "approved"}),
        encoding="utf-8",
    )
    context_path = project_root / "data" / "web_runs" / "run-sync" / "context.json"
    context_path.parent.mkdir(parents=True)
    context_path.write_text(prepared.model_dump_json(indent=2), encoding="utf-8")

    monkeypatch.setattr(regeneration, "PROJECT_ROOT", project_root)
    target = regeneration.ReportTarget("run-sync", "run-sync-example-org", "outputs/example/run-sync")
    regeneration._sync_output_directory(
        target,
        rendered,
        context_path,
        prepared,
        run_payload={
            "id": "run-sync",
            "domains": ["example.org"],
            "summary": {"kpis": {"total_sources": 22}},
        },
    )

    synchronized = json.loads(
        (project_root / "outputs" / "example" / "run-sync" / "run-summary.json").read_text(
            encoding="utf-8"
        )
    )
    metrics = prepared.decision_snapshot["metrics"]

    assert synchronized["summary"]["kpis"]["registered_sources"] == metrics["registered_sources"]["value"]
    assert synchronized["summary"]["kpis"]["total_sources"] == metrics["total_sources"]["value"]
    assert synchronized["summary"]["kpis"]["queried_sources"] == metrics["queried_sources"]["value"]
    assert synchronized["summary"]["kpis"]["productive_sources"] == metrics["productive_sources"]["value"]
    assert synchronized["report"]["validation_status"] == "approved"
    assert synchronized["report"]["final"] is True
