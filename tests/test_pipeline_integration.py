import asyncio

import yaml

from cyberdeck import cli
from cyberdeck.collectors.base import CollectionResult
from cyberdeck.schemas import EvidenceStatus, SourceStatus, ThreatEvent


def _org_file(tmp_path, domains):
    path = tmp_path / "org.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "organization": {
                    "name": "Authorized Example",
                    "sector": "financial",
                    "country": "",
                    "author": "test",
                    "authorized_scope": True,
                    "primary_domains": domains,
                    "control_maturity": {},
                    "fraud_maturity": {},
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _run_with(monkeypatch, tmp_path, primary_results, domains):
    async def primary(*_args, **_kwargs):
        return primary_results

    async def enrichment(*_args, **_kwargs):
        return []

    async def validation(*_args, **_kwargs):
        return CollectionResult(SourceStatus(name="validation", status="empty", records=0), [])

    monkeypatch.setattr(cli, "_collect_primary_sources", primary)
    monkeypatch.setattr(cli, "_collect_vulnerability_enrichment", enrichment)
    monkeypatch.setattr(cli, "_collect_evidence_validation", validation)
    monkeypatch.setattr(cli, "store_events", lambda events, _path: len(events))
    org_path = _org_file(tmp_path, domains)
    _output, context = asyncio.run(
        cli.run_pipeline(
            str(org_path),
            "snapshot",
            30,
            str(tmp_path / "report.html"),
            source_config_override={"fixture": {}},
            return_context=True,
            render_html=False,
        )
    )
    return context


def test_pipeline_handles_multiple_domains_duplicates_false_positive_and_real_finding(monkeypatch, tmp_path):
    finding = ThreatEvent(
        id="spf-a",
        title="SPF policy not observed for one.example",
        category="attack_surface",
        source="fixture-a",
        evidence_url="dns://one.example/TXT",
        severity=0.6,
        tags=["domain:one.example", "email_security"],
        validation_result="confirmed_missing",
        technical_validation={"validation_result": "confirmed_missing"},
    )
    duplicate = finding.model_copy(update={"id": "spf-b", "source": "fixture-b"})
    second_domain = ThreatEvent(
        id="asset-two",
        title="Observed DNS asset two.example",
        category="attack_surface_dns",
        source="fixture-a",
        evidence_url="https://two.example/",
        tags=["domain:two.example", "dns_inventory_only"],
    )
    false_positive = ThreatEvent(
        id="fp",
        title="Unrelated brand mention",
        category="brand_reputation",
        source="fixture-a",
        evidence_url="https://news.invalid/unrelated",
        tags=["domain:one.example", "false_positive"],
    )
    context = _run_with(
        monkeypatch,
        tmp_path,
        [
            CollectionResult(SourceStatus(name="fixture-a", status="ok", records=3), [finding, second_domain, false_positive]),
            CollectionResult(SourceStatus(name="fixture-b", status="partial", records=1), [duplicate]),
        ],
        ["one.example", "two.example"],
    )

    assert context.processing_summary["raw_records_collected"] == 4
    assert context.processing_summary["duplicates_removed"] == 1
    assert context.processing_summary["false_positives"] == 1
    assert context.processing_summary["validated_findings"] == 1
    assert context.processing_summary["confirmed_findings"] == 0
    assert context.processing_summary["calculated_risks"] == 1
    assert context.processing_summary["confirmed_incidents"] == 0
    assert context.risk_findings[0].evidence_status == EvidenceStatus.VALIDATED
    assert context.risk_findings[0].likelihood_inputs["sector_context"] == 0


def test_pipeline_preserves_timeout_no_api_and_no_result_states_without_inventing_findings(monkeypatch, tmp_path):
    context = _run_with(
        monkeypatch,
        tmp_path,
        [
            CollectionResult(SourceStatus(name="no-key", status="missing", records=0, warning="not configured"), []),
            CollectionResult(SourceStatus(name="slow", status="timeout", records=0), []),
            CollectionResult(SourceStatus(name="empty", status="empty", records=0), []),
        ],
        ["one.example"],
    )

    states = {status.name: status for status in context.source_statuses}
    assert not states["no-key"].configured and not states["no-key"].queried
    assert states["slow"].timed_out and not states["slow"].success
    assert states["empty"].success and states["empty"].no_data
    assert context.raw_events == []
    assert context.risk_findings == []
    assert context.processing_summary["validated_findings"] == 0
    assert context.processing_summary["confirmed_findings"] == 0
    assert context.metrics["forecast"]["7"]["signal_pressure_index"] is None
    assert context.metrics["prospective_attack_risk"]["status"] == "insufficient_evidence"
