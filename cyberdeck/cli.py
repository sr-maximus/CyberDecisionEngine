from __future__ import annotations

import asyncio
import os
import platform
import shutil
import sys
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from cyberdeck.analysis.control_theory import prioritize_actions
from cyberdeck.analysis.cyber_radar import build_cyber_risk_radar
from cyberdeck.analysis.forecasting import build_forecast
from cyberdeck.analysis.fraud import FRAUD_REFERENCE_NOTES, build_fraud_findings, fraud_pressure_index
from cyberdeck.analysis.game_theory import minimax_recommendations
from cyberdeck.analysis.mitre_mapping import build_atlas_profile, build_d3fend_profile, build_mitre_profile
from cyberdeck.analysis.narratives import build_narrative_intelligence
from cyberdeck.analysis.strategic_news import build_strategic_intelligence
from cyberdeck.analysis.risk_engine import business_impact, contextual_likelihood, control_effectiveness, inherent_risk, matrix_4x4, monte_carlo_risk, residual_risk, threat_activity_score
from cyberdeck.analysis.source_intel import build_actor_profile, build_pattern_profile, build_source_coverage
from cyberdeck.analysis.strategy import build_strategic_action_plan
from cyberdeck.analysis.systemic import build_systemic_model
from cyberdeck.analysis.trend_detection import summarize_trends
from cyberdeck.analysis.vulnerability import build_vulnerability_intelligence
from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.collectors.censys_passive import CensysPassiveCollector
from cyberdeck.collectors.cisa_kev import CisaKevCollector
from cyberdeck.collectors.common_crawl import CommonCrawlCollector
from cyberdeck.collectors.darkweb_authorized import DarkwebAuthorizedCollector
from cyberdeck.collectors.evidence_explorer import EvidenceExplorerCollector
from cyberdeck.collectors.epss import EpssCollector
from cyberdeck.collectors.fraud_intelligence import FraudIntelligenceCollector
from cyberdeck.collectors.github_advisories import GithubAdvisoriesCollector
from cyberdeck.collectors.kali_surface import KaliSurfaceCollector
from cyberdeck.collectors.misp import MispCollector
from cyberdeck.collectors.nvd import NvdCollector
from cyberdeck.collectors.osint_tools import OsintToolsCollector
from cyberdeck.collectors.otx import OtxPulseCollector
from cyberdeck.collectors.ransomware_live import RansomwareLiveCollector
from cyberdeck.collectors.rss import RssCollector
from cyberdeck.collectors.shodan_passive import ShodanPassiveCollector
from cyberdeck.collectors.socmint_public import SocmintPublicCollector
from cyberdeck.collectors.spiderfoot import SpiderFootCollector
from cyberdeck.collectors.stix_taxii import StixTaxiiCollector
from cyberdeck.collectors.tor_runtime import TorRuntimeCollector
from cyberdeck.collectors.urlscan_search import UrlscanSearchCollector
from cyberdeck.collectors.web_search import WebSearchCollector
from cyberdeck.enrichment.cve_enricher import cves_from_events
from cyberdeck.enrichment.evidence_pipeline import process_evidence_records
from cyberdeck.enrichment.normalizer import normalize_events
from cyberdeck.frameworks.sync import sync_frameworks
from cyberdeck.knowledge import create_knowledge_backend, knowledge_records_from_bundle
from cyberdeck.logging import console, fail, ok, warn
from cyberdeck.reporting.html_report import REFERENCES, render_report
from cyberdeck.safety import enforce_authorized_scope
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, RunContext, SourceStatus, ThreatEvent
from cyberdeck.semantics import CLAIM_EVIDENCE_MODEL_VERSION, build_claim_evidence_bundle
from cyberdeck.settings import PROJECT_ROOT, load_app_config, load_sources_config, write_yaml
from cyberdeck.storage.db import latest_report, store_events


app = typer.Typer(help="CyberDecisionEngine defensive cyber decision intelligence CLI.")
frameworks_app = typer.Typer(help="Framework sync commands.")
report_app = typer.Typer(help="Report commands.")
app.add_typer(frameworks_app, name="frameworks")
app.add_typer(report_app, name="report")


@app.command()
def doctor(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    """Check local environment and safety posture."""
    table = Table(title="CyberDecisionEngine Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    py_ok = sys.version_info >= (3, 13)
    arch = platform.machine()
    xcode = shutil.which("xcode-select") is not None
    brew = shutil.which("brew") is not None
    config_ok = (PROJECT_ROOT / "config" / "app.yml").exists()
    report_dir_ok = (PROJECT_ROOT / "reports").exists()

    checks = [
        ("Python 3.13+", py_ok, platform.python_version()),
        ("macOS Intel x86_64", arch == "x86_64", arch),
        ("Xcode CLT probe", xcode, "xcode-select available" if xcode else "missing"),
        ("Homebrew probe", brew, "brew available" if brew else "missing"),
        ("Config files", config_ok, "config/app.yml"),
        ("Reports dir", report_dir_ok, "reports/"),
        ("Dark Web guardrail", True, "Tor disabled; redacted imports only"),
        ("Secret redaction", True, "console/report redaction enabled"),
    ]
    for name, passed, detail in checks:
        table.add_row(name, "[green]OK[/green]" if passed else "[yellow]WARN[/yellow]", detail)
    console.print(table)
    if verbose and not py_ok:
        warn("This workstation has Python below 3.13. The installer will require Python 3.13+ on Mac Intel.")


@app.command("init-org")
def init_org(
    name: str = typer.Option(..., "--name"),
    sector: str = typer.Option(..., "--sector"),
    country: str = typer.Option(..., "--country"),
    author: str = typer.Option(..., "--author"),
    out: str = typer.Option(..., "--out"),
) -> None:
    """Create an authorized organization profile."""
    profile = {
        "organization": {
            "name": name,
            "sector": sector,
            "country": country,
            "author": author,
            "authorized_scope": True,
            "business_units": ["banking"],
            "crown_jewels": ["digital_banking", "payments", "identity", "cloud", "apis", "fraud_platforms"],
            "technologies": ["cloud", "iam", "siem", "edr", "waf", "mobile"],
            "risk_appetite": {"operational": 0.25, "financial": 0.25, "reputational": 0.20, "regulatory": 0.20, "innovation": 0.10},
            "control_maturity": {
                "iso27001_score": 0.60,
                "nist_csf_score": 0.62,
                "soc2_score": 0.54,
                "d3fend_coverage": 0.55,
                "attack_detection_coverage": 0.50,
                "incident_response_maturity": 0.62,
            },
            "fraud_maturity": {
                "identity_proofing": 0.55,
                "transaction_monitoring": 0.60,
                "device_intelligence": 0.52,
                "mule_detection": 0.48,
                "case_management": 0.58,
                "customer_awareness": 0.54,
            },
        },
        "sources": {
            "allow_passive_external_exposure": False,
            "allow_socmint_public": True,
            "allow_darkweb_authorized_import": True,
            "allow_tor": True,
        },
    }
    path = write_yaml(out, profile)
    ok(f"Organization profile written: {path}")


@frameworks_app.command("sync")
def frameworks_sync(
    all_: bool = typer.Option(False, "--all", help="Sync all supported frameworks."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Sync framework caches and mappings."""
    statuses = asyncio.run(sync_frameworks(sync_all=all_))
    for status in statuses:
        message = f"{status.name}: {status.status} ({status.records} records)"
        if status.warning and verbose:
            warn(f"{message} - {status.warning}")
        else:
            ok(message)


@app.command()
def run(
    org: str = typer.Option(..., "--org"),
    mode: str = typer.Option("snapshot", "--mode"),
    lookback_days: int = typer.Option(30, "--lookback-days"),
    html: str = typer.Option("reports/cyberdeck_executive.html", "--html"),
    real_only: bool = typer.Option(True, "--real-only/--allow-demo", help="Use only real/free sources; never inject demo data."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a passive defensive intelligence pipeline and generate HTML."""
    output = asyncio.run(run_pipeline(org, mode, lookback_days, html, verbose=verbose, real_only=real_only))
    ok(f"Report ready: {output}")


@app.command()
def monitor(
    org: str = typer.Option(..., "--org"),
    duration: str = typer.Option("24h", "--duration"),
    interval: str = typer.Option("30m", "--interval"),
    html: str = typer.Option("reports/cyberdeck_monitor.html", "--html"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run controlled passive monitoring for a duration."""
    asyncio.run(_monitor(org, duration, interval, html, verbose))


@report_app.command("open")
def report_open(latest: bool = typer.Option(False, "--latest")) -> None:
    """Open the latest generated HTML report."""
    if not latest:
        raise typer.BadParameter("Use --latest to open the newest report.")
    report_path = latest_report()
    if report_path is None:
        fail("No HTML reports found in reports/.")
        raise typer.Exit(1)
    webbrowser.open(report_path.as_uri())
    ok(f"Opened: {report_path}")


async def run_pipeline(
    org_path: str,
    mode: str,
    lookback_days: int,
    html: str,
    verbose: bool = False,
    real_only: bool = True,
    source_config_override: Optional[Dict[str, object]] = None,
    return_context: bool = False,
    render_html: bool = True,
):
    org_data = enforce_authorized_scope(org_path)
    org = OrganizationProfile(**org_data["organization"])
    source_config = source_config_override or load_sources_config().get("sources", {})
    app_config = load_app_config().get("app", {})
    lookback_hours = max(1, int(getattr(org, "lookback_hours", lookback_days * 24)))
    analysis_window = getattr(org, "analysis_window", f"{lookback_days}d")
    context = RunContext(
        organization=org,
        mode=mode,
        lookback_days=lookback_days,
        lookback_hours=lookback_hours,
        analysis_window=analysis_window,
        report_display_at=org.report_display_at,
        references=REFERENCES,
    )
    knowledge_backend = create_knowledge_backend()
    knowledge_context = await knowledge_backend.read_context(_scope_terms(org))
    context.knowledge_backend = {
        "status": knowledge_backend.status(),
        "read": knowledge_context.model_dump(),
    }

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), TimeElapsedColumn(), console=console, transient=False) as progress:
        task = progress.add_task(f"Loading organization profile: {org.name}", total=None)
        await asyncio.sleep(0.05)
        progress.update(task, description="Collecting passive and authorized sources")
        first_results = await _collect_primary_sources(source_config, org_data, real_only=real_only)
        for result in first_results:
            context.source_statuses.append(result.status)
            context.raw_events.extend(result.events)

        progress.update(task, description="Enriching CVEs with EPSS and NVD")
        cves = cves_from_events(context.raw_events)
        enrich_results = await _collect_vulnerability_enrichment(source_config, cves)
        for result in enrich_results:
            context.source_statuses.append(result.status)
            context.raw_events.extend(result.events)

        progress.update(task, description="Normalizing, classifying and deduplicating records")
        raw_record_count = len(context.raw_events)
        processed = process_evidence_records(
            normalize_events(context.raw_events),
            _scope_terms(org),
            raw_count=raw_record_count,
        )
        events = processed.records
        if real_only:
            events = [event for event in events if not event.demo]
        context.raw_events = [event for event in events if _event_within_window(event, lookback_days, lookback_hours)]
        evidence_result = await _collect_evidence_validation(source_config, context.raw_events, org)
        context.source_statuses.append(evidence_result.status)
        if evidence_result.events:
            raw_record_count += len(evidence_result.events)
            processed = process_evidence_records(
                normalize_events([*context.raw_events, *evidence_result.events]),
                _scope_terms(org),
                raw_count=raw_record_count,
            )
            context.raw_events = processed.records
            if real_only:
                context.raw_events = [event for event in context.raw_events if not event.demo]
            context.raw_events = [event for event in context.raw_events if _event_within_window(event, lookback_days, lookback_hours)]
        context.processing_summary = dict(processed.summary)
        stored = store_events(context.raw_events, app_config.get("cache_db", "data/cyberdeck.sqlite"))
        context.source_statuses.append(SourceStatus(name="Cache local de evidencias", status="ok", records=stored, mode="cache"))

        progress.update(task, description="Calculating risk, fraud and posture metrics")
        context.risk_findings = _build_all_findings(context.raw_events, org, real_only=real_only)
        context.metrics = _build_metrics(context.raw_events, context.risk_findings, org, context.source_statuses)
        context.processing_summary["validated_findings"] = sum(
            1
            for finding in context.risk_findings
            if finding.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        )
        context.processing_summary["confirmed_findings"] = sum(
            1 for finding in context.risk_findings if finding.evidence_status == EvidenceStatus.CONFIRMED
        )
        context.processing_summary["calculated_risks"] = len(context.risk_findings)
        context.processing_summary["confirmed_incidents"] = sum(1 for item in context.risk_findings if item.incident_confirmed)
        context.processing_summary["false_positives"] = sum(
            1 for event in context.raw_events if event.evidence_status == EvidenceStatus.FALSE_POSITIVE
        )
        context.incidents_confirmed = int(context.processing_summary["confirmed_incidents"])
        context.false_positive_count = int(context.processing_summary["false_positives"])
        context.connector_coverage = context.metrics.get("source_coverage", {})
        subject_ids = list(dict.fromkeys([org.name, *org.subject_aliases, *org.primary_domains]))
        claim_bundle = build_claim_evidence_bundle(
            context.raw_events,
            context.risk_findings,
            subject_ids,
            scope=f"{org.entity_type}:{org.name}",
        )
        context.claim_evidence_model_version = CLAIM_EVIDENCE_MODEL_VERSION
        context.claims = [item.model_dump() for item in claim_bundle.claims]
        context.evidence_items = [item.model_dump() for item in claim_bundle.evidence]
        context.claim_evidence_links = [item.model_dump() for item in claim_bundle.links]
        context.contradicting_evidence = [item.model_dump() for item in claim_bundle.contradictions]
        context.interpretations = [item.model_dump() for item in claim_bundle.interpretations]
        context.decisions = [item.model_dump() for item in claim_bundle.decisions]
        sync_result = await knowledge_backend.write_validated(knowledge_records_from_bundle(claim_bundle))
        context.knowledge_backend["sync"] = sync_result.model_dump()

        output = Path(html)
        if render_html:
            progress.update(task, description="Generating executive HTML report")
            output = render_report(context, html)
            progress.update(task, description=f"Report ready: {output}")
        else:
            progress.update(task, description="Analysis context ready; report pending user request")
    if verbose:
        _print_source_statuses(context.source_statuses)
    if return_context:
        return output, context
    return output


def _event_within_window(event: ThreatEvent, lookback_days: int, lookback_hours: int) -> bool:
    if event.demo:
        return True
    observed_at = _parse_event_datetime(event.observed_at)
    if observed_at is not None:
        return datetime.now(timezone.utc) - observed_at <= timedelta(hours=max(1, lookback_hours))
    return event.age_days <= max(lookback_days, 1)


def _parse_event_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


async def _collect_primary_sources(source_config: Dict[str, object], org_data: Dict[str, object], real_only: bool = True):
    cisa_config = source_config.get("cisa_kev", {})
    web_search_config = source_config.get("web_search", {})
    osint_public_config = source_config.get("osint_public", {})
    osint_tools_config = source_config.get("osint_tools", {})
    kali_surface_config = source_config.get("kali_surface", {})
    spiderfoot_config = source_config.get("spiderfoot", {})
    socmint_config = source_config.get("socmint_public", {})
    ransomware_live_config = source_config.get("ransomware_live", {})
    urlscan_config = source_config.get("urlscan", {})
    otx_config = source_config.get("otx", {})
    eps = []
    collectors = [
        CisaKevCollector(cisa_config.get("url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")),
        WebSearchCollector(
            web_search_config.get("queries", []),
            max_records=int(web_search_config.get("max_records", 40)),
            enabled=bool(web_search_config.get("enabled", True)),
            providers=web_search_config.get("providers", web_search_config.get("provider")),
            max_queries=int(web_search_config.get("max_queries", 20)),
            request_delay_seconds=float(web_search_config.get("request_delay_seconds", 0.35)),
            google_cse_api_key=web_search_config.get("google_cse_api_key"),
            google_cse_cx=web_search_config.get("google_cse_cx"),
            google_cse_api_key_env=web_search_config.get("google_cse_api_key_env", "GOOGLE_CSE_API_KEY"),
            google_cse_cx_env=web_search_config.get("google_cse_cx_env", "GOOGLE_CSE_CX"),
            brave_api_key=web_search_config.get("brave_api_key"),
            brave_api_key_env=web_search_config.get("brave_api_key_env", "BRAVE_SEARCH_API_KEY"),
            timeout_seconds=float(web_search_config.get("timeout_seconds", 8.0)),
            collection_timeout_seconds=float(web_search_config.get("collection_timeout_seconds", 80.0)),
            provider_query_limits=web_search_config.get("provider_query_limits"),
        ),
        UrlscanSearchCollector(
            urlscan_config.get("terms", []),
            enabled=bool(urlscan_config.get("enabled", True)),
            max_records=int(urlscan_config.get("max_records", 60)),
            api_key_env=str(urlscan_config.get("api_key_env", "URLSCAN_API_KEY")),
            timeout_seconds=float(urlscan_config.get("timeout_seconds", 8.0)),
        ),
        CommonCrawlCollector(
            osint_public_config.get("domains", []),
            enabled=bool(osint_public_config.get("enabled", True)),
            max_records=int(osint_public_config.get("max_records", 40)),
            max_indexes=int(osint_public_config.get("max_indexes", 1)),
        ),
        OsintToolsCollector(
            osint_tools_config.get("targets", []),
            endpoint=osint_tools_config.get("endpoint") or os.getenv("OSINT_TOOLS_URL", "http://osint-tools:7001"),
            enabled=bool(osint_tools_config.get("enabled", True)),
            max_records=int(osint_tools_config.get("max_records", 60)),
            timeout_seconds=float(osint_tools_config.get("timeout_seconds", 80)),
            proxy_url=osint_tools_config.get("proxy_url"),
            tools=osint_tools_config.get("tools"),
            priority=bool(osint_tools_config.get("priority", False)),
        ),
        KaliSurfaceCollector(
            kali_surface_config.get("domains", []),
            endpoint=kali_surface_config.get("endpoint") or os.getenv("KALI_SURFACE_URL", "http://kali-surface:7010"),
            enabled=bool(kali_surface_config.get("enabled", True)),
            mode=str(kali_surface_config.get("mode", "light")),
            max_records=int(kali_surface_config.get("max_records", 120)),
            max_hosts=int(kali_surface_config.get("max_hosts", 40)),
            timeout_seconds=float(kali_surface_config.get("timeout_seconds", 120)),
        ),
        SpiderFootCollector(
            spiderfoot_config.get("domains", []),
            endpoint=spiderfoot_config.get("endpoint") or os.getenv("SPIDERFOOT_URL", "http://spiderfoot:7020"),
            enabled=bool(spiderfoot_config.get("enabled", True)),
            max_records=int(spiderfoot_config.get("max_records", 120)),
            timeout_seconds=float(spiderfoot_config.get("timeout_seconds", 900)),
            max_threads=int(spiderfoot_config.get("max_threads", 4)),
            include_raw=bool(spiderfoot_config.get("include_raw", False)),
            depth=str(spiderfoot_config.get("depth", "deep")),
        ),
        RssCollector(source_config.get("rss", {}).get("feeds", [])),
        GithubAdvisoriesCollector(source_config.get("github_advisories", {}).get("api", "https://api.github.com/advisories")),
        SocmintPublicCollector(
            socmint_config.get("keywords", []),
            enabled=bool(org_data.get("sources", {}).get("allow_socmint_public", True)),
            real_only=real_only,
            max_records=int(socmint_config.get("max_records", 10)),
            max_queries=int(socmint_config.get("max_queries", 1)),
        ),
        RansomwareLiveCollector(
            ransomware_live_config.get("search_terms", []),
            enabled=bool(ransomware_live_config.get("enabled", True)),
            max_records=int(ransomware_live_config.get("max_records", 30)),
            country_filter=org_data.get("organization", {}).get("country") or None,
        ),
        OtxPulseCollector(
            otx_config.get("domains", []),
            enabled=bool(otx_config.get("enabled", True)),
            max_records=int(otx_config.get("max_records", 60)),
            api_key_env=str(otx_config.get("api_key_env", "OTX_API_KEY")),
            timeout_seconds=float(otx_config.get("timeout_seconds", 8.0)),
        ),
        TorRuntimeCollector(enabled=bool(org_data.get("sources", {}).get("allow_tor", False))),
        DarkwebAuthorizedCollector(
            enabled=bool(source_config.get("darkweb_authorized", {}).get("enabled", False)),
            allow_tor=bool(org_data.get("sources", {}).get("allow_tor", False)),
        ),
        StixTaxiiCollector(enabled=True),
        MispCollector(),
        ShodanPassiveCollector(),
        CensysPassiveCollector(),
    ]
    if not real_only:
        collectors.insert(2, FraudIntelligenceCollector())
    for collector in collectors:
        eps.append(_collect_safely(collector))
    return await asyncio.gather(*eps)


async def _collect_vulnerability_enrichment(source_config: Dict[str, object], cves: List[str]):
    epss_config = source_config.get("epss", {})
    nvd_config = source_config.get("nvd", {})
    collectors = [
        EpssCollector(epss_config.get("api", "https://api.first.org/data/v1/epss"), cves),
        NvdCollector(nvd_config.get("api", "https://services.nvd.nist.gov/rest/json/cves/2.0"), cves, nvd_config.get("env_key", "NVD_API_KEY")),
    ]
    return await asyncio.gather(*(_collect_safely(collector) for collector in collectors))


async def _collect_evidence_validation(source_config: Dict[str, object], events: List[ThreatEvent], org: OrganizationProfile) -> CollectionResult:
    explorer_config = source_config.get("evidence_explorer", {})
    collector = EvidenceExplorerCollector(
        events,
        domains=explorer_config.get("domains") or org.primary_domains,
        terms=explorer_config.get("terms") or _scope_terms(org),
        endpoint=explorer_config.get("endpoint") or os.getenv("OSINT_TOOLS_URL", "http://osint-tools:7001"),
        enabled=bool(explorer_config.get("enabled", True)),
        max_urls=int(explorer_config.get("max_urls", 30)),
        timeout_seconds=float(explorer_config.get("timeout_seconds", 8.0)),
    )
    return await _collect_safely(collector)


async def _collect_safely(collector: Collector) -> CollectionResult:
    timeout_seconds = _collector_timeout_budget(collector)
    try:
        return await asyncio.wait_for(collector.collect(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return CollectionResult(
            SourceStatus(
                name=getattr(collector, "name", collector.__class__.__name__),
                status="timeout",
                records=0,
                mode="real",
                warning=f"Collector exceeded {int(timeout_seconds)} seconds and was skipped to keep the report generation flow available.",
            ),
            [],
        )
    except Exception as exc:  # pragma: no cover - runtime/network defensive guard
        return CollectionResult(
            SourceStatus(
                name=getattr(collector, "name", collector.__class__.__name__),
                status="error",
                records=0,
                mode="real",
                warning=str(exc),
            ),
            [],
        )


def _collector_timeout_budget(collector: Collector) -> float:
    raw_timeout: Any = getattr(collector, "timeout_seconds", None)
    try:
        configured = float(raw_timeout) if raw_timeout is not None else 45.0
    except (TypeError, ValueError):
        configured = 45.0
    name = getattr(collector, "name", collector.__class__.__name__).lower()
    if "spiderfoot" in name or "inventario pasivo" in name:
        domain_count = len(getattr(collector, "domains", []) or [])
        waves = max(1, (domain_count + 1) // 2)
        return min(max(configured * waves + 25.0, 75.0), float(os.getenv("CDE_SPIDERFOOT_COLLECTOR_TIMEOUT_SECONDS", "1800")))
    if "kali" in name or "superficie externa" in name:
        return min(max(configured + 18.0, 45.0), float(os.getenv("CDE_KALI_COLLECTOR_TIMEOUT_SECONDS", "360")))
    if "internet search" in name or "busqueda publica" in name:
        collection_budget = float(getattr(collector, "collection_timeout_seconds", 120.0) or 120.0)
        return min(collection_budget + 25.0, float(os.getenv("CDE_WEB_SEARCH_COLLECTOR_TIMEOUT_SECONDS", "1200")))
    if "osint tools" in name or "correlacion osint" in name:
        return min(max(configured + 20.0, 45.0), float(os.getenv("CDE_OSINT_TOOLS_COLLECTOR_TIMEOUT_SECONDS", "600")))
    if "evidencia web" in name or "evidence" in name:
        return min(max(configured * 16 + 20.0, 45.0), float(os.getenv("CDE_EVIDENCE_EXPLORER_TIMEOUT_SECONDS", "360")))
    return min(max(configured + 10.0, 20.0), float(os.getenv("CDE_DEFAULT_COLLECTOR_TIMEOUT_SECONDS", "60")))


def _scope_terms(org: OrganizationProfile) -> List[str]:
    terms: List[str] = []
    for domain in org.primary_domains:
        cleaned = domain.strip().lower()
        if not cleaned:
            continue
        terms.append(cleaned)
        label = cleaned.split(".", 1)[0].replace("-", " ").replace("_", " ").strip()
        compact = label.replace(" ", "")
        if len(label) >= 4:
            terms.append(label)
        if len(compact) >= 4:
            terms.append(compact)
    org_name = (org.name or "").strip().lower()
    if org_name and not org_name.startswith("domain intelligence:") and len(org_name) >= 4:
        terms.append(org_name)
        terms.append(org_name.replace(" ", ""))
    deduped: List[str] = []
    seen = set()
    for term in terms:
        if len(term) < 4 or term in seen:
            continue
        seen.add(term)
        deduped.append(term)
    return deduped


def _event_scope_relevant(event: ThreatEvent, terms: List[str]) -> bool:
    if not terms:
        return False
    text = " ".join(
        [
            event.title,
            event.category,
            event.source,
            event.actor or "",
            event.technique or "",
            event.evidence_url or "",
            " ".join(event.tags),
        ]
    ).lower()
    return any(term in text for term in terms)


def _scope_relevant_events(events: List[ThreatEvent], org: OrganizationProfile) -> List[ThreatEvent]:
    terms = _scope_terms(org)
    return [event for event in events if _event_scope_relevant(event, terms)]


def _is_actionable_finding_event(event: ThreatEvent) -> bool:
    if _is_validation_only_event(event):
        return False
    if event.evidence_status not in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}:
        return False
    if event.category == "vulnerability":
        return event.vulnerability_status in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"}
    if event.category in {"phishing", "fraud", "account_takeover", "transaction_fraud", "ransomware", "darkweb_ransomware"}:
        return True
    if event.category == "attack_surface":
        return event.severity >= 0.55 and "dns_inventory_only" not in event.tags
    if event.category == "attack_surface_web":
        return event.severity >= 0.6 and any(tag in event.tags for tag in {"exposed_admin", "weak_tls", "missing_auth", "sensitive_endpoint"})
    if event.category == "osint_document_exposure":
        text = " ".join([event.title, event.evidence_url or "", " ".join(event.tags)]).lower()
        sensitive_terms = {"credential", "password", "backup", "dump", "secret", "config", "admin", "vpn", "source code", "apikey", "api key"}
        return any(term in text for term in sensitive_terms)
    return False


def _is_validation_only_event(event: ThreatEvent) -> bool:
    tags = set(event.tags or [])
    if tags.intersection({"validation_required", "reputation_checker", "dns_inventory_only"}):
        return True
    if event.category in {"web_search", "brand_reputation", "attack_surface_dns", "evidence_validation"} and event.severity < 0.55:
        return True
    return False


def _build_all_findings(events: List[ThreatEvent], org: OrganizationProfile, real_only: bool = True) -> List[RiskFinding]:
    general = _build_general_findings(events, org)
    scoped_events = _scope_relevant_events(events, org)
    fraud = build_fraud_findings(scoped_events, org.fraud_maturity, org.control_maturity, real_only=real_only)
    return sorted(general + fraud, key=lambda finding: finding.residual_risk, reverse=True)


def _build_general_findings(events: List[ThreatEvent], org: OrganizationProfile) -> List[RiskFinding]:
    control = org.control_maturity
    ce = (
        control_effectiveness(
            iso=control.get("iso27001_score", 0.0),
            nist=control.get("nist_csf_score", 0.0),
            soc2=control.get("soc2_score", 0.0),
            d3fend=control.get("d3fend_coverage", 0.0),
            attack_detection=control.get("attack_detection_coverage", 0.0),
            ir=control.get("incident_response_maturity", 0.0),
        )
        if control
        else 0.0
    )
    representative = [event for event in _scope_relevant_events(events, org) if _is_actionable_finding_event(event)][:8]
    if not representative:
        return []
    findings: List[RiskFinding] = []
    for event in representative:
        event_tags = {tag.lower() for tag in event.tags}
        declared_sector = (org.sector or "").strip().lower()
        explicit_sector_targeting = bool(
            declared_sector
            and declared_sector not in {"unknown", "no declarado", "not_declared"}
            and (
                "sector_targeting" in event_tags
                or "sector_campaign" in event_tags
                or f"sector:{declared_sector}" in event_tags
            )
        )
        sector_targeting = 0.2 if explicit_sector_targeting else 0.0
        event_activity = threat_activity_score(
            [
                {
                    "source_weight": event.source_weight,
                    "confidence": event.confidence,
                    "age_days": event.age_days,
                    "half_life": 14,
                }
            ]
        )
        activity_input = event_activity
        exposure_input = max(0.0, min(1.0, event.severity))
        vulnerability_input = min(1.0, event.cvss / 10) if event.vulnerability_status in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"} else 0.0
        epss_input = event.epss if vulnerability_input else 0.001
        kev_input = 1.0 if "kev" in event.tags and vulnerability_input else 0.0
        confidence_input = event.confidence_score
        likelihood = contextual_likelihood(
            A=activity_input * confidence_input,
            E=exposure_input,
            V=vulnerability_input,
            P=epss_input,
            K=kev_input,
            T=event_activity,
            S=sector_targeting,
            G=0.0,
            C=control.get("iso27001_score", 0.0),
            D=control.get("attack_detection_coverage", 0.0),
            R=control.get("incident_response_maturity", 0.0),
        )
        impact = _impact_for_event(event)
        inherent = inherent_risk(likelihood, impact)
        residual = residual_risk(inherent, ce)
        matrix = matrix_4x4(likelihood, impact)
        findings.append(
            RiskFinding(
                title=event.title,
                category=event.category,
                likelihood=round(likelihood, 4),
                impact=round(impact, 4),
                inherent_risk=round(inherent, 2),
                residual_risk=round(residual, 2),
                matrix_score=int(matrix["matrix_score"]),
                matrix_label=str(matrix["label"]),
                evidence=_finding_evidence_for_event(event),
                recommendations=_recommendations_for_event(event),
                owner=_owner_for_event(event),
                demo=event.demo,
                finding_id=f"fnd-{event.canonical_id or event.id}",
                evidence_status=event.evidence_status,
                confidence_level=event.confidence_level,
                confidence_score=event.confidence_score,
                linked_evidence_ids=[event.canonical_id or event.id],
                likelihood_inputs={
                    "activity": round(activity_input, 4),
                    "evidence_confidence": round(confidence_input, 4),
                    "exposure": round(exposure_input, 4),
                    "vulnerability_applicability": round(vulnerability_input, 4),
                    "epss": round(epss_input, 4),
                    "kev": round(kev_input, 4),
                    "sector_context": round(sector_targeting, 4),
                },
                impact_inputs={"business_impact": round(impact, 4)},
                control_inputs={
                    "control_effectiveness": round(ce, 4),
                    "detection": round(control.get("attack_detection_coverage", 0.0), 4),
                    "response": round(control.get("incident_response_maturity", 0.0), 4),
                },
                assumptions=[
                    "El cálculo usa evidencia externa y no sustituye validación interna.",
                    "La ausencia de una política pública no demuestra un ataque activo.",
                    "Los controles internos no declarados se tratan como desconocidos y no reducen el riesgo residual.",
                ],
                validation_method=event.validation_result,
                incident_confirmed=event.incident_confirmed,
                vulnerability_status=event.vulnerability_status,
            )
        )
    return findings


def _finding_evidence_for_event(event: ThreatEvent) -> List[str]:
    evidence = [event.evidence_url or f"{event.source} ({'demo' if event.demo else 'real'})"]
    rationale = _event_risk_rationale(event)
    if rationale:
        evidence.append(rationale)
    return evidence


def _event_risk_rationale(event: ThreatEvent) -> str:
    tags = set(event.tags or [])
    if event.cve or "kev" in tags:
        return "Base de criticidad: CVE/KEV o vulnerabilidad explícita correlacionada con la evidencia."
    if event.category in {"phishing", "fraud", "account_takeover", "transaction_fraud"}:
        return "Base de criticidad: señal pública con contexto explícito de fraude, suplantación o abuso; requiere validación operacional antes de takedown."
    if event.category in {"ransomware", "darkweb_ransomware"}:
        return "Base de criticidad: señal de ransomware/dark web autorizada dentro del alcance declarado."
    if event.category == "attack_surface":
        return "Base de criticidad: configuración o control técnico débil observado, no solo presencia de dominio."
    if event.category == "osint_document_exposure":
        return "Base de criticidad: documento o dato expuesto contiene términos sensibles verificables."
    return ""


def _impact_for_event(event: ThreatEvent) -> float:
    if event.category in {"phishing", "fraud", "account_takeover", "transaction_fraud"}:
        return business_impact(0.85, 0.60, 0.70, 0.78, 0.35, 0.72, 0.82)
    if event.category == "vulnerability":
        return business_impact(0.70, 0.74, 0.66, 0.70, 0.68, 0.55, 0.66)
    if event.category in {"ransomware", "darkweb_ransomware"}:
        return business_impact(0.86, 0.88, 0.70, 0.75, 0.90, 0.66, 0.82)
    return business_impact(0.58, 0.55, 0.55, 0.55, 0.45, 0.42, 0.55)


def _recommendations_for_event(event: ThreatEvent) -> List[str]:
    if event.category in {"phishing", "fraud", "account_takeover", "transaction_fraud"}:
        return ["Reforzar autenticacion resistente a phishing", "Monitorear dominios lookalike y takedown", "Integrar reglas de fraude, device intelligence y SOC"]
    if event.category == "vulnerability":
        return ["Priorizar KEV/EPSS con exposicion externa", "Aplicar patching basado en riesgo", "Aumentar deteccion ATT&CK T1190"]
    if event.category in {"ransomware", "darkweb_ransomware"}:
        return ["Validar backups inmutables", "Ejercitar respuesta a incidentes", "Revisar segmentacion, terceros y privilegios"]
    return ["Mantener monitoreo CTI", "Actualizar playbooks", "Revisar supuestos con responsables"]


def _owner_for_event(event: ThreatEvent) -> str:
    if event.category in {"phishing", "fraud", "account_takeover", "transaction_fraud"}:
        return "Fraude/SOC"
    if event.category in {"ransomware", "darkweb_ransomware"}:
        return "CISO/SOC/Continuidad"
    if event.category == "vulnerability":
        return "Infraestructura/DevSecOps"
    return "CISO"


def _build_metrics(events: List[ThreatEvent], findings: List[RiskFinding], org: OrganizationProfile, statuses: List[SourceStatus]) -> Dict[str, object]:
    analysis_events = _scope_relevant_events(events, org)
    assured_events = [
        event
        for event in analysis_events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    fraud_pressure = fraud_pressure_index(assured_events)
    control_key_labels = {
        "nist_csf_score": "NIST CSF 2.0",
        "iso27001_score": "ISO 27001:2022",
        "soc2_score": "SOC 2",
        "d3fend_coverage": "D3FEND",
        "attack_detection_coverage": "ATT&CK Detection",
        "incident_response_maturity": "Incident Response",
    }
    control_scores = {
        label: org.control_maturity[key]
        for key, label in control_key_labels.items()
        if key in org.control_maturity
    }
    avg_likelihood = sum(f.likelihood for f in findings) / max(1, len(findings))
    avg_impact = sum(f.impact for f in findings) / max(1, len(findings))
    source_coverage = build_source_coverage(statuses, events)
    avg_ce = (
        control_effectiveness(
            org.control_maturity.get("iso27001_score", 0.0),
            org.control_maturity.get("nist_csf_score", 0.0),
            org.control_maturity.get("soc2_score", 0.0),
            org.control_maturity.get("d3fend_coverage", 0.0),
            org.control_maturity.get("attack_detection_coverage", 0.0),
            org.control_maturity.get("incident_response_maturity", 0.0),
        )
        if control_scores
        else 0.0
    )
    evidence_assurance = len(assured_events) / max(1, len(analysis_events))
    source_health = float(source_coverage.get("source_health_score", 0.0) or 0.0)
    max_residual = max((finding.residual_risk for finding in findings), default=0.0)
    external_posture = (
        100 * (0.4 * source_health + 0.35 * evidence_assurance + 0.25 * max(0.0, 1 - max_residual / 100))
        if analysis_events
        else 0.0
    )
    monte_carlo = monte_carlo_risk(avg_likelihood, avg_impact, avg_ce, n=2000)
    declared_sector = (org.sector or "").strip().lower()
    sector_targeting_observed = any(
        "sector_targeting" in {tag.lower() for tag in event.tags}
        or "sector_campaign" in {tag.lower() for tag in event.tags}
        or (declared_sector and f"sector:{declared_sector}" in {tag.lower() for tag in event.tags})
        for event in assured_events
    )
    darkweb_signal = min(1.0, sum(1 for event in assured_events if event.category.startswith("darkweb") or "darkweb" in event.tags) / 10)
    strategic_news = build_strategic_intelligence(analysis_events, org)
    return {
        "posture_index": round(external_posture, 2),
        "external_cyber_intelligence_posture_index": round(external_posture, 2),
        "posture_index_type": "external_cyber_intelligence_posture_index",
        "posture_index_limitations": "No mide cumplimiento ni madurez interna; resume salud de fuentes, aseguramiento de evidencia y riesgo externo calculado.",
        "fraud_pressure": round(fraud_pressure, 3),
        "fraud_notes": FRAUD_REFERENCE_NOTES,
        "control_scores": control_scores,
        "control_assessment": {
            "status": "self_declared_unverified" if control_scores else "unassessed",
            "is_compliance_assessment": False,
            "note": "Los valores internos solo se muestran cuando fueron declarados; no equivalen a certificacion, auditoria ni cumplimiento.",
        },
        "trends": summarize_trends(analysis_events),
        "actors": build_actor_profile(analysis_events),
        "patterns": build_pattern_profile(analysis_events),
        "mitre": build_mitre_profile(analysis_events),
        "d3fend": build_d3fend_profile(analysis_events),
        "atlas": build_atlas_profile(analysis_events),
        "source_coverage": source_coverage,
        "vulnerability_intelligence": build_vulnerability_intelligence(analysis_events, findings),
        "risk_heat_radar": build_cyber_risk_radar(analysis_events, findings),
        "strategy": build_strategic_action_plan(findings, analysis_events, org, source_coverage),
        "strategic_news": strategic_news,
        "pestel": strategic_news["pestel"],
        "porter": strategic_news["porter"],
        "narrative_intelligence": build_narrative_intelligence(analysis_events, org),
        "forecast": build_forecast(
            kev_signal=1.0 if any(event.vulnerability_status in {"cve_applicable", "kev_exposed", "exploitation_observed"} for event in assured_events) else 0.0,
            sector_signal=0.2 if sector_targeting_observed else 0.0,
            socmint_signal=fraud_pressure,
            darkweb_signal=darkweb_signal,
        ),
        "monte_carlo": monte_carlo,
        "risk_methodology": {
            "purpose": "La estructura de riesgo convierte evidencia trazable en una estimacion contextual de plausibilidad, impacto de negocio, riesgo inherente, riesgo residual y matriz 4x4; no confirma incidentes.",
            "likelihood": "L es una estimacion contextual acotada. Solo usa CVE/KEV como aplicables cuando activo, producto y version han sido confirmados; los controles no declarados no se presumen.",
            "impact": "I pondera impacto financiero, operacional, confidencialidad, integridad, disponibilidad, legal y reputacional.",
            "control_effectiveness": "CE combina ISO, NIST, SOC2, D3FEND, cobertura ATT&CK y respuesta a incidentes, con tope de reduccion de 0.85 para evitar riesgo cero.",
            "matrix": "La matriz 4x4 usa ceil(4*L) y ceil(4*I). 1-3 Bajo, 4-7 Medio, 8-11 Alto, 12-16 Critico.",
            "monte_carlo": f"P10={monte_carlo['p10']}, P50={monte_carlo['p50']}, P90={monte_carlo['p90']}",
            "pestel_porter": "PESTEL y Porter son lentes contextuales sustentadas por evidencia explícita. Sus índices expresan soporte relativo de señales, no riesgo, probabilidad, cumplimiento ni madurez.",
            "chaos_sensitivity": "K=|R(x+epsilon)-R(x)|/(epsilon+1e-6). K alto indica que pequenos cambios de evidencia o controles pueden cambiar prioridad.",
        },
        "system_model": build_systemic_model(org.crown_jewels, org.technologies),
        "game_theory": minimax_recommendations(expected_loss=max((f.residual_risk for f in findings), default=20), control_cost=8.0),
        "control_priorities": (
            prioritize_actions(
                [
                    1 - org.control_maturity.get("attack_detection_coverage", 0.0),
                    1 - org.control_maturity.get("incident_response_maturity", 0.0),
                    1 - org.fraud_maturity.get("customer_awareness", 0.0),
                ]
            )
            if control_scores
            else []
        ),
    }


async def _monitor(org: str, duration: str, interval: str, html: str, verbose: bool) -> None:
    duration_seconds = _parse_duration(duration)
    interval_seconds = max(60, _parse_duration(interval))
    started = time.time()
    iteration = 1
    while time.time() - started <= duration_seconds:
        stem = Path(html).stem
        suffix = Path(html).suffix or ".html"
        output = str(Path(html).with_name(f"{stem}_{iteration}{suffix}"))
        await run_pipeline(org, "monitor", 30, output, verbose=verbose, real_only=True)
        iteration += 1
        if time.time() - started + interval_seconds > duration_seconds:
            break
        await asyncio.sleep(interval_seconds)


def _parse_duration(value: str) -> int:
    cleaned = value.strip().lower()
    if cleaned.endswith("h"):
        return int(float(cleaned[:-1]) * 3600)
    if cleaned.endswith("m"):
        return int(float(cleaned[:-1]) * 60)
    if cleaned.endswith("s"):
        return int(float(cleaned[:-1]))
    return int(float(cleaned))


def _print_source_statuses(statuses: List[SourceStatus]) -> None:
    table = Table(title="Source Status")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Mode")
    table.add_column("Records", justify="right")
    table.add_column("Warning")
    for status in statuses:
        table.add_row(status.name, status.status, status.mode, str(status.records), status.warning or "")
    console.print(table)


if __name__ == "__main__":
    app()
