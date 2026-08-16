import pytest
from pydantic import ValidationError

from cyberdeck.reporting.html_report import _capture_preview_url, _evidence_preview_gallery
from cyberdeck.schemas import EvidenceCapture, EvidenceStatus, OrganizationProfile, RunContext, ThreatEvent
from cyberdeck_api.evidence_capture import _capture_candidates


def test_capture_requires_hash_dimensions_and_timestamp():
    with pytest.raises(ValidationError):
        EvidenceCapture(
            screenshotId="SS-001",
            runId="run-001",
            evidenceId="E-001",
            sourceId="source-001",
            originalPageUrl="https://example.com/evidence",
            captureTimestamp="2026-07-19T12:00:00+00:00",
            finalUrl="https://example.com/evidence",
            imagePath="assets/evidence.png",
            validationStatus="captured",
            relatedEvidenceId="E-001",
        )


def test_report_gallery_uses_only_explicit_verified_capture():
    event = ThreatEvent(
        id="E-001",
        title="Verified page",
        category="open_web",
        source="public source",
        evidence_url="https://example.com/evidence",
        captures=[
            EvidenceCapture(
                screenshotId="SS-001",
                runId="run-001",
                evidenceId="E-001",
                sourceId="source-001",
                originalPageUrl="https://example.com/evidence",
                pageTitle="Evidence page",
                captureTimestamp="2026-07-19T12:00:00+00:00",
                finalUrl="https://example.com/evidence",
                responseStatus=200,
                contentType="text/html",
                viewport={"width": 1440, "height": 900},
                fullPage=True,
                imagePath="assets/evidence-E-001.png",
                imageHash="sha256:fixture",
                imageFormat="png",
                imageSizeBytes=18432,
                dimensions={"width": 1440, "height": 2400},
                browserEngine="internal_browser",
                browserEngineVersion="chromium-fixture",
                validationStatus="verified",
                relatedEvidenceId="E-001",
            )
        ],
    )
    gallery = _evidence_preview_gallery([event.model_dump(mode="json")], "es")
    assert gallery[0]["preview_url"] == "assets/evidence-E-001.png"
    assert gallery[0]["image_hash"] == "sha256:fixture"
    assert gallery[0]["screenshot_id"] == "SS-001"
    assert gallery[0]["image_size_bytes"] == 18432


def test_legacy_screenshot_fields_do_not_become_visual_evidence():
    event = {
        "id": "legacy",
        "title": "Legacy preview",
        "evidence_url": "https://urlscan.io/result/synthetic-record/",
        "screenshot_url": "https://urlscan.io/screenshots/synthetic-record.png",
        "technical_validation": {
            "screenshot_url": "https://urlscan.io/screenshots/synthetic-record.png"
        },
    }
    assert _evidence_preview_gallery([event], "es") == []


def test_remote_preview_is_not_accepted_as_internal_capture():
    assert _capture_preview_url(
        {
            "validationStatus": "verified",
            "imagePath": "https://urlscan.io/screenshots/example.png",
        }
    ) == ""


def test_failed_capture_requires_an_explicit_reason():
    capture = EvidenceCapture(
        screenshotId="SS-FAILED",
        runId="run-001",
        evidenceId="E-002",
        sourceId="source-001",
        originalPageUrl="https://example.com/evidence",
        captureTimestamp="2026-07-19T12:00:00+00:00",
        finalUrl="https://example.com/evidence",
        validationStatus="failed",
        failureReason="page_required_authentication",
        relatedEvidenceId="E-002",
    )
    assert capture.failure_reason == "page_required_authentication"


def test_capture_candidates_prioritize_scope_and_skip_unapplied_global_advisories():
    context = RunContext(
        organization=OrganizationProfile(
            name="Example Group",
            sector="Financial services",
            country="CO",
            author="test-suite",
            primary_domains=["example.com"],
            brands=["Example Bank"],
            authorized_scope=True,
        ),
        mode="snapshot",
        lookback_days=30,
        raw_events=[
            ThreatEvent(
                id="GHSA-CONTEXT",
                title="Unrelated package vulnerability",
                category="vulnerability",
                source="global advisory",
                evidence_url="https://github.com/advisories/GHSA-CONTEXT",
                evidence_status=EvidenceStatus.CONTEXTUAL,
                relationship_to_scope="contextual",
                vulnerability_status="cve_candidate",
                severity=0.99,
            ),
            ThreatEvent(
                id="OFFICIAL-PAGE",
                title="Example Group corporate update",
                category="web_search",
                source="public search",
                evidence_url="https://www.example.com/news/update",
                evidence_status=EvidenceStatus.RELATED,
                relationship_to_scope="direct",
                confidence_score=0.75,
            ),
            ThreatEvent(
                id="JSON-FEED",
                title="Example Group raw feed",
                category="open_data",
                source="public feed",
                evidence_url="https://example.com/feed.json",
                evidence_status=EvidenceStatus.DIRECT,
                relationship_to_scope="direct",
            ),
        ],
    )

    candidates = _capture_candidates(context)

    assert [item[1]["evidence_id"] for item in candidates] == ["OFFICIAL-PAGE"]


def test_capture_candidates_reserve_html_evidence_for_each_primary_domain():
    context = RunContext(
        organization=OrganizationProfile(
            name="Example Group",
            sector="Energy",
            country="CO",
            author="test-suite",
            primary_domains=["alpha.example", "beta.example"],
            authorized_scope=True,
        ),
        mode="snapshot",
        lookback_days=30,
        raw_events=[
            ThreatEvent(
                id="ALPHA-PDF",
                title="Alpha security policy",
                category="osint_public_index",
                source="public index",
                evidence_url="https://alpha.example/security-policy.pdf",
                evidence_status=EvidenceStatus.VALIDATED,
                relationship_to_scope="direct",
            ),
            ThreatEvent(
                id="ALPHA-HOME",
                title="Alpha official site",
                category="osint_public_index",
                source="public index",
                evidence_url="https://alpha.example/",
                evidence_status=EvidenceStatus.RELATED,
                relationship_to_scope="direct",
            ),
            ThreatEvent(
                id="ALPHA-HTTP",
                title="Alpha official site over HTTP",
                category="osint_public_index",
                source="public index",
                evidence_url="http://alpha.example/",
                evidence_status=EvidenceStatus.RELATED,
                relationship_to_scope="direct",
            ),
            ThreatEvent(
                id="ALPHA-PORTAL",
                title="Alpha supplier portal",
                category="osint_public_index",
                source="public index",
                evidence_url="https://portal.alpha.example/",
                evidence_status=EvidenceStatus.RELATED,
                relationship_to_scope="direct",
            ),
            ThreatEvent(
                id="BETA-HOME",
                title="Beta official site",
                category="osint_public_index",
                source="public index",
                evidence_url="https://www.beta.example/",
                evidence_status=EvidenceStatus.RELATED,
                relationship_to_scope="direct",
            ),
        ],
    )

    candidates = _capture_candidates(context)

    assert [item[1]["evidence_id"] for item in candidates[:2]] == ["ALPHA-HOME", "BETA-HOME"]
    assert all(not item[1]["url"].endswith(".pdf") for item in candidates)
