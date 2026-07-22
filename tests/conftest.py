import pytest

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, RunContext, SourceStatus, ThreatEvent


@pytest.fixture
def regression_context() -> RunContext:
    """Deterministic synthetic context; never presented as collected intelligence."""
    events = [
        ThreatEvent(
            id="E-FIXTURE-FRAUD",
            title="Synthetic phishing record related to example.com",
            category="fraud phishing",
            source="fixture-public-search",
            evidence_url="https://example.com/evidence/phishing",
            evidence_status=EvidenceStatus.VALIDATED,
            confidence_score=0.86,
            technical_validation={"validation_method": "fixture_reproducible_query"},
            demo=True,
        ),
        ThreatEvent(
            id="E-FIXTURE-IDENTITY",
            title="Synthetic credential exposure record related to example.com",
            category="identity credential",
            source="fixture-public-search",
            evidence_url="https://example.com/evidence/identity",
            evidence_status=EvidenceStatus.VALIDATED,
            confidence_score=0.82,
            technical_validation={"validation_method": "fixture_reproducible_query"},
            demo=True,
        ),
    ]
    findings = [
        RiskFinding(
            finding_id="F-FIXTURE-FRAUD",
            title="Synthetic fraud condition",
            category="fraud",
            likelihood=0.4,
            impact=0.5,
            inherent_risk=0.2,
            residual_risk=0.12,
            matrix_score=4,
            matrix_label="Bajo",
            evidence=["https://example.com/evidence/phishing"],
            evidence_status=EvidenceStatus.VALIDATED,
            confidence_score=0.86,
            linked_evidence_ids=["E-FIXTURE-FRAUD"],
            validation_method="fixture_reproducible_query",
            demo=True,
        ),
        RiskFinding(
            finding_id="F-FIXTURE-IDENTITY",
            title="Synthetic identity condition",
            category="identity credential",
            likelihood=0.3,
            impact=0.4,
            inherent_risk=0.12,
            residual_risk=0.08,
            matrix_score=3,
            matrix_label="Bajo",
            evidence=["https://example.com/evidence/identity"],
            evidence_status=EvidenceStatus.VALIDATED,
            confidence_score=0.82,
            linked_evidence_ids=["E-FIXTURE-IDENTITY"],
            validation_method="fixture_reproducible_query",
            demo=True,
        ),
    ]
    return RunContext(
        organization=OrganizationProfile(
            name="Synthetic Regression Organization",
            sector="Financial and insurance activities",
            country="CO",
            author="test-suite",
            authorized_scope=True,
            primary_domains=["example.com"],
        ),
        mode="snapshot",
        lookback_days=30,
        raw_events=events,
        risk_findings=findings,
        source_statuses=[
            SourceStatus(name="fixture-public-search", status="ok", records=2, mode="fixture"),
            SourceStatus(name="fixture-socmint", status="empty", records=0, mode="fixture"),
            SourceStatus(name="fixture-darkweb", status="empty", records=0, mode="fixture"),
        ],
    )
