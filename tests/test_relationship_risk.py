from cyberdeck.analysis.relationship_risk import build_relationship_risk_intelligence
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example Holdings",
        sector="Transport",
        subsector="Aviation | Cargo",
        country="Colombia",
        author="Test",
        authorized_scope=True,
        primary_domains=["example.com"],
        comparison_domains=["competitor.example"],
        critical_suppliers=["Cloud Partner"],
        declared_competitors=["Market Peer"],
    )


def _event(event_id: str, **changes: object) -> ThreatEvent:
    payload = {
        "id": event_id,
        "title": "Public record",
        "category": "open_web",
        "source": "public-index",
        "source_refs": ["public-index"],
        "evidence_url": f"https://evidence.example/{event_id}",
        "relationship_to_scope": "explicit_mention",
    }
    payload.update(changes)
    return ThreatEvent(**payload)


def test_declared_supplier_without_assured_risk_evidence_is_context_only() -> None:
    event = _event(
        "supplier-context",
        title="Cloud Partner announces a new regional service",
        evidence_status=EvidenceStatus.RELATED,
    )

    result = build_relationship_risk_intelligence([event], _organization())
    row = result["third_party"]["rows"][0]

    assert row["name"] == "Cloud Partner"
    assert row["status"] == "context_only"
    assert row["attention_score"] is None
    assert row["risk_signal_count"] == 0


def test_validated_supplier_risk_signal_receives_traceable_attention_score() -> None:
    event = _event(
        "supplier-risk",
        title="Cloud Partner reports ransomware service interruption",
        evidence_status=EvidenceStatus.VALIDATED,
        severity=0.8,
        confidence_score=0.9,
    )

    result = build_relationship_risk_intelligence([event], _organization())
    row = result["third_party"]["rows"][0]

    assert row["status"] == "evidence_supported_signal"
    assert row["risk_signal_count"] == 1
    assert row["attention_score"] is not None
    assert row["evidence_ids"] == ["supplier-risk"]


def test_actor_name_is_not_reclassified_as_a_supplier() -> None:
    event = _event(
        "actor-signal",
        title="Supply-chain campaign attributed in public reporting",
        actor="Threat Group Z",
        evidence_status=EvidenceStatus.VALIDATED,
    )

    result = build_relationship_risk_intelligence([event], _organization())
    names = {row["name"] for row in result["third_party"]["rows"]}

    assert "Threat Group Z" not in names


def test_domain_abuse_uses_only_observed_hosts_and_excludes_scope_subdomains() -> None:
    events = [
        _event(
            "lookalike",
            title="Observed login page",
            host="examp1e.invalid",
            evidence_status=EvidenceStatus.RELATED,
        ),
        _event(
            "owned-subdomain",
            title="Owned help portal",
            host="help.example.com",
            evidence_status=EvidenceStatus.VALIDATED,
        ),
    ]

    result = build_relationship_risk_intelligence(events, _organization())
    rows = result["domain_abuse"]["rows"]

    assert result["domain_abuse"]["generation_policy"] == "observed_only_no_generated_domains"
    assert [row["candidate_domain"] for row in rows] == ["examp1e.invalid"]
    assert rows[0]["malicious_intent_confirmed"] is False


def test_domain_abuse_collapses_scope_subdomains_and_keeps_only_best_target() -> None:
    organization = _organization().model_copy(
        update={
            "primary_domains": [
                "example.com",
                "help.example.com",
                "jobs.example.com",
                "loyalty.example.invalid",
            ]
        }
    )
    event = _event(
        "single-candidate",
        host="examp1e.invalid",
        evidence_url="https://evidence.example/single-candidate",
    )

    result = build_relationship_risk_intelligence([event], organization)
    rows = result["domain_abuse"]["rows"]

    assert result["domain_abuse"]["candidate_count"] == 1
    assert [(row["candidate_domain"], row["target_domain"]) for row in rows] == [
        ("examp1e.invalid", "example.com")
    ]


def test_domain_abuse_keeps_valid_evidence_urls_and_rejects_malformed_values() -> None:
    events = [
        _event(
            "valid-url",
            host="examp1e.invalid",
            evidence_url="https://urlscan.io/result/valid-reference/",
        ),
        _event(
            "malformed-url",
            host="examp1e.invalid",
            evidence_url="https://capacidad de inteligencia pública/result/broken/",
        ),
    ]

    row = build_relationship_risk_intelligence(events, _organization())["domain_abuse"]["rows"][0]

    assert row["urls"] == ["https://urlscan.io/result/valid-reference/"]


def test_domain_abuse_collapses_observed_subdomains_to_one_candidate_root() -> None:
    events = [
        _event(
            "candidate-root",
            host="insurance.examp1e.invalid",
            evidence_url="https://evidence.example/candidate-root",
        ),
        _event(
            "candidate-nested",
            host="login.beta.examp1e.invalid",
            evidence_url="https://evidence.example/candidate-nested",
        ),
    ]

    rows = build_relationship_risk_intelligence(events, _organization())["domain_abuse"]["rows"]

    assert len(rows) == 1
    assert rows[0]["candidate_domain"] == "examp1e.invalid"
    assert rows[0]["observed_hosts"] == [
        "insurance.examp1e.invalid",
        "login.beta.examp1e.invalid",
    ]
    assert rows[0]["record_count"] == 2


def test_domain_abuse_rejects_weak_unrelated_domains() -> None:
    event = _event("unrelated", host="google.com")

    result = build_relationship_risk_intelligence([event], _organization())

    assert result["domain_abuse"]["candidate_count"] == 0
    assert result["domain_abuse"]["rows"] == []


def test_domain_abuse_exposes_only_observed_public_registration_metadata() -> None:
    event = _event(
        "lookalike-metadata",
        host="examp1e.invalid",
        first_seen="2026-08-20T12:00:00Z",
        last_seen="2026-08-21T12:00:00Z",
        technical_validation={
            "resolved_ips": ["8.8.8.8", "127.0.0.1"],
            "country": "Colombia",
            "city": "Bogota",
            "registrar": "Example Registrar",
            "registrant_organization": "Public Example Holder",
            "creation_date": "2026-01-02",
        },
    )

    row = build_relationship_risk_intelligence([event], _organization())["domain_abuse"]["rows"][0]
    observation = row["observation"]

    assert observation["ip_addresses"] == ["8.8.8.8"]
    assert observation["countries"] == ["Colombia"]
    assert observation["cities"] == ["Bogota"]
    assert observation["registrars"] == ["Example Registrar"]
    assert observation["registrants"] == ["Public Example Holder"]
    assert observation["created_at"] == ["2026-01-02"]
    assert observation["first_seen"] == ["2026-08-20T12:00:00Z"]


def test_declared_competitor_never_becomes_technical_risk_by_declaration() -> None:
    result = build_relationship_risk_intelligence([], _organization())
    row = result["competitive_context"]["rows"][0]

    assert row["name"] == "Market Peer"
    assert row["risk_effect"] == "none_by_declaration"
    assert row["status"] == "declared_no_evidence"
