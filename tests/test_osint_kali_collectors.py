from cyberdeck.collectors.kali_surface import _events_from_payload as kali_events_from_payload
from cyberdeck.collectors.osint_tools import _events_from_payload as osint_events_from_payload
from cyberdeck.collectors.spiderfoot import _events_from_payload as spiderfoot_events_from_payload
from cyberdeck.cli import _collector_timeout_budget
from cyberdeck.cli import _build_general_findings
from cyberdeck.enrichment.evidence_pipeline import process_evidence_records
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile


class _FakeCollector:
    def __init__(self, name, timeout_seconds=80, collection_timeout_seconds=180, domains=None):
        self.name = name
        self.timeout_seconds = timeout_seconds
        self.collection_timeout_seconds = collection_timeout_seconds
        self.domains = domains or []


def test_osint_tools_payload_to_events():
    events = osint_events_from_payload(
        {
            "results": [
                {
                    "url": "https://x.com/grupoaval",
                    "target": "grupoaval",
                    "platform": "x.com",
                    "confidence": 0.7,
                    "metadata": {"username": "grupoaval", "links": ["https://grupoaval.com"]},
                }
            ]
        },
        5,
    )

    assert events[0].source == "Evidencia publica de perfil"
    assert events[0].category == "social_signal"
    assert events[0].evidence_url == "https://x.com/grupoaval"
    assert "profile_enriched" in events[0].tags


def test_kali_surface_payload_to_events():
    events = kali_events_from_payload(
        {
            "domains": [
                {
                    "domain": "example.com",
                    "subdomains": ["www.example.com"],
                    "web_assets": [
                        {
                            "url": "https://www.example.com",
                            "host": "www.example.com",
                            "status_code": 200,
                            "technologies": ["nginx"],
                        }
                    ],
                    "findings": [
                        {
                            "type": "email_security",
                            "severity": "high",
                            "title": "DMARC no observado",
                            "asset": "_dmarc.example.com",
                            "tool": "dig",
                        }
                    ],
                }
            ]
        },
        10,
    )

    categories = {event.category for event in events}
    assert {"attack_surface", "attack_surface_web", "attack_surface_dns"}.issubset(categories)
    assert all(event.demo is False for event in events)
    assert all("Kali" not in event.source for event in events)
    assert all("tool:" not in " ".join(event.tags) for event in events)


def test_dns_only_admin_subdomain_requires_validation_and_has_no_fake_url():
    events = kali_events_from_payload(
        {
            "domains": [
                {
                    "domain": "puertobahia.com.co",
                    "subdomains": ["admin.mastest.puertobahia.com.co"],
                    "web_assets": [],
                    "findings": [],
                }
            ]
        },
        5,
    )

    event = events[0]
    assert event.category == "attack_surface_dns"
    assert event.evidence_url is None
    assert "dns_inventory_only" in event.tags
    assert "validation_required" in event.tags
    assert "nombre sensible" in event.title


def test_confirmed_missing_dmarc_becomes_validated_low_risk_finding():
    events = kali_events_from_payload(
        {
            "domains": [
                {
                    "domain": "example.com",
                    "subdomains": ["example.com"],
                    "web_assets": [],
                    "findings": [
                        {
                            "type": "email_security",
                            "severity": "medium",
                            "title": "DMARC no observado",
                            "asset": "_dmarc.example.com",
                            "validation": {
                                "query_performed": "TXT _dmarc.example.com",
                                "resolver_used": "system resolver via dig",
                                "raw_response": [],
                                "record_found": False,
                                "validation_result": "confirmed_missing",
                                "mx_observed": True,
                            },
                        }
                    ],
                }
            ]
        },
        5,
    )
    processed = process_evidence_records(events, ["example.com"]).records
    organization = OrganizationProfile(
        name="Example",
        sector="",
        country="",
        author="test",
        authorized_scope=True,
        primary_domains=["example.com"],
    )
    findings = _build_general_findings(processed, organization)

    assert processed[0].evidence_status == EvidenceStatus.VALIDATED
    assert len(findings) == 1
    assert findings[0].residual_risk < 10
    assert findings[0].incident_confirmed is False


def test_spiderfoot_payload_to_events_uses_real_records_only():
    events = spiderfoot_events_from_payload(
        {
            "domains": [
                {
                    "domain": "example.com",
                    "records": [
                        {
                            "type": "Internet Name",
                            "data": "example.com",
                            "module": "sfp_dnsresolve",
                            "source": "example.com",
                        },
                        {
                            "type": "URL",
                            "data": "https://www.example.com/login",
                            "module": "sfp_spider",
                            "source": "https://www.example.com",
                        },
                        {
                            "type": "Raw Data from RIRs/APIs",
                            "data": "{large raw object}",
                            "module": "sfp_arin",
                            "source": "example.com",
                        },
                    ],
                }
            ]
        },
        10,
    )

    assert len(events) == 2
    assert {event.category for event in events} == {"attack_surface_dns", "attack_surface_web"}
    assert events[1].evidence_url == "https://www.example.com/login"
    assert all(event.demo is False for event in events)


def test_visible_source_names_keep_special_timeout_budgets():
    assert _collector_timeout_budget(_FakeCollector("Busqueda publica")) >= 200
    assert _collector_timeout_budget(_FakeCollector("Correlacion OSINT")) >= 100
    assert _collector_timeout_budget(_FakeCollector("Superficie externa")) >= 90
    assert _collector_timeout_budget(_FakeCollector("Inventario pasivo", domains=["a.com", "b.com", "c.com"])) >= 180
