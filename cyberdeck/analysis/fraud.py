from __future__ import annotations

from typing import Dict, Iterable, List

from cyberdeck.analysis.risk_engine import business_impact, contextual_likelihood, control_effectiveness, inherent_risk, matrix_4x4, residual_risk, threat_activity_score
from cyberdeck.schemas import EvidenceStatus, RiskFinding, ThreatEvent
from cyberdeck.utils.scoring import clamp


FRAUD_CONTROL_WEIGHTS = {
    "identity_proofing": 0.18,
    "transaction_monitoring": 0.20,
    "device_intelligence": 0.16,
    "mule_detection": 0.16,
    "case_management": 0.15,
    "customer_awareness": 0.15,
}


FRAUD_REFERENCE_NOTES = [
    "Fraud analytics uses statistical anomaly detection and supervised learning where labels exist.",
    "Cyber-enabled fraud must join identity, device, transaction, behavioral and threat-intel signals.",
    "Operational metrics must include losses avoided, detection latency, false positives and case throughput.",
]


def fraud_control_maturity(values: Dict[str, float]) -> float:
    return clamp(sum(clamp(values.get(name, 0.0)) * weight for name, weight in FRAUD_CONTROL_WEIGHTS.items()))


def fraud_pressure_index(events: Iterable[ThreatEvent]) -> float:
    fraud_events = [
        {
            "source_weight": event.source_weight,
            "confidence": event.confidence,
            "age_days": event.age_days,
            "half_life": 14,
        }
        for event in events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        and (
            {"fraud", "brand_impersonation", "fake_domain", "fake_recruitment", "disinformation"}.intersection(
                {tag.lower() for tag in event.tags}
            )
            or event.category in {"fraud", "phishing", "account_takeover", "brand_impersonation", "fake_domain", "fake_recruitment"}
        )
    ]
    return threat_activity_score(fraud_events)


def build_fraud_findings(events: List[ThreatEvent], fraud_maturity: Dict[str, float], control_maturity: Dict[str, float], real_only: bool = False) -> List[RiskFinding]:
    fraud_source_events = [
        event
        for event in events
        if not event.demo
        and event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        and (
            {"fraud", "brand_impersonation", "fake_domain", "fake_recruitment", "disinformation"}.intersection(
                {tag.lower() for tag in event.tags}
            )
            or event.category
            in {
                "fraud",
                "phishing",
                "account_takeover",
                "transaction_fraud",
                "business_email_compromise",
                "brand_impersonation",
                "fake_domain",
                "fake_recruitment",
            }
        )
    ]
    if not fraud_source_events:
        return []
    pressure = fraud_pressure_index(events)
    maturity = fraud_control_maturity(fraud_maturity) if fraud_maturity else 0.0
    ce = control_effectiveness(
        iso=control_maturity.get("iso27001_score", 0.0),
        nist=control_maturity.get("nist_csf_score", 0.0),
        soc2=control_maturity.get("soc2_score", 0.0),
        d3fend=control_maturity.get("d3fend_coverage", 0.0),
        attack_detection=control_maturity.get("attack_detection_coverage", 0.0),
        ir=control_maturity.get("incident_response_maturity", 0.0),
    )
    ce = clamp((ce * 0.65) + (maturity * 0.35))
    findings: List[RiskFinding] = []
    scenarios = [
        (
            "Phishing, smishing y suplantacion de marca contra clientes",
            "fraud",
            0.72,
            ["DMARC, SPF, DKIM y monitoreo de dominios lookalike", "Campanas de awareness por segmentos", "Takedown coordinado con legal y proveedores"],
            "Fraude",
        ),
        (
            "Account takeover con credenciales filtradas o session hijacking",
            "account_takeover",
            0.78,
            ["Autenticacion resistente a phishing", "Analitica de device fingerprint y impossible travel", "Step-up authentication por riesgo"],
            "Fraude",
        ),
        (
            "Mule accounts y dispersion transaccional anomala",
            "transaction_fraud",
            0.68,
            ["Graph analytics de beneficiarios", "Velocity rules por canal y dispositivo", "Orquestacion de casos con retroalimentacion del SOC"],
            "Fraude",
        ),
        (
            "BEC y pagos no autorizados por ingenieria social",
            "business_email_compromise",
            0.74,
            ["Verificacion fuera de banda de cambios de cuenta", "Controles duales para pagos criticos", "Monitoreo de reglas sospechosas de correo"],
            "Tesoreria/Fraude",
        ),
        (
            "Suplantación de marca, dominios similares y ofertas laborales falsas",
            "brand_reputation_fraud",
            0.64,
            [
                "Validar y documentar perfiles, anuncios y dominios que suplanten a la organización",
                "Publicar canales oficiales de contratación y comunicación",
                "Coordinar preservación de evidencia y solicitudes de retiro con legal y plataformas",
            ],
            "Marca/Comunicaciones/Legal",
        ),
    ]
    for title, category, base_exposure, recommendations, owner in scenarios:
        category_terms = {
            "fraud": {"fraud", "phishing", "brand_impersonation", "social_signal"},
            "account_takeover": {"account_takeover", "credential_exposure"},
            "transaction_fraud": {"transaction_fraud", "mule_account"},
            "business_email_compromise": {"business_email_compromise", "bec"},
            "brand_reputation_fraud": {
                "brand_impersonation",
                "fake_domain",
                "fake_recruitment",
                "disinformation",
                "fraud",
            },
        }[category]
        related_events = [
            event
            for event in fraud_source_events
            if event.category in category_terms or category_terms.intersection({tag.lower() for tag in event.tags})
        ]
        if not related_events:
            continue
        likelihood = contextual_likelihood(
            A=min(1.0, 0.35 + 0.1 * len(related_events)),
            E=base_exposure,
            V=0.45,
            P=0.35 + pressure * 0.45,
            K=0.0,
            T=pressure,
            S=0.85,
            G=0.55,
            data_sufficiency=max(event.confidence_score for event in related_events),
            base_rate=0.10,
        )
        impact = business_impact(
            financial=0.86,
            operational=0.62,
            confidentiality=0.66,
            integrity=0.78,
            availability=0.36,
            legal=0.72,
            reputational=0.84,
        )
        inherent = inherent_risk(likelihood, impact)
        residual = residual_risk(inherent, ce)
        matrix = matrix_4x4(likelihood, impact)
        findings.append(
            RiskFinding(
                title=title,
                category=category,
                likelihood=round(likelihood, 4),
                impact=round(impact, 4),
                inherent_risk=round(inherent, 2),
                residual_risk=round(residual, 2),
                matrix_score=int(matrix["matrix_score"]),
                matrix_label=str(matrix["label"]),
                evidence=_fraud_evidence(related_events, pressure, maturity),
                recommendations=recommendations,
                owner=owner,
                demo=False,
                linked_evidence_ids=[event.canonical_id or event.id for event in related_events],
                confidence_score=max(event.confidence_score for event in related_events),
                likelihood_inputs={
                    "activity": min(1.0, 0.35 + 0.1 * len(related_events)),
                    "exposure": base_exposure,
                    "signal_pressure": pressure,
                    "data_sufficiency": max(event.confidence_score for event in related_events),
                },
                impact_inputs={"financial": 0.86, "operational": 0.62, "reputational": 0.84},
                control_inputs={"declared_control_effectiveness": ce},
                assumptions=["La aplicabilidad depende de que la evidencia enlazada sea confirmada por el propietario."],
                validation_method="public_evidence_correlation",
            )
        )
    return findings


def _fraud_evidence(events: List[ThreatEvent], pressure: float, maturity: float) -> List[str]:
    urls = [event.evidence_url for event in events if event.evidence_url]
    if urls:
        return [
            "Senales reales de fuentes publicas gratuitas: " + ", ".join(urls[:4]),
            f"FraudPressureIndex={pressure:.2f}; FraudControlMaturity={maturity:.2f}",
        ]
    return [
        "Fuentes metodologicas: FBI IC3, ENISA Finance Threat Landscape, ACFE y NIST SP 800-63-4.",
        f"FraudPressureIndex={pressure:.2f}; FraudControlMaturity={maturity:.2f}",
    ]
