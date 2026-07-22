from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List

from cyberdeck.schemas import EvidenceStatus, RiskFinding, ThreatEvent


RISK_TYPES = [
    ("Vulnerabilidades explotables", "vulnerability", "Priorizar KEV/EPSS, exposicion externa y activos criticos."),
    ("Fraude e ingenieria social", "fraud", "Ajustar controles de identidad, monitoreo transaccional y takedown."),
    ("Identidad y accesos", "identity", "Reforzar MFA resistente a phishing, PAM, deteccion de valid accounts."),
    ("Ransomware y continuidad", "ransomware", "Validar backups, segmentacion, EDR/NDR y ejercicios de crisis."),
    ("Cloud, APIs y DevSecOps", "cloud_api", "Revisar API security, secretos, SCA/SBOM, CI/CD y CSPM."),
    ("Terceros y cadena de suministro", "third_party", "Monitorear proveedores, contratos, SBOM y resiliencia operacional."),
    ("Datos, privacidad y regulacion", "data_privacy", "Reducir exposicion de datos, trazabilidad legal y respuesta regulatoria."),
    ("IA, agentes y automatizacion", "ai_automation", "Gobernar prompts, agentes, herramientas, logs y decisiones automatizadas."),
]


def build_cyber_risk_radar(events: Iterable[ThreatEvent], findings: Iterable[RiskFinding]) -> Dict[str, object]:
    event_list = [
        event
        for event in events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    finding_list = list(findings)
    rows = []
    for index, (name, key, decision) in enumerate(RISK_TYPES, start=1):
        evidence_count = _evidence_count(key, event_list)
        residual = max((finding.residual_risk for finding in finding_list if _finding_matches(key, finding)), default=0.0)
        trend = min(1.0, evidence_count / 18)
        score = min(1.0, (residual / 45) * 0.58 + trend * 0.42)
        rows.append(
            {
                "index": index,
                "name": name,
                "key": key,
                "score": round(score, 3),
                "heat": _heat(score),
                "evidence_count": evidence_count,
                "max_residual_risk": round(residual, 2),
                "decision": decision,
                "signals": _signals(key, event_list),
            }
        )
    return {
        "purpose": "Radar-calor propio para decision ejecutiva: combina intensidad de evidencia, riesgo residual y tendencia por tipo de ciberriesgo. Sirve para ver donde anticiparse, donde invertir y que area debe actuar primero.",
        "how_to_read": "Cada sector numerado representa un tipo de ciberriesgo. El color va de verde a rojo segun calor; el radio representa intensidad. La tabla explica la decision recomendada y las senales que originaron el puntaje.",
        "rows": rows,
    }


def _evidence_count(key: str, events: List[ThreatEvent]) -> int:
    return sum(1 for event in events if _event_matches(key, event))


def _event_matches(key: str, event: ThreatEvent) -> bool:
    text = " ".join([event.category, event.title, event.technique or "", " ".join(event.tags)]).lower()
    if key == "vulnerability":
        return event.vulnerability_status in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"}
    if key == "fraud":
        return any(term in text for term in ["fraud", "phishing", "smishing", "vishing", "bec", "scam", "impersonat"])
    if key == "identity":
        return any(term in text for term in ["identity", "valid accounts", "credential", "mfa", "account_takeover", "t1078"])
    if key == "ransomware":
        return any(term in text for term in ["ransomware", "darkweb_ransomware", "darkweb_index", "tor_onion", "ransomhub", "lockbit", "blackcat", "ransomware_signal"])
    if key == "cloud_api":
        return any(term in text for term in ["cloud", "api", "container", "kubernetes", "github", "dependency", "open_source"])
    if key == "third_party":
        return any(term in text for term in ["third_party", "supplier", "vendor", "dependency", "github_advisory", "supply"])
    if key == "data_privacy":
        return any(term in text for term in ["data", "privacy", "confidentiality", "exfiltration", "leak"])
    if key == "ai_automation":
        return any(term in text for term in [" ai ", "model", "agent", "automation", "prompt", "llm"])
    return False


def _finding_matches(key: str, finding: RiskFinding) -> bool:
    text = " ".join([finding.category, finding.title]).lower()
    if key == "vulnerability":
        return "vulnerab" in text or "cve" in text
    if key == "fraud":
        return any(
            term in text
            for term in ["fraud", "phishing", "bec", "account takeover", "mule", "dmarc", "spf", "dkim"]
        )
    if key == "identity":
        return any(
            term in text
            for term in ["identity", "credential", "account takeover", "valid account", "dmarc", "spf", "dkim"]
        )
    if key == "ransomware":
        return "ransom" in text
    if key == "cloud_api":
        return any(term in text for term in ["cloud", "api", "github", "dependency"])
    if key == "third_party":
        return any(term in text for term in ["third", "supplier", "provider", "dependency"])
    if key == "data_privacy":
        return any(term in text for term in ["data", "privacy", "confidential"])
    if key == "ai_automation":
        return any(term in text for term in ["ai_security", "artificial intelligence", "llm", "prompt", "model exposure", "agentic"])
    return False


def _signals(key: str, events: List[ThreatEvent]) -> List[str]:
    counter = Counter()
    for event in events:
        if _event_matches(key, event):
            counter[event.source] += 1
    return [f"{source}: {count}" for source, count in counter.most_common(4)]


def _heat(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.55:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"
