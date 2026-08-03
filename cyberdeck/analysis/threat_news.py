from __future__ import annotations

import re
from typing import Any, Iterable

from cyberdeck.schemas import EvidenceStatus, ThreatEvent


MODEL_VERSION = "threat-news-attribution-v1.0.0"

_CYBER_ACTION = re.compile(
    r"\b(ransomware|malware|phish\w*|breach|intrusion|exploit\w*|vulnerab\w*|cve-\d+|"
    r"attack|ataque|extortion|filtraci\w*|credential\w*|"
    r"suplant\w*|imperson\w*|fraud\w*|estafa\w*|scam\w*|botnet|ddos)\b",
    re.IGNORECASE,
)
_ATTRIBUTION = re.compile(
    r"\b(?:apt[- ]?\d+|fin\d+|unc\d+|uat[- ]?\d+|ta\d+|lazarus|scattered spider|lockbit|cl0p|akira|black basta|"
    r"ransomhouse|play ransomware|threat actor|actor de amenazas|grupo de ransomware|"
    r"grupo cibernetico|grupo cibernético)\b",
    re.IGNORECASE,
)
_BUSINESS_ONLY = re.compile(
    r"\b(acquisition|adquisicion|merger|sustainab|sostenibil|financial results|resultados financieros|"
    r"dividend|produccion|production|earnings|inversion)\b",
    re.IGNORECASE,
)


def build_threat_news(events: Iterable[ThreatEvent]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        if not event.evidence_url or event.evidence_url in seen:
            continue
        if event.evidence_status in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}:
            continue
        text = " ".join([event.title, event.category, event.actor or "", " ".join(event.tags)])
        has_action = bool(_CYBER_ACTION.search(text))
        actor_match = _ATTRIBUTION.search(text)
        has_actor = bool(
            (
                event.actor
                and event.actor.casefold()
                not in {"unattributed", "unknown", "sin atribución", "no atribuido", "open_web", "public_web"}
            )
            or actor_match
            or any(tag.casefold() in {"threat_actor", "actor_attribution"} for tag in event.tags)
        )
        if not has_action or not has_actor:
            continue
        if _BUSINESS_ONLY.search(text) and not _CYBER_ACTION.search(event.title):
            continue
        relationship = str(event.relationship_to_scope or "unassessed")
        if relationship not in {"direct", "group", "sector", "related", "contextual"}:
            continue
        seen.add(event.evidence_url)
        status = str(getattr(event.evidence_status, "value", event.evidence_status))
        rows.append(
            {
                "evidence_id": str(event.canonical_id or event.id),
                "title": event.title,
                "url": event.evidence_url,
                "source": event.source,
                "observed_at": event.observed_at,
                "actor": (
                    event.actor
                    if event.actor
                    and event.actor.casefold()
                    not in {"unattributed", "unknown", "sin atribución", "no atribuido", "open_web", "public_web"}
                    else actor_match.group(0) if actor_match else "unattributed"
                ),
                "technique": event.technique,
                "relationship": relationship,
                "evidence_status": status,
                "classification": "attributed_threat_or_campaign",
                "observed_attack": bool(event.incident_confirmed and status == "confirmed"),
            }
        )
    rows.sort(key=lambda item: item["observed_at"], reverse=True)
    return {
        "model_version": MODEL_VERSION,
        "status": "evidence_backed" if rows else "no_data",
        "record_count": len(rows),
        "validated_count": sum(item["evidence_status"] in {"validated", "confirmed"} for item in rows),
        "rows": rows[:40],
        "limitations": [
            "La inclusión exige una acción cibernética y una atribución explícita de actor o campaña.",
            "Una noticia atribuida no confirma que la organización analizada haya sufrido un incidente.",
            "Ataque observado solo se utiliza cuando existe incidente confirmado y evidencia confirmada.",
        ],
    }
