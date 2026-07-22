from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from cyberdeck.analysis.strategic_news import build_strategic_intelligence
from cyberdeck.schemas import OrganizationProfile, ThreatEvent


def build_pestel(
    events: Sequence[ThreatEvent],
    country: str,
    business_units: Optional[List[str]] = None,
    organization: Optional[OrganizationProfile] = None,
) -> Dict[str, object]:
    """Compatibility entry point for the evidence-based strategic engine."""
    profile = organization or OrganizationProfile(
        name="Undeclared organization",
        sector="",
        country=country,
        author="CyberDecisionEngine",
        business_units=business_units or [],
    )
    return build_strategic_intelligence(events, profile)["pestel"]
