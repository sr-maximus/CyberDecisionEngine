from __future__ import annotations


def sector_keywords(sector: str) -> list[str]:
    if sector.lower() in {"financial", "banking", "fintech"}:
        return ["bank", "payment", "card", "swift", "fintech", "fraud", "phishing", "mule", "account takeover"]
    return [sector.lower()]
