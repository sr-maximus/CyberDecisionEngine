from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def age_days(value: Optional[str]) -> int:
    parsed = parse_date(value)
    if parsed is None:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, (now_utc() - parsed).days)
