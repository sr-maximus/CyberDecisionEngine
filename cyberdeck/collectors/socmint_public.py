from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import unicodedata
from typing import Iterable, List, Optional
from xml.etree import ElementTree as ET

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class SocmintPublicCollector(Collector):
    name = "SOCMINT Public"

    def __init__(self, keywords: Iterable[str], enabled: bool = True, real_only: bool = True, max_records: int = 10, max_queries: int = 5):
        self.keywords = [keyword for keyword in keywords if keyword]
        self.enabled = enabled
        self.real_only = real_only
        self.max_records = max(1, int(max_records))
        self.max_queries = max(1, int(max_queries))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.keywords:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No SOCMINT keywords configured."), [])
        events: List[ThreatEvent] = []
        seen: set[str] = set()
        warnings: List[str] = []
        async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "CyberDecisionEngine/1.0 by Edwin Penuela"}) as client:
            for query in self.keywords[: self.max_queries]:
                if len(events) >= self.max_records:
                    break
                try:
                    response = await client.get(
                        "https://www.reddit.com/search.rss",
                        params={"q": query, "sort": "new", "t": "year", "limit": min(10, self.max_records)},
                    )
                    if response.status_code == 429:
                        warnings.append(f"Reddit rate limit for query: {query}")
                    else:
                        response.raise_for_status()
                        _extend_unique(events, _parse_reddit(query, response.text, self.max_records - len(events)), seen, self.max_records)
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"Reddit {query}: {exc}")
                if len(events) >= self.max_records:
                    break
                try:
                    response = await client.get(
                        "https://hn.algolia.com/api/v1/search_by_date",
                        params={"query": query, "tags": "story", "hitsPerPage": min(10, self.max_records - len(events))},
                    )
                    response.raise_for_status()
                    _extend_unique(events, _parse_hacker_news_public(query, response.json(), self.max_records - len(events)), seen, self.max_records)
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"Hacker News {query}: {exc}")
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        if not events and not warnings:
            warnings.append("No public SOCMINT matches for configured keywords.")
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None),
            events,
        )


def _parse_reddit(query: str, xml_text: str, limit: int) -> List[ThreatEvent]:
    root = ET.fromstring(xml_text)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    events: List[ThreatEvent] = []
    for index, entry in enumerate(root.findall("atom:entry", ns)):
        if len(events) >= limit:
            break
        title = entry.findtext("atom:title", default="Reddit public search result", namespaces=ns)
        updated = entry.findtext("atom:updated", namespaces=ns)
        content = entry.findtext("atom:content", default="", namespaces=ns)
        link_node = entry.find("atom:link[@rel='alternate']", ns)
        if link_node is None:
            link_node = entry.find("atom:link", ns)
        link = link_node.attrib.get("href") if link_node is not None else None
        if not _matches_query(query, f"{title} {content} {link or ''}"):
            continue
        category, tags, technique = _classify(title, query)
        events.append(
            ThreatEvent(
                id=f"SOCMINT-REDDIT-{abs(hash((query, title, index))) % 10_000_000}",
                title=f"{title} | query: {query}",
                category=category,
                source="SOCMINT Public: Reddit RSS",
                source_weight=0.44,
                confidence=0.42,
                age_days=_age_days(updated),
                severity=0.48 if category == "social_signal" else 0.60,
                epss=0.02,
                cvss=0.0,
                actor="public_social_signal",
                technique=technique,
                tags=["socmint_public", "reddit_rss", *tags],
                evidence_url=link,
                observed_at=_date_or_now(updated),
                demo=False,
            )
        )
    return events


def _parse_hacker_news_public(query: str, payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, hit in enumerate(payload.get("hits", [])[:limit]):
        title = hit.get("title") or hit.get("story_title") or "Hacker News public search result"
        link = hit.get("url") or hit.get("story_url")
        text = f"{title} {hit.get('story_text') or ''} {link or ''}"
        if not _matches_query(query, text):
            continue
        updated = hit.get("created_at")
        category, tags, technique = _classify(title, query)
        events.append(
            ThreatEvent(
                id=f"SOCMINT-HN-{abs(hash((query, title, index))) % 10_000_000}",
                title=f"{title} | query: {query}",
                category=category,
                source="SOCMINT Public: Hacker News public index",
                source_weight=0.40,
                confidence=0.38,
                age_days=_age_days(updated),
                severity=0.46 if category == "social_signal" else 0.58,
                epss=0.02,
                cvss=0.0,
                actor="public_discussion_signal",
                technique=technique,
                tags=["socmint_public", "hacker_news_public", *tags],
                evidence_url=link,
                observed_at=_date_or_now(updated),
                demo=False,
            )
        )
    return events


def _extend_unique(events: List[ThreatEvent], candidates: List[ThreatEvent], seen: set[str], max_records: int) -> None:
    for event in candidates:
        key = event.evidence_url or event.title
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if len(events) >= max_records:
            break


def _matches_query(query: str, text: str) -> bool:
    full_query = _norm(query.strip('"'))
    terms = [_norm(term.strip('"')) for term in query.replace(" OR ", " ").split() if len(term.strip('"')) > 3]
    terms = [term for term in terms if term not in {"para", "with", "from"}]
    if not terms:
        return True
    haystack = _norm(text)
    if full_query in haystack:
        return True
    if len(terms) == 2:
        compact = "".join(terms[:2])
        return compact in haystack.replace(" ", "")
    if len(terms) > 2:
        return all(term in haystack for term in terms[:3])
    required = terms[:3]
    return len(required) >= 2 and all(term in haystack for term in required)


def _norm(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.lower())
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def _classify(title: str, query: str) -> tuple[str, List[str], Optional[str]]:
    text = f"{title} {query}".lower()
    if any(term in text for term in ["phishing", "smishing", "vishing", "suplant", "fraude", "estafa", "scam"]):
        return "phishing", ["fraud", "brand_impersonation"], "T1566"
    return "social_signal", ["brand_signal"], None


def _date_or_now(value: Optional[str]) -> str:
    parsed = _parse_date(value)
    return (parsed or datetime.now(timezone.utc)).isoformat()


def _age_days(value: Optional[str]) -> int:
    parsed = _parse_date(value)
    if parsed is None:
        return 0
    return max(0, (datetime.now(timezone.utc) - parsed).days)


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None
