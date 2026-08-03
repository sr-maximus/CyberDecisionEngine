from __future__ import annotations

import asyncio
from html import unescape
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck.utils.dates import age_days
from cyberdeck.utils.http import HttpClient
from cyberdeck.utils.text import extract_cves


FRAUD_TERMS = ("fraud", "phishing", "smishing", "vishing", "bec", "account takeover", "scam", "spoof", "identity theft", "text scam", "impersonat")
THREAT_ACTORS = (
    "APT28",
    "APT29",
    "APT41",
    "Akira",
    "BlackCat",
    "Clop",
    "FIN7",
    "Lazarus",
    "LockBit",
    "RansomHub",
    "Scattered Spider",
    "Salt Typhoon",
    "TA505",
    "Volt Typhoon",
)


class RssCollector(Collector):
    name = "RSS CTI"

    def __init__(self, feeds: List[Dict[str, str]]):
        self.feeds = feeds
        self.http = HttpClient()

    async def collect(self) -> CollectionResult:
        events: List[ThreatEvent] = []
        warnings: List[str] = []

        async def fetch(feed: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str], Optional[Exception]]:
            try:
                xml_text = await self.http.get_text(feed["url"])
                return feed, xml_text, None
            except Exception as exc:
                return feed, None, exc

        results = await asyncio.gather(*(fetch(feed) for feed in self.feeds[:24]))
        for feed, xml_text, error in results:
            if error is not None or xml_text is None:
                warnings.append(f"{feed.get('name', feed.get('url'))}: {error}")
                continue
            events.extend(
                _parse_rss(
                    feed.get("name", "RSS"),
                    feed["url"],
                    xml_text,
                    metadata=feed,
                    max_items=max(1, min(20, int(feed.get("max_items", 12) or 12))),
                )
            )
        if not events:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="; ".join(warnings)), [])
        status = "partial" if warnings else "ok"
        return CollectionResult(SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None), events[:300])


def _parse_rss(
    source_name: str,
    source_url: str,
    xml_text: str,
    *,
    metadata: Optional[Dict[str, Any]] = None,
    max_items: int = 20,
) -> List[ThreatEvent]:
    metadata = metadata or {}
    feed_type = str(metadata.get("feed_type") or "cti").strip().lower()
    context_topics = [str(topic).strip().lower() for topic in metadata.get("context_topics", []) if str(topic).strip()]
    root = ET.fromstring(xml_text)
    items = root.findall(".//item")
    if not items:
        namespace = "{http://www.w3.org/2005/Atom}"
        items = root.findall(f".//{namespace}entry")
    events: List[ThreatEvent] = []
    for index, item in enumerate(items[:max_items]):
        title = item.findtext("title") or item.findtext("{http://www.w3.org/2005/Atom}title") or "Untitled feed item"
        description = item.findtext("description") or item.findtext("summary") or item.findtext("{http://www.w3.org/2005/Atom}summary") or ""
        summary = _plain_text(description)
        link = item.findtext("link") or source_url
        if link == source_url:
            atom_link = item.find("{http://www.w3.org/2005/Atom}link")
            if atom_link is not None:
                link = atom_link.attrib.get("href", source_url)
        pub_date = item.findtext("pubDate") or item.findtext("published") or item.findtext("{http://www.w3.org/2005/Atom}published") or item.findtext("{http://www.w3.org/2005/Atom}updated")
        text = f"{title} {summary}"
        cves = extract_cves(text)
        lowered = text.lower()
        category = (
            "phishing"
            if any(term in lowered for term in FRAUD_TERMS)
            else "strategic_news"
            if feed_type == "strategic"
            else "threat_intel"
        )
        tags = ["rss", f"feed_type:{feed_type}"]
        if feed_type == "strategic":
            tags.extend(["strategic_context", *[f"context:{topic}" for topic in context_topics]])
        if category == "phishing":
            tags.extend(["fraud", "social_engineering"])
        if cves:
            tags.append("cve")
        events.append(
            ThreatEvent(
                id=f"RSS-{source_name}-{index}",
                title=title[:240],
                category=category,
                source=source_name,
                source_weight=float(metadata.get("source_weight", 0.65) or 0.65),
                confidence=float(metadata.get("confidence", 0.58) or 0.58),
                age_days=age_days(pub_date),
                severity=0.58,
                epss=0.0,
                cvss=0.0,
                cve=cves[0] if cves else None,
                actor=_detect_actor(text),
                technique="T1566" if category == "phishing" else None,
                tags=tags,
                evidence_url=link,
                demo=False,
                technical_validation={
                    "feed_url": source_url,
                    "published_at": pub_date,
                    "classification": "contextual",
                    "feed_type": feed_type,
                    "context_topics": context_topics,
                    "summary": summary[:1200],
                },
            )
        )
    return events


def _detect_actor(text: str) -> str:
    lowered = text.lower()
    for actor in THREAT_ACTORS:
        if actor.lower() in lowered:
            return actor
    match = re.search(r"\b(?:APT|FIN|UNC|UAT|TA)[- ]?\d{2,6}\b", text, flags=re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return "unattributed"


def _plain_text(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", unescape(value or ""))
    return re.sub(r"\s+", " ", without_tags).strip()
