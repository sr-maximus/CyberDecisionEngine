from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List

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
        for feed in self.feeds[:12]:
            try:
                xml_text = await self.http.get_text(feed["url"])
                events.extend(_parse_rss(feed.get("name", "RSS"), feed["url"], xml_text))
            except Exception as exc:
                warnings.append(f"{feed.get('name', feed.get('url'))}: {exc}")
        if not events:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="; ".join(warnings)), [])
        status = "partial" if warnings else "ok"
        return CollectionResult(SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None), events[:120])


def _parse_rss(source_name: str, source_url: str, xml_text: str) -> List[ThreatEvent]:
    root = ET.fromstring(xml_text)
    items = root.findall(".//item")
    if not items:
        namespace = "{http://www.w3.org/2005/Atom}"
        items = root.findall(f".//{namespace}entry")
    events: List[ThreatEvent] = []
    for index, item in enumerate(items[:20]):
        title = item.findtext("title") or item.findtext("{http://www.w3.org/2005/Atom}title") or "Untitled feed item"
        description = item.findtext("description") or item.findtext("summary") or item.findtext("{http://www.w3.org/2005/Atom}summary") or ""
        link = item.findtext("link") or source_url
        if link == source_url:
            atom_link = item.find("{http://www.w3.org/2005/Atom}link")
            if atom_link is not None:
                link = atom_link.attrib.get("href", source_url)
        pub_date = item.findtext("pubDate") or item.findtext("published") or item.findtext("{http://www.w3.org/2005/Atom}published") or item.findtext("{http://www.w3.org/2005/Atom}updated")
        text = f"{title} {description}"
        cves = extract_cves(text)
        lowered = text.lower()
        category = "phishing" if any(term in lowered for term in FRAUD_TERMS) else "threat_intel"
        tags = ["rss"]
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
                source_weight=0.65,
                confidence=0.58,
                age_days=age_days(pub_date),
                severity=0.58,
                epss=0.05,
                cvss=6.0,
                cve=cves[0] if cves else None,
                actor=_detect_actor(text),
                technique="T1566" if category == "phishing" else "T1595",
                tags=tags,
                evidence_url=link,
                demo=False,
            )
        )
    return events


def _detect_actor(text: str) -> str:
    lowered = text.lower()
    for actor in THREAT_ACTORS:
        if actor.lower() in lowered:
            return actor
    return "unattributed"
