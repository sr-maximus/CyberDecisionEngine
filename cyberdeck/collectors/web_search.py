from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import os
import re
import unicodedata
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class WebSearchCollector(Collector):
    name = "Busqueda publica"

    def __init__(
        self,
        queries: Iterable[str],
        max_records: int = 40,
        enabled: bool = True,
        providers: object = None,
        max_queries: int = 20,
        request_delay_seconds: float = 0.35,
        google_cse_api_key: Optional[str] = None,
        google_cse_cx: Optional[str] = None,
        google_cse_api_key_env: str = "GOOGLE_CSE_API_KEY",
        google_cse_cx_env: str = "GOOGLE_CSE_CX",
        brave_api_key: Optional[str] = None,
        brave_api_key_env: str = "BRAVE_SEARCH_API_KEY",
        timeout_seconds: float = 8.0,
        collection_timeout_seconds: float = 80.0,
        provider_query_limits: Optional[dict] = None,
    ):
        self.queries = [query for query in queries if query]
        # Zero means no fixed result cap. The finite query list, provider
        # backoff and optional collection window still bound each execution.
        self.max_records = max(0, int(max_records))
        self.enabled = enabled
        self.providers = _normalize_providers(providers)
        self.max_queries = max(0, int(max_queries))
        self.request_delay_seconds = max(0.0, float(request_delay_seconds))
        self.google_cse_api_key = google_cse_api_key or os.getenv(google_cse_api_key_env or "GOOGLE_CSE_API_KEY")
        self.google_cse_cx = google_cse_cx or os.getenv(google_cse_cx_env or "GOOGLE_CSE_CX")
        self.brave_api_key = brave_api_key or os.getenv(brave_api_key_env or "BRAVE_SEARCH_API_KEY")
        self.timeout_seconds = max(3.0, float(timeout_seconds))
        requested_collection_timeout = float(collection_timeout_seconds)
        self.collection_timeout_seconds = (
            None
            if requested_collection_timeout <= 0
            else max(self.timeout_seconds + 5.0, requested_collection_timeout)
        )
        self.provider_query_limits = _provider_query_limits(self.max_queries, provider_query_limits)

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.queries:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay consultas de busqueda publica configuradas."))
        events: List[ThreatEvent] = []
        seen: set[str] = set()
        warnings: List[str] = []
        notes: List[str] = []
        warned_once: set[str] = set()
        provider_counts: dict[str, int] = {}
        disabled_providers: set[str] = set()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.collection_timeout_seconds if self.collection_timeout_seconds is not None else None
        budget_exhausted = False
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True, headers={"User-Agent": "CyberDecisionEngine/1.0"}) as client:
            queries = self.queries if self.max_queries <= 0 else self.queries[: self.max_queries]
            for query in queries:
                if self.max_records > 0 and len(events) >= self.max_records:
                    break
                if deadline is not None and loop.time() >= deadline:
                    budget_exhausted = True
                    break
                for provider in self.providers:
                    if self.max_records > 0 and len(events) >= self.max_records:
                        break
                    if deadline is not None and loop.time() >= deadline:
                        budget_exhausted = True
                        break
                    if provider in disabled_providers:
                        continue
                    provider_limit = self.provider_query_limits.get(provider, self.max_queries)
                    if provider_limit > 0 and provider_counts.get(provider, 0) >= provider_limit:
                        continue
                    remaining = self.max_records - len(events) if self.max_records > 0 else 50
                    made_request = False
                    try:
                        if provider == "google_news_rss":
                            made_request = True
                            response = await client.get(
                                "https://news.google.com/rss/search",
                                params={"q": query, "hl": "es-419"},
                            )
                            response.raise_for_status()
                            _extend_unique(events, _parse_google_news(query, response.text, remaining), seen, self.max_records)
                        elif provider == "duckduckgo_lite":
                            made_request = True
                            response = await client.get(
                                "https://html.duckduckgo.com/html/",
                                params={"q": query, "kl": "wt-wt"},
                                headers={"Accept-Language": "es;q=0.9,en;q=0.7"},
                            )
                            response.raise_for_status()
                            candidates = _parse_duckduckgo(query, response.text, remaining)
                            if not candidates:
                                if self.request_delay_seconds:
                                    await asyncio.sleep(self.request_delay_seconds)
                                response = await client.get(
                                    "https://lite.duckduckgo.com/lite/",
                                    params={"q": query, "kl": "wt-wt"},
                                    headers={"Accept-Language": "es;q=0.9,en;q=0.7"},
                                )
                                response.raise_for_status()
                                candidates = _parse_duckduckgo(query, response.text, remaining)
                            _extend_unique(events, candidates, seen, self.max_records)
                        elif provider == "hacker_news":
                            made_request = True
                            response = await client.get(
                                "https://hn.algolia.com/api/v1/search_by_date",
                                params={"query": query, "tags": "story", "hitsPerPage": min(10, remaining)},
                            )
                            response.raise_for_status()
                            _extend_unique(events, _parse_hacker_news(query, response.json(), remaining), seen, self.max_records)
                        elif provider == "gdelt":
                            made_request = True
                            response = await client.get(
                                "https://api.gdeltproject.org/api/v2/doc/doc",
                                params={"query": query, "mode": "ArtList", "format": "json", "maxrecords": min(20, remaining), "sort": "HybridRel"},
                            )
                            response.raise_for_status()
                            _extend_unique(events, _parse_gdelt(query, response.json(), remaining), seen, self.max_records)
                        elif provider == "google_cse":
                            if not self.google_cse_api_key or not self.google_cse_cx:
                                _warn_once(notes, warned_once, "Google CSE omitted: configure GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX for full web search.")
                                continue
                            made_request = True
                            response = await client.get(
                                "https://www.googleapis.com/customsearch/v1",
                                params={"q": query, "key": self.google_cse_api_key, "cx": self.google_cse_cx, "num": min(10, remaining)},
                            )
                            response.raise_for_status()
                            _extend_unique(events, _parse_google_cse(query, response.json(), remaining), seen, self.max_records)
                        elif provider == "brave":
                            if not self.brave_api_key:
                                _warn_once(notes, warned_once, "Brave Search omitted: configure BRAVE_SEARCH_API_KEY for broad web search.")
                                continue
                            made_request = True
                            response = await client.get(
                                "https://api.search.brave.com/res/v1/web/search",
                                params={"q": query, "count": min(10, remaining), "search_lang": "es", "safesearch": "off"},
                                headers={"X-Subscription-Token": self.brave_api_key, "Accept": "application/json"},
                            )
                            response.raise_for_status()
                            _extend_unique(events, _parse_brave(query, response.json(), remaining), seen, self.max_records)
                        else:
                            _warn_once(warnings, warned_once, f"Search provider ignored: {provider}")
                    except httpx.HTTPStatusError as exc:  # pragma: no cover - network dependent
                        status_code = exc.response.status_code
                        if status_code in {403, 429}:
                            disabled_providers.add(provider)
                            _warn_once(warnings, warned_once, f"{provider}: disabled for this run after HTTP {status_code}.")
                        else:
                            warnings.append(f"{provider} {query}: {exc}")
                    except Exception as exc:  # pragma: no cover - network dependent
                        warnings.append(f"{provider} {query}: {exc}")
                    if made_request:
                        provider_counts[provider] = provider_counts.get(provider, 0) + 1
                        if self.request_delay_seconds:
                            if deadline is None:
                                await asyncio.sleep(self.request_delay_seconds)
                            else:
                                remaining_budget = deadline - loop.time()
                                if remaining_budget <= 0:
                                    budget_exhausted = True
                                    break
                                await asyncio.sleep(min(self.request_delay_seconds, remaining_budget))
        if budget_exhausted:
            warnings.append(f"Search budget reached after {int(self.collection_timeout_seconds or 0)} seconds; partial public results were returned.")
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join([*warnings, *notes]) or None),
            events,
        )


def _parse_google_news(query: str, xml_text: str, limit: int) -> List[ThreatEvent]:
    root = ET.fromstring(xml_text)
    events: List[ThreatEvent] = []
    for index, item in enumerate(root.findall("./channel/item")[:limit]):
        title = item.findtext("title") or "Google News search result"
        link = item.findtext("link")
        published = item.findtext("pubDate")
        description = BeautifulSoup(item.findtext("description") or "", "html.parser").get_text(" ", strip=True)
        category, tags, technique = _classify_search_result(title, query, link, description)
        events.append(
            ThreatEvent(
                id=f"WEB-GNEWS-{abs(hash((query, title, index))) % 10_000_000}",
                title=title,
                category=category,
                source="Busqueda publica",
                source_weight=0.58,
                confidence=0.56,
                age_days=_age_days(published),
                severity=0.50 if category == "web_search" else 0.62,
                epss=0.03,
                cvss=0.0,
                actor="unattributed",
                technique=technique,
                tags=["internet_search", "google_news_rss", *tags],
                evidence_url=link,
                observed_at=_date_or_now(published),
                demo=False,
                technical_validation={"summary": description, "query": query, "provider": "google_news_rss"},
            )
        )
    return events


def _parse_hacker_news(query: str, payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, hit in enumerate(payload.get("hits", [])[:limit]):
        title = hit.get("title") or hit.get("story_title") or "Hacker News public search result"
        link = hit.get("url") or hit.get("story_url")
        text = f"{title} {hit.get('story_text') or ''} {link or ''}"
        if not _matches_query(query, text):
            continue
        published = hit.get("created_at")
        category, tags, technique = _classify_search_result(title, query, link, hit.get("story_text") or "")
        events.append(
            ThreatEvent(
                id=f"WEB-HN-{abs(hash((query, title, index))) % 10_000_000}",
                title=title,
                category=category,
                source="Busqueda publica",
                source_weight=0.42,
                confidence=0.40,
                age_days=_age_days(published),
                severity=0.46 if category == "web_search" else 0.58,
                epss=0.02,
                cvss=0.0,
                actor="unattributed",
                technique=technique,
                tags=["internet_search", "hacker_news_public", *tags],
                evidence_url=link,
                observed_at=_date_or_now(published),
                demo=False,
                technical_validation={"summary": hit.get("story_text") or "", "query": query, "provider": "hacker_news_public"},
            )
        )
    return events


def _parse_duckduckgo(query: str, html_text: str, limit: int) -> List[ThreatEvent]:
    soup = BeautifulSoup(html_text, "html.parser")
    events: List[ThreatEvent] = []
    index = 0
    result_nodes = soup.select(".result")
    if result_nodes:
        for result in result_nodes:
            anchor = result.select_one(".result__a")
            if not anchor:
                continue
            link = _clean_duckduckgo_redirect(anchor.get("href", ""))
            title = anchor.get_text(" ", strip=True)
            snippet_el = result.select_one(".result__snippet")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            event = _duckduckgo_event(query, index, title, link, snippet)
            if event:
                events.append(event)
                index += 1
            if len(events) >= limit:
                return events
    anchors = soup.select("a.result-link")
    if not anchors:
        anchors = [anchor for anchor in soup.select("a") if anchor.get("href") and "uddg=" in anchor.get("href", "")]
    for anchor in anchors:
        link = _clean_duckduckgo_redirect(anchor.get("href", ""))
        title = anchor.get_text(" ", strip=True)
        row = anchor.find_parent("tr")
        snippet = ""
        if row:
            next_row = row.find_next_sibling("tr")
            if next_row:
                snippet = next_row.get_text(" ", strip=True)
        event = _duckduckgo_event(query, index, title, link, snippet)
        if event:
            events.append(event)
            index += 1
        if len(events) >= limit:
            break
    return events


def _duckduckgo_event(query: str, index: int, title: str, link: str, snippet: str) -> Optional[ThreatEvent]:
    if not title or not link or link.startswith("javascript:"):
        return None
    if _is_noise_url(link):
        return None
    if not _matches_query(query, f"{title} {snippet} {link}"):
        return None
    return _search_event(
        prefix="WEB-DDG",
        query=query,
        index=index,
        title=title,
        link=link,
        snippet=snippet,
        source="Busqueda publica",
        source_weight=0.52,
        confidence=0.50,
        provider_tag="duckduckgo_lite",
        published=None,
    )


def _parse_google_cse(query: str, payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, item in enumerate(payload.get("items", [])[:limit]):
        title = item.get("title") or "Google Programmable Search result"
        link = item.get("link")
        snippet = item.get("snippet") or ""
        if not _matches_query(query, f"{title} {snippet} {link or ''}"):
            continue
        events.append(
            _search_event(
                prefix="WEB-GCSE",
                query=query,
                index=index,
                title=title,
                link=link,
                snippet=snippet,
                source="Busqueda publica",
                source_weight=0.62,
                confidence=0.60,
                provider_tag="google_cse",
                published=None,
            )
        )
    return events


def _parse_brave(query: str, payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    results = payload.get("web", {}).get("results", [])
    for index, item in enumerate(results[:limit]):
        title = item.get("title") or "Brave Search result"
        link = item.get("url")
        extra_snippets = item.get("extra_snippets") or [""]
        snippet = item.get("description") or extra_snippets[0] or ""
        if not _matches_query(query, f"{title} {snippet} {link or ''}"):
            continue
        events.append(
            _search_event(
                prefix="WEB-BRAVE",
                query=query,
                index=index,
                title=title,
                link=link,
                snippet=snippet,
                source="Busqueda publica",
                source_weight=0.62,
                confidence=0.58,
                provider_tag="brave_search",
                published=item.get("age"),
            )
        )
    return events


def _parse_gdelt(query: str, payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, item in enumerate(payload.get("articles", [])[:limit]):
        title = item.get("title") or "GDELT public media result"
        link = item.get("url")
        snippet = item.get("domain") or item.get("sourcecountry") or ""
        if not _matches_query(query, f"{title} {snippet} {link or ''}"):
            continue
        events.append(
            _search_event(
                prefix="WEB-GDELT",
                query=query,
                index=index,
                title=title,
                link=link,
                snippet=snippet,
                source="Busqueda publica",
                source_weight=0.57,
                confidence=0.54,
                provider_tag="gdelt",
                published=item.get("seendate"),
            )
        )
    return events


def _search_event(
    prefix: str,
    query: str,
    index: int,
    title: str,
    link: Optional[str],
    snippet: str,
    source: str,
    source_weight: float,
    confidence: float,
    provider_tag: str,
    published: Optional[str],
) -> ThreatEvent:
    category, tags, technique = _classify_search_result(title, query, link, snippet)
    public_entity_tags, public_entities = _public_entity_candidates(title, link, snippet)
    return ThreatEvent(
        id=f"{prefix}-{abs(hash((query, title, link, index))) % 10_000_000}",
        title=title,
        category=category,
        source=source,
        source_weight=source_weight,
        confidence=confidence,
        age_days=_age_days(published),
        severity=_search_severity(category, tags),
        epss=0.03,
        cvss=0.0,
        actor="unattributed",
        technique=technique,
        tags=["internet_search", provider_tag, *tags, *public_entity_tags],
        evidence_url=link,
        observed_at=_date_or_now(published),
        demo=False,
        technical_validation={
            "summary": snippet,
            "query": query,
            "provider": provider_tag,
            "public_entity_candidates": public_entities,
            "does_not_demonstrate": (
                "a public profile or contact mention does not prove current employment, ownership or identity "
                "without official-source corroboration"
            ),
        },
    )


def _public_entity_candidates(title: str, link: Optional[str], snippet: str) -> tuple[list[str], list[dict[str, str]]]:
    text = f"{title} {snippet}"
    tags: list[str] = []
    entities: list[dict[str, str]] = []
    for email in sorted(set(re.findall(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", text, re.IGNORECASE)))[:12]:
        normalized = email.lower()
        tags.append(f"email:{normalized}")
        entities.append({"type": "email", "value": normalized, "status": "public_contact_candidate"})
    for phone in _public_phone_candidates(text)[:8]:
        tags.append(f"phone:{phone}")
        entities.append({"type": "phone", "value": phone, "status": "public_contact_candidate"})
    if link and re.search(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/in/", link, re.IGNORECASE):
        candidate = re.split(r"\s[-|·]\s", title, maxsplit=1)[0].strip()
        if 2 <= len(candidate.split()) <= 6 and not re.search(
            r"\b(linkedin|profile|perfiles|jobs|empleos|company)\b", candidate, re.IGNORECASE
        ):
            tags.extend(["public_profile", "profile_platform:linkedin", f"person_candidate:{candidate}"])
            entities.append({"type": "person", "value": candidate, "status": "public_profile_candidate"})
    return _unique_tags(tags), entities


def _public_phone_candidates(text: str) -> list[str]:
    values = []
    for match in re.findall(r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?(?:\d[\s().-]*){7,14}(?!\w)", text):
        digits = re.sub(r"\D", "", match)
        if not 7 <= len(digits) <= 15:
            continue
        if re.fullmatch(r"(?:19|20)\d{6,12}", digits):
            continue
        normalized = f"+{digits}" if match.strip().startswith("+") else digits
        if normalized not in values:
            values.append(normalized)
    return values


def _extend_unique(events: List[ThreatEvent], candidates: List[ThreatEvent], seen: set[str], max_records: int) -> None:
    for event in candidates:
        key = event.evidence_url or event.title
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if max_records > 0 and len(events) >= max_records:
            break


def _classify_search_result(title: str, query: str, url: Optional[str] = None, snippet: str = "") -> tuple[str, List[str], Optional[str]]:
    # The query expresses analyst intent, not an observed fact. Only returned
    # content and its URL may drive classification.
    text = _norm(f"{title} {snippet} {url or ''}")
    tags = ["open_web_signal", *_hashtag_tags(f"{title} {snippet}")]
    platform = _social_platform(url)
    if platform:
        tags.extend(["socmint_public", "social_profile_or_post", f"platform_{platform}"])

    if _is_reputation_checker(url, text):
        return "brand_reputation", _unique_tags([*tags, "brand_protection", "reputation_checker", "validation_required"]), None

    recruitment_terms = [
        "empleo",
        "oferta laboral",
        "oferta de trabajo",
        "vacante",
        "reclutamiento",
        "recruitment",
        "job offer",
        "job vacancy",
        "hiring",
    ]
    deception_terms = [
        "falso",
        "falsa",
        "fake",
        "fraude",
        "fraud",
        "estafa",
        "scam",
        "suplant",
        "impersonat",
    ]
    fraud_terms = [
        "phishing",
        "smishing",
        "vishing",
        "suplant",
        "estafa",
        "fraude",
        "scam",
        "farsa",
        "clonen",
        "clon",
        "fake",
        "dominio falso",
        "soporte falso",
        "login falso",
    ]
    reputation_terms = ["queja", "reclamo", "denuncia", "mala atencion", "falla", "caido", "indisponible"]
    leak_terms = ["data breach", "filtracion", "filtracion", "fuga de datos", "credential", "credencial", "leak", "dark web", "breach forum", ".onion"]
    if any(term in text for term in recruitment_terms) and any(term in text for term in deception_terms):
        return (
            "fake_recruitment",
            _unique_tags([*tags, "fraud", "brand_impersonation", "fake_recruitment", "brand_protection"]),
            "T1566",
        )
    if any(term in text for term in fraud_terms):
        return "phishing", _unique_tags([*tags, "fraud", "brand_impersonation", "brand_protection"]), "T1566"
    if any(term in text for term in reputation_terms):
        return "brand_reputation", _unique_tags([*tags, "brand_protection", "customer_signal"]), None
    if any(term in text for term in leak_terms):
        return "data_leak", _unique_tags([*tags, "darkweb_index", "credential_exposure", "brand_protection"]), "T1589"
    if any(term in text for term in ["ransomware", "ciberataque", "cyberattack", "malware"]):
        return "ransomware", _unique_tags([*tags, "ransomware_signal"]), "T1486"
    if platform:
        return "social_signal", _unique_tags(tags), None
    return "web_search", _unique_tags(tags), None


def _search_severity(category: str, tags: List[str]) -> float:
    if "reputation_checker" in tags or "validation_required" in tags:
        return 0.34
    if category in {"web_search", "social_signal", "brand_reputation"}:
        return 0.50
    if category == "data_leak":
        return 0.70
    return 0.64


def _is_reputation_checker(url: Optional[str], text: str) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    host = parsed.netloc.lower().removeprefix("www.")
    path = parsed.path.lower()
    checker_hosts = {
        "emailveritas.com",
        "scamadviser.com",
        "urlvoid.com",
        "virustotal.com",
        "ipqualityscore.com",
        "scam-detector.com",
        "eveninsight.com",
    }
    checker_path_terms = ("url-checker", "website-safety", "check-website", "scam-check", "domain-check")
    if host in checker_hosts or any(host.endswith(f".{item}") for item in checker_hosts):
        return True
    return any(term in path for term in checker_path_terms) and any(term in text for term in ("legit", "scam", "safe", "reputation", "checker"))


def _normalize_providers(providers: object) -> List[str]:
    if not providers or providers == "aggregated_public_search":
        return ["duckduckgo_lite", "google_news_rss", "gdelt", "hacker_news", "google_cse", "brave"]
    if isinstance(providers, str):
        values = [providers]
    else:
        values = list(providers) if isinstance(providers, Iterable) else []
    normalized = [str(value).strip() for value in values if str(value).strip()]
    return normalized or ["duckduckgo_lite", "google_news_rss", "gdelt", "hacker_news", "google_cse", "brave"]


def _provider_query_limits(max_queries: int, configured: Optional[dict]) -> dict[str, int]:
    if max_queries <= 0:
        limits = {
            "duckduckgo_lite": 0,
            "google_news_rss": 0,
            "gdelt": 0,
            "hacker_news": 0,
            "google_cse": 0,
            "brave": 0,
        }
    else:
        limits = {
            "duckduckgo_lite": min(max_queries, 12),
            "google_news_rss": min(max_queries, 8),
            "gdelt": min(max_queries, 5),
            "hacker_news": min(max_queries, 5),
            "google_cse": min(max_queries, 25),
            "brave": min(max_queries, 25),
        }
    if isinstance(configured, dict):
        for key, value in configured.items():
            try:
                limits[str(key)] = max(0, int(value))
            except (TypeError, ValueError):
                continue
    return limits


def _warn_once(warnings: List[str], seen: set[str], message: str) -> None:
    if message not in seen:
        seen.add(message)
        warnings.append(message)


def _social_platform(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    host = urlparse(url).netloc.lower().removeprefix("www.")
    platforms = {
        "linkedin.com": "linkedin",
        "instagram.com": "instagram",
        "facebook.com": "facebook",
        "x.com": "x",
        "twitter.com": "x",
        "tiktok.com": "tiktok",
        "youtube.com": "youtube",
        "reddit.com": "reddit",
        "threads.net": "threads",
    }
    for domain, platform in platforms.items():
        if host == domain or host.endswith(f".{domain}"):
            return platform
    return None


def _hashtag_tags(value: str) -> List[str]:
    return [f"hashtag:{match.group(1).lower()}" for match in re.finditer(r"#([A-Za-z0-9_]{2,64})", value)]


def _unique_tags(tags: List[str]) -> List[str]:
    seen = set()
    output = []
    for tag in tags:
        if tag and tag not in seen:
            seen.add(tag)
            output.append(tag)
    return output


def _clean_duckduckgo_redirect(raw_url: str) -> str:
    if not raw_url:
        return ""
    raw_url = raw_url.strip()
    parsed = urlparse(raw_url)
    if "duckduckgo.com" in parsed.netloc and parsed.query:
        qs = parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
    if raw_url.startswith("//duckduckgo.com/l/?"):
        qs = parse_qs(urlparse("https:" + raw_url).query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
    if raw_url.startswith("/l/?"):
        qs = parse_qs(urlparse("https://duckduckgo.com" + raw_url).query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
    return raw_url


def _is_noise_url(link: str) -> bool:
    parsed = urlparse(link)
    host = parsed.netloc.lower().removeprefix("www.")
    path = parsed.path.lower()
    query = parsed.query.lower()
    if host.endswith("duckduckgo.com") and path.endswith("/y.js"):
        return True
    if host.endswith("bing.com") and "/aclick" in path:
        return True
    if any(token in query for token in ("ad_domain=", "ad_provider=", "utm_campaign=hotel", "msclkid=")):
        return True
    return False


def _matches_query(query: str, text: str) -> bool:
    haystack = _norm(text)
    compact_haystack = haystack.replace(" ", "").replace(".", "")
    quoted_phrases = [_norm(value) for value in re.findall(r'"([^"]+)"', query) if value.strip()]
    for phrase in quoted_phrases:
        compact_phrase = phrase.replace(" ", "").replace(".", "")
        if phrase not in haystack and compact_phrase not in compact_haystack:
            return False
    cleaned_query = re.sub(r'"[^"]+"', " ", query)
    cleaned_query = re.sub(r"\b(OR|AND)\b", " ", cleaned_query, flags=re.IGNORECASE)
    terms = [_norm(term.strip('()')) for term in cleaned_query.split() if len(term.strip('()')) > 2]
    terms = [
        term
        for term in terms
        if term not in {"para", "with", "from", "site", "not", "the"}
        and not term.startswith(("site:", "-site:", "filetype:", "intitle:"))
    ]
    if not terms:
        return True
    if quoted_phrases and not terms:
        return True
    for term in terms:
        if "." in term:
            label = term.split(".", 1)[0].replace("-", "")
            if len(label) >= 4 and label in compact_haystack:
                return True
    if re.search(r"\bOR\b", query, flags=re.IGNORECASE):
        return any(term in haystack for term in terms)
    return all(term in haystack for term in terms[:3])


def _norm(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.lower())
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


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
        for fmt in ("%Y%m%d%H%M%S", "%Y%m%d"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None
