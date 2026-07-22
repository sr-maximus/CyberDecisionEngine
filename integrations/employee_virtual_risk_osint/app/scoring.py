from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from rapidfuzz import fuzz

from .false_positive import false_positive_label, human_review_required, identity_match_score
from .models import Employee, EmployeeRiskSummary, QuerySpec, ScoredEvidence, SearchResult
from .privacy import email_domain, normalize_text


SOCIAL_DOMAINS = {
    "linkedin.com": "LinkedIn",
    "twitter.com": "X/Twitter",
    "x.com": "X",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "tiktok.com": "TikTok",
    "reddit.com": "Reddit",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "telegram.org": "Telegram",
    "discord.com": "Discord",
}

RELIABILITY_BY_DOMAIN = {
    "linkedin.com": 0.65,
    "github.com": 0.80,
    "gitlab.com": 0.75,
    "bitbucket.org": 0.75,
    "facebook.com": 0.45,
    "instagram.com": 0.45,
    "x.com": 0.45,
    "twitter.com": 0.45,
    "reddit.com": 0.45,
    "pastebin.com": 0.35,
    "gist.github.com": 0.80,
}


def registered_domain(url: str) -> str:
    parsed = urlparse(url or "")
    host = parsed.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def detect_social_surface(url: str) -> str:
    domain = registered_domain(url)
    return SOCIAL_DOMAINS.get(domain, "")


def source_reliability_score(url: str, employee: Employee) -> float:
    domain = registered_domain(url)
    if not domain:
        return 0.25
    if domain in RELIABILITY_BY_DOMAIN:
        return RELIABILITY_BY_DOMAIN[domain]
    corp_domain = email_domain(employee.corporate_email)
    if corp_domain and domain.endswith(corp_domain):
        return 0.90
    if domain.endswith(".gov") or ".gov." in domain:
        return 0.85
    if domain.endswith(".edu") or ".edu." in domain:
        return 0.80
    if domain in {"example.org", "example.net"}:
        return 0.45
    return 0.55


def keyword_relevance_score(keyword: str, text: str) -> float:
    keyword_n = normalize_text(keyword)
    text_n = normalize_text(text)
    if not keyword_n or not text_n:
        return 0.0
    if keyword_n in text_n:
        return 1.0
    ratio = fuzz.partial_ratio(keyword_n, text_n) / 100
    if ratio >= 0.90:
        return 0.85
    if ratio >= 0.75:
        return 0.65
    return 0.20


def context_relevance_score(employee: Employee, text: str) -> float:
    text_n = normalize_text(text)
    signals = [
        employee.organization,
        employee.department,
        employee.role,
        employee.city,
        employee.country,
        email_domain(employee.corporate_email),
    ]
    hits = 0
    total = 0
    for signal in signals:
        signal_n = normalize_text(signal)
        if not signal_n:
            continue
        total += 1
        if signal_n in text_n:
            hits += 1
    if total == 0:
        return 0.35
    return min(1.0, 0.20 + 0.80 * hits / total)


def recency_score(published_date: str, searched_at: str) -> float:
    raw = (published_date or "").strip()
    if not raw:
        return 0.45
    try:
        clean = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.45
    now = datetime.now(timezone.utc)
    age_days = max(0, (now - dt).days)
    if age_days <= 180:
        return 1.0
    if age_days <= 365:
        return 0.85
    if age_days <= 3 * 365:
        return 0.65
    if age_days <= 5 * 365:
        return 0.45
    return 0.25


def evidence_quality_score(result: SearchResult) -> float:
    title_len = len((result.title or "").strip())
    snippet_len = len((result.snippet or "").strip())
    url_len = len((result.url or "").strip())
    score = 0.0
    if url_len > 12:
        score += 0.25
    if title_len > 8:
        score += 0.30
    if snippet_len > 30:
        score += 0.35
    if snippet_len > 120:
        score += 0.10
    return min(1.0, max(0.20, score))


def score_result(
    employee: Employee,
    spec: QuerySpec,
    result: SearchResult,
    risk_config: Dict[str, Any],
    min_confidence: float,
) -> ScoredEvidence:
    combined_text = " ".join([result.url, result.title, result.snippet])
    identity = identity_match_score(employee, combined_text)
    reliability = source_reliability_score(result.url, employee)
    keyword_rel = keyword_relevance_score(spec.keyword, combined_text)
    context_rel = context_relevance_score(employee, combined_text)
    recency = recency_score(result.published_date, result.searched_at)
    quality = evidence_quality_score(result)

    confidence = (
        0.35 * identity +
        0.20 * reliability +
        0.15 * keyword_rel +
        0.15 * context_rel +
        0.10 * recency +
        0.05 * quality
    )
    dimensions = risk_config.get("dimensions", {})
    severity = float(dimensions.get(spec.dimension_key, {}).get("severity", 3))
    evidence_risk = min(100.0, confidence * severity * 20.0)
    fp_label = false_positive_label(confidence, identity)
    review = human_review_required(confidence, min_confidence, fp_label)

    notes = ""
    if review:
        notes = "Revisar identidad/contexto antes de considerar el hallazgo como válido."
    if spec.dimension_key == "positive_mitigating_signals":
        notes = "Señal mitigante; no se interpreta como riesgo negativo."

    return ScoredEvidence(
        employee_id=employee.employee_id,
        employee_name=employee.full_name,
        dimension_key=spec.dimension_key,
        dimension_label=spec.dimension_label,
        keyword=spec.keyword,
        query=spec.query,
        query_type=spec.query_type,
        url=result.url,
        title=result.title,
        snippet=result.snippet,
        source=result.source,
        searched_at=result.searched_at,
        published_date=result.published_date,
        identity_match=round(identity, 4),
        source_reliability=round(reliability, 4),
        keyword_relevance=round(keyword_rel, 4),
        context_relevance=round(context_rel, 4),
        recency_score=round(recency, 4),
        evidence_quality=round(quality, 4),
        confidence_score=round(confidence, 4),
        severity_score=round(severity, 2),
        evidence_risk=round(evidence_risk, 2),
        false_positive_risk=fp_label,
        requires_human_review=review,
        social_surface=detect_social_surface(result.url),
        notes=notes,
        preview_image_url=getattr(result, "image_url", ""),
    )


def dedupe_results(results: List[Tuple[QuerySpec, SearchResult]]) -> List[Tuple[QuerySpec, SearchResult]]:
    seen = set()
    output: List[Tuple[QuerySpec, SearchResult]] = []
    for spec, result in results:
        key = (result.url.strip().lower().rstrip("/"), spec.dimension_key, spec.keyword)
        if not result.url or key in seen:
            continue
        seen.add(key)
        output.append((spec, result))
    return output


def risk_level(score: float, risk_config: Dict[str, Any]) -> str:
    classes = risk_config.get("risk_classes", [])
    for item in classes:
        if float(item["min"]) <= score <= float(item["max"]):
            return item["label"]
    if score <= 20:
        return "Bajo"
    if score <= 40:
        return "Moderado"
    if score <= 60:
        return "Alto"
    if score <= 80:
        return "Crítico"
    return "Extremo"


def aggregate_employee_risk(
    employee: Employee,
    evidence: List[ScoredEvidence],
    risk_config: Dict[str, Any],
) -> EmployeeRiskSummary:
    dimensions_cfg = risk_config.get("dimensions", {})
    access_multipliers = {int(k): float(v) for k, v in risk_config.get("access_multipliers", {}).items()}
    access_multiplier = access_multipliers.get(int(employee.access_level), 1.0)

    dimension_risks: Dict[str, float] = {}
    dimension_labels: Dict[str, str] = {}
    dim_conf_sum: Dict[str, float] = defaultdict(float)
    dim_count: Dict[str, int] = defaultdict(int)

    for dim_key, cfg in dimensions_cfg.items():
        if cfg.get("mitigating", False):
            continue
        dim_evidence = [e for e in evidence if e.dimension_key == dim_key]
        raw_sum = sum(e.confidence_score * e.severity_score * 10.0 for e in dim_evidence)
        dimension_risks[dim_key] = round(min(100.0, raw_sum * access_multiplier), 2)
        dimension_labels[dim_key] = cfg.get("label", dim_key)
        dim_conf_sum[dim_key] = sum(e.confidence_score for e in dim_evidence)
        dim_count[dim_key] = len(dim_evidence)

    positive_evidence = [e for e in evidence if dimensions_cfg.get(e.dimension_key, {}).get("mitigating", False)]
    mitigation_score = min(30.0, sum(e.confidence_score for e in positive_evidence) * 10.0)

    weighted_sum = 0.0
    weight_total = 0.0
    for dim_key, risk in dimension_risks.items():
        weight = float(dimensions_cfg.get(dim_key, {}).get("weight", 0.0))
        weighted_sum += risk * weight
        weight_total += weight
    total = weighted_sum / weight_total if weight_total else 0.0
    total = max(0.0, min(100.0, total - mitigation_score))

    dimension_probability_impact: Dict[str, Dict[str, float]] = {}
    for dim_key, cfg in dimensions_cfg.items():
        if cfg.get("mitigating", False):
            continue
        count = dim_count.get(dim_key, 0)
        conf_sum = dim_conf_sum.get(dim_key, 0.0)
        probability = min(1.0, conf_sum / 3.0) if count else 0.0
        impact = min(1.0, (float(cfg.get("severity", 3)) / 5.0) * (access_multiplier / 2.0))
        dimension_probability_impact[dim_key] = {
            "probability": round(probability, 4),
            "impact": round(impact, 4),
            "label": cfg.get("label", dim_key),
        }

    keyword_counter = Counter()
    keyword_risk = defaultdict(float)
    for e in evidence:
        if dimensions_cfg.get(e.dimension_key, {}).get("mitigating", False):
            continue
        keyword_counter[e.keyword] += 1
        keyword_risk[e.keyword] += e.evidence_risk
    top_keywords = [
        {"keyword": kw, "frequency": freq, "risk": round(keyword_risk[kw], 2)}
        for kw, freq in keyword_counter.most_common(15)
    ]

    surfaces_seen = set()
    social_surfaces = []
    for e in evidence:
        if e.social_surface:
            key = (e.social_surface, e.url)
            if key not in surfaces_seen:
                surfaces_seen.add(key)
                social_surfaces.append({
                    "surface": e.social_surface,
                    "url": e.url,
                    "title": e.title,
                    "confidence_score": e.confidence_score,
                    "false_positive_risk": e.false_positive_risk,
                    "query_type": e.query_type,
                    "preview_image_url": e.preview_image_url,
                })

    return EmployeeRiskSummary(
        employee=employee,
        total_risk=round(total, 2),
        risk_level=risk_level(total, risk_config),
        mitigation_score=round(mitigation_score, 2),
        dimension_risks=dimension_risks,
        dimension_labels=dimension_labels,
        dimension_probability_impact=dimension_probability_impact,
        top_keywords=top_keywords,
        social_surfaces=social_surfaces,
        evidence=evidence,
    )
