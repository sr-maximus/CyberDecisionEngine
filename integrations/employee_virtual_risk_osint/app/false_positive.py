from __future__ import annotations

from typing import List

from rapidfuzz import fuzz

from .models import Employee
from .privacy import email_domain, normalize_text


def name_tokens(full_name: str) -> List[str]:
    tokens = [t for t in normalize_text(full_name).split() if len(t) > 2]
    return tokens


def identity_match_score(employee: Employee, text: str) -> float:
    text_n = normalize_text(text)
    if not text_n:
        return 0.0

    full_name_n = normalize_text(employee.full_name)
    corp_email_n = normalize_text(employee.corporate_email)
    personal_email_n = normalize_text(employee.personal_email) if employee.authorized_personal_email else ""
    org_n = normalize_text(employee.organization)
    city_n = normalize_text(employee.city)
    country_n = normalize_text(employee.country)
    corp_domain_n = normalize_text(email_domain(employee.corporate_email))

    score = 0.0
    if corp_email_n and corp_email_n in text_n:
        score = max(score, 1.0)
    if personal_email_n and personal_email_n in text_n:
        score = max(score, 0.95)
    if full_name_n and full_name_n in text_n:
        score = max(score, 0.85)
    else:
        tokens = name_tokens(employee.full_name)
        if tokens:
            hits = sum(1 for token in tokens if token in text_n)
            ratio = hits / len(tokens)
            if hits >= 2:
                score = max(score, 0.45 + 0.30 * ratio)
            elif hits == 1:
                score = max(score, 0.25)
            fuzzy = fuzz.partial_ratio(full_name_n, text_n) / 100 if full_name_n else 0
            if fuzzy >= 0.85:
                score = max(score, 0.70)
            elif fuzzy >= 0.70:
                score = max(score, 0.50)

    context_bonus = 0.0
    for context in [org_n, city_n, country_n, corp_domain_n]:
        if context and context in text_n:
            context_bonus += 0.05
    return min(1.0, score + context_bonus)


def false_positive_label(confidence_score: float, identity_score: float) -> str:
    if confidence_score < 0.25 or identity_score < 0.25:
        return "alto"
    if confidence_score < 0.45 or identity_score < 0.45:
        return "medio"
    return "bajo"


def human_review_required(confidence_score: float, min_confidence: float, false_positive_risk: str) -> bool:
    return confidence_score < min_confidence or false_positive_risk in {"medio", "alto"}
