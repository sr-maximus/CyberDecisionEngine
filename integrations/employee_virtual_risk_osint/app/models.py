from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class Employee:
    employee_id: str
    full_name: str
    corporate_email: str = ""
    personal_email: str = ""
    identification_document_hash: str = ""
    role: str = ""
    department: str = ""
    organization: str = ""
    country: str = ""
    city: str = ""
    access_level: int = 1
    access_category: str = "publico"
    consent_status: str = "not_provided"
    consent_date: str = ""
    authorized_personal_email: bool = False

    def to_safe_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("identification_document_hash", None)
        return data


@dataclass
class QuerySpec:
    query: str
    employee_id: str
    dimension_key: str
    dimension_label: str
    keyword: str
    query_type: str


@dataclass
class SearchResult:
    query: str
    url: str
    title: str
    snippet: str
    source: str
    searched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    published_date: str = ""
    image_url: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScoredEvidence:
    employee_id: str
    employee_name: str
    dimension_key: str
    dimension_label: str
    keyword: str
    query: str
    query_type: str
    url: str
    title: str
    snippet: str
    source: str
    searched_at: str
    published_date: str
    identity_match: float
    source_reliability: float
    keyword_relevance: float
    context_relevance: float
    recency_score: float
    evidence_quality: float
    confidence_score: float
    severity_score: float
    evidence_risk: float
    false_positive_risk: str
    requires_human_review: bool
    social_surface: str = ""
    notes: str = ""
    preview_image_url: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmployeeRiskSummary:
    employee: Employee
    total_risk: float
    risk_level: str
    mitigation_score: float
    dimension_risks: Dict[str, float]
    dimension_labels: Dict[str, str]
    dimension_probability_impact: Dict[str, Dict[str, float]]
    top_keywords: List[Dict[str, Any]]
    social_surfaces: List[Dict[str, str]]
    evidence: List[ScoredEvidence]
    skipped: bool = False
    skip_reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "employee": self.employee.to_safe_dict(),
            "total_risk": self.total_risk,
            "risk_level": self.risk_level,
            "mitigation_score": self.mitigation_score,
            "dimension_risks": self.dimension_risks,
            "dimension_labels": self.dimension_labels,
            "dimension_probability_impact": self.dimension_probability_impact,
            "top_keywords": self.top_keywords,
            "social_surfaces": self.social_surfaces,
            "evidence": [e.as_dict() for e in self.evidence],
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }
