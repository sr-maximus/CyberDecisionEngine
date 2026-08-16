from app.models import Employee, QuerySpec, SearchResult
from app.scoring import score_result


def test_score_result_basic():
    employee = Employee(
        employee_id="E001",
        full_name="Synthetic Employee 001",
        corporate_email="employee-001@organization.example.invalid",
        organization="Empresa Demo",
        city="Bogotá",
        country="Colombia",
        access_level=4,
        consent_status="approved",
    )
    spec = QuerySpec(
        query='"Synthetic Employee 001" "GitHub"',
        employee_id="E001",
        dimension_key="technical_exposure",
        dimension_label="Exposición técnica",
        keyword="GitHub",
        query_type="name_keyword",
    )
    result = SearchResult(
        query=spec.query,
        url="https://github.com/mock/ana",
        title="Synthetic Employee 001 GitHub",
        snippet="Synthetic Employee 001 uses GitHub in a controlled laboratory.",
        source="mock",
    )
    risk_config = {"dimensions": {"technical_exposure": {"severity": 5}}}
    scored = score_result(employee, spec, result, risk_config, min_confidence=0.35)
    assert scored.confidence_score > 0.5
    assert scored.false_positive_risk == "bajo"
