from app.models import Employee, QuerySpec, SearchResult
from app.scoring import score_result


def test_score_result_basic():
    employee = Employee(
        employee_id="E001",
        full_name="Ana María Torres",
        corporate_email="ana.torres@empresa.com",
        organization="Empresa Demo",
        city="Bogotá",
        country="Colombia",
        access_level=4,
        consent_status="approved",
    )
    spec = QuerySpec(
        query='"Ana María Torres" "GitHub"',
        employee_id="E001",
        dimension_key="technical_exposure",
        dimension_label="Exposición técnica",
        keyword="GitHub",
        query_type="name_keyword",
    )
    result = SearchResult(
        query=spec.query,
        url="https://github.com/mock/ana",
        title="Ana María Torres GitHub",
        snippet="Ana María Torres de Empresa Demo usa GitHub para laboratorios.",
        source="mock",
    )
    risk_config = {"dimensions": {"technical_exposure": {"severity": 5}}}
    scored = score_result(employee, spec, result, risk_config, min_confidence=0.35)
    assert scored.confidence_score > 0.5
    assert scored.false_positive_risk == "bajo"
