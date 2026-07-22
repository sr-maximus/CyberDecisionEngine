from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List

from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_PATH = PROJECT_ROOT / "config" / "term_registry.json"


class SemanticValidationError(ValueError):
    pass


class TermDefinition(BaseModel):
    term_id: str
    executive_label_es: str
    technical_label_es: str
    english_label: str
    definition: str
    allowed_states: List[str] = Field(default_factory=list)
    prohibited_states: List[str] = Field(default_factory=list)
    required_fields: List[str] = Field(default_factory=list)
    examples: List[str] = Field(default_factory=list)
    counterexamples: List[str] = Field(default_factory=list)
    replacement_terms: List[str] = Field(default_factory=list)
    version: str = "1.0.0"


class TermRegistry:
    def __init__(self, terms: Iterable[TermDefinition], version: str = "1.0.0") -> None:
        self.version = version
        self._terms = {term.term_id: term.model_copy(update={"version": version}) for term in terms}
        if len(self._terms) < 1:
            raise SemanticValidationError("TermRegistry cannot be empty.")

    @classmethod
    def load(cls, path: Path = DEFAULT_REGISTRY_PATH) -> "TermRegistry":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls([TermDefinition(**item) for item in payload.get("terms", [])], str(payload.get("version", "1.0.0")))

    def get(self, term_id: str) -> TermDefinition:
        try:
            return self._terms[term_id]
        except KeyError as exc:
            raise SemanticValidationError(f"Unknown semantic term: {term_id}") from exc

    @property
    def terms(self) -> Dict[str, TermDefinition]:
        return dict(self._terms)

    def label(self, term_id: str, *, language: str = "es", audience: str = "executive") -> str:
        term = self.get(term_id)
        if language == "en":
            return term.english_label
        return term.technical_label_es if audience == "technical" else term.executive_label_es

    def labels(self, *, language: str = "es", audience: str = "executive") -> Dict[str, str]:
        return {term_id: self.label(term_id, language=language, audience=audience) for term_id in self._terms}

    def validate(self, term_id: str, payload: Dict[str, Any]) -> None:
        term = self.get(term_id)
        missing = [field for field in term.required_fields if not _present(payload.get(field))]
        if missing:
            raise SemanticValidationError(f"{term_id} requires: {', '.join(missing)}")

        state = str(payload.get("state") or payload.get("status") or payload.get("validation_status") or payload.get("value_status") or "")
        if state and state in term.prohibited_states:
            raise SemanticValidationError(f"{term_id} prohibits state '{state}'.")
        if term_id == "validated_finding" and payload.get("validation_status") not in {"validated", "confirmed"}:
            raise SemanticValidationError("validated_finding requires validation_status validated or confirmed.")
        if term_id == "direct_evidence":
            if payload.get("direct_relationship") is not True:
                raise SemanticValidationError("direct_evidence requires a direct relationship.")
            if payload.get("validation_method") in {"text_match", "keyword_match", "textual_coincidence"}:
                raise SemanticValidationError("Textual coincidence alone is not direct evidence.")
        if term_id == "confirmed":
            if payload.get("confirmation_threshold_passed") is not True:
                raise SemanticValidationError("confirmed requires confirmation_threshold_passed=true.")
            if payload.get("unresolved_critical_contradiction") is True:
                raise SemanticValidationError("confirmed cannot have an unresolved critical contradiction.")
        if term_id == "alert" and not _positive_threshold(payload.get("threshold")):
            raise SemanticValidationError("alert requires an explicit threshold.")
        if term_id == "risk" and (payload.get("likelihood") is None or payload.get("impact") is None):
            raise SemanticValidationError("risk requires likelihood and impact.")
        if term_id == "probability" and payload.get("prediction_is_calibrated") is not True:
            raise SemanticValidationError("probability requires a calibrated model.")
        if term_id == "attack_observed" and not payload.get("adversary_telemetry"):
            raise SemanticValidationError("ATT&CK observed requires adversary telemetry.")
        if term_id == "observed_zero":
            valid_zero = (
                payload.get("value_status") == "observed_zero"
                and payload.get("successful_query") is True
                and _positive_threshold(payload.get("valid_denominator"))
                and payload.get("adequate_coverage") is True
            )
            if not valid_zero:
                raise SemanticValidationError("0 % requires observed_zero, a successful query, valid denominator and adequate coverage.")


def _present(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, tuple, set, dict)):
        return bool(value)
    return True


def _positive_threshold(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return bool(str(value or "").strip())


@lru_cache(maxsize=1)
def get_term_registry() -> TermRegistry:
    return TermRegistry.load()
