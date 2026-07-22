from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field, model_validator

from cyberdeck.settings import PROJECT_ROOT


class LocalizedText(BaseModel):
    es: str
    en: str


class MethodVariable(BaseModel):
    id: str
    label: str
    range: str


class MethodologyRecord(BaseModel):
    methodId: str
    name: LocalizedText
    version: str
    status: Literal["active", "reference_only", "inactive"]
    purpose: LocalizedText
    formula: str
    variables: List[MethodVariable] = Field(default_factory=list)
    weights: Dict[str, float] = Field(default_factory=dict)
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    missingDataPolicy: str
    deduplicationPolicy: str
    inputFields: List[str]
    outputRange: str
    interpretation: LocalizedText
    limitations: List[str]
    example: str
    frameworkReferences: List[str]
    implementationReference: str
    testReferences: List[str]
    effectiveFrom: str


class MethodologyRegistry(BaseModel):
    registryVersion: str
    effectiveFrom: str
    methods: List[MethodologyRecord]

    @model_validator(mode="after")
    def validate_registry(self) -> "MethodologyRegistry":
        method_ids = [item.methodId for item in self.methods]
        if len(method_ids) != len(set(method_ids)):
            raise ValueError("Methodology methodId values must be unique")
        for item in self.methods:
            if item.status == "active" and (not item.implementationReference or not item.testReferences):
                raise ValueError(f"Active method {item.methodId} requires implementation and tests")
        return self

    def public_payload(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


@lru_cache(maxsize=1)
def load_methodology_registry(path: Path | None = None) -> MethodologyRegistry:
    registry_path = path or PROJECT_ROOT / "config" / "methodologies.json"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    return MethodologyRegistry.model_validate(payload)
