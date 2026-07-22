from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openpyxl import load_workbook


ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_DIR = ROOT / "data" / "frameworks"
SCENARIO_DIR = ROOT / "data" / "scenarios"


def worksheet_rows(path: Path, sheet_name: str) -> list[dict[str, Any]]:
    workbook = load_workbook(path, read_only=True, data_only=True)
    sheet = workbook[sheet_name]
    iterator = sheet.iter_rows(values_only=True)
    headers = [str(cell).strip() if cell is not None else "" for cell in next(iterator)]
    rows: list[dict[str, Any]] = []
    for raw in iterator:
        row = {headers[index]: value for index, value in enumerate(raw) if index < len(headers)}
        if any(value not in (None, "") for value in row.values()):
            rows.append(row)
    return rows


def load_disarm() -> dict[str, Any]:
    path = FRAMEWORK_DIR / "DISARM_FRAMEWORKS_MASTER.xlsx"
    tactics = {
        str(row.get("disarm_id")): {
            "id": str(row.get("disarm_id")),
            "name": str(row.get("name") or ""),
            "phase_id": str(row.get("phase_id") or ""),
            "summary": str(row.get("summary") or ""),
        }
        for row in worksheet_rows(path, "tactics")
        if row.get("disarm_id") and row.get("name")
    }
    techniques = []
    for row in worksheet_rows(path, "techniques"):
        disarm_id = str(row.get("disarm_id") or "")
        name = str(row.get("name") or "")
        if not disarm_id.startswith("T") or not name:
            continue
        tactic_id = str(row.get("tactic_id") or "")
        usable = str(row.get("Usable") or "").strip().lower()
        techniques.append(
            {
                "id": disarm_id,
                "name": name,
                "summary": str(row.get("summary") or ""),
                "tactic_id": tactic_id,
                "tactic": tactics.get(tactic_id, {}).get("name", tactic_id),
                "usable": usable == "yes",
            }
        )
    payload = {
        "source": "DISARMFoundation/DISARMframeworks-20-observable",
        "source_url": "https://github.com/DISARMFoundation/DISARMframeworks-20-observable",
        "tactics": list(tactics.values()),
        "techniques": techniques,
    }
    (FRAMEWORK_DIR / "disarm_observable.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def load_attack() -> list[dict[str, Any]]:
    path = FRAMEWORK_DIR / "mitre_attack_enterprise.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id", "")
                break
        tactics = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", []) if phase.get("phase_name")]
        rows.append(
            {
                "id": external_id or obj.get("id", ""),
                "name": obj.get("name", ""),
                "tactics": tactics,
                "description": obj.get("description", ""),
            }
        )
    return rows


def load_simple_json(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [{"id": key, "name": value} for key, value in data.items()]


def scenario_record(index: int, attack: dict[str, Any], disarm: dict[str, Any], d3fend: dict[str, str], atlas: dict[str, str], sector: str) -> dict[str, Any]:
    return {
        "id": f"CDE-SCN-{index:04d}",
        "status": "preventive_template",
        "sector": sector,
        "title_es": f"{attack['name']} con narrativa DISARM: {disarm['name']}",
        "title_en": f"{attack['name']} with DISARM narrative: {disarm['name']}",
        "frameworks": {
            "attack": {"id": attack["id"], "name": attack["name"], "tactics": attack.get("tactics", [])[:3]},
            "disarm": {"id": disarm["id"], "name": disarm["name"], "tactic": disarm.get("tactic", "")},
            "d3fend": d3fend,
            "atlas": atlas,
        },
        "scores": {
            "likelihood": 0.0,
            "impact": 0.0,
            "inherent_risk": 0.0,
            "control_effectiveness": 0.0,
            "residual_risk": 0.0,
            "geographic_relevance": 0.0,
        },
        "math": {
            "z": 0.0,
            "formula": "not_calculated_until_current_run_evidence_is_validated",
            "variables": {},
        },
        "recommendation_es": f"Si la evidencia actual coincide de forma explícita, validar el activo y contrastar la opción defensiva {d3fend['id']} {d3fend['name']} antes de decidir tratamiento.",
        "recommendation_en": f"If current evidence matches explicitly, validate the asset and test defensive option {d3fend['id']} {d3fend['name']} before deciding treatment.",
        "strategic_question_es": "¿La narrativa puede alterar confianza, continuidad, fraude, reputación o presión regulatoria en los mercados o países del alcance?",
        "strategic_question_en": "Can the narrative alter trust, continuity, fraud, reputation or regulatory pressure in the markets or countries under scope?",
    }


def build_scenarios() -> dict[str, Any]:
    disarm = load_disarm()
    attack = load_attack()
    d3fend = load_simple_json(FRAMEWORK_DIR / "mitre_d3fend_minimal.json")
    atlas = load_simple_json(FRAMEWORK_DIR / "mitre_atlas_minimal.json")
    sectors = ["financial", "government", "energy", "healthcare", "telecom", "retail", "education", "transport", "technology", "media"]
    usable_disarm = [item for item in disarm["techniques"] if item["usable"]] or disarm["techniques"]
    attack = attack[:90]
    usable_disarm = usable_disarm[:70]

    records = []
    index = 1
    for sector in sectors:
        for atk in attack:
            for dis in usable_disarm:
                d3 = d3fend[(index - 1) % len(d3fend)]
                atl = atlas[(index - 1) % len(atlas)]
                records.append(scenario_record(index, atk, dis, d3, atl, sector))
                index += 1
                if len(records) >= 1500:
                    payload = scenario_payload(records)
                    write_scenarios(payload)
                    return payload
    payload = scenario_payload(records)
    write_scenarios(payload)
    return payload


def scenario_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "generated_by": "CyberDecisionEngine",
        "version": "2026.07.evidence-gated-attack-d3fend-atlas-disarm",
        "scenario_count": len(records),
        "sources": [
            "MITRE ATT&CK Enterprise STIX",
            "MITRE D3FEND minimal local mapping",
            "MITRE ATLAS minimal local mapping",
            "DISARM Foundation DISARM 2.0 Observations Framework",
        ],
        "math_model": {
            "es": "La biblioteca contiene plantillas preventivas sin probabilidad ni riesgo precalculado. La corrida solo prioriza una plantilla cuando evidencia directa, validada o confirmada satisface criterios explícitos ATT&CK, ATLAS o DISARM.",
            "en": "The library contains preventive templates without precomputed probability or risk. A run only prioritizes a template when direct, validated or confirmed evidence satisfies explicit ATT&CK, ATLAS or DISARM criteria.",
            "formula": "scenario_support = assured_current_run_evidence_only",
        },
        "scenarios": records,
    }


def write_scenarios(payload: dict[str, Any]) -> None:
    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    (SCENARIO_DIR / "cyber_scenario_library.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    payload = build_scenarios()
    print(f"Generated {payload['scenario_count']} scenarios")
