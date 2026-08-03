from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import yaml

from cyberdeck.frameworks.atlas import ATLAS_MINIMAL
from cyberdeck.frameworks.attack import ATTACK_MINIMAL
from cyberdeck.frameworks.defend import D3FEND_MINIMAL
from cyberdeck.frameworks.f3 import F3_DATA_PATH, F3_SOURCE, validate_f3_records
from cyberdeck.frameworks.iso27001 import ISO27001_2022_SUMMARY
from cyberdeck.frameworks.nist_csf import NIST_CSF_2, NIST_CSF_CATEGORIES
from cyberdeck.frameworks.soc2 import SOC2_TSC
from cyberdeck.schemas import SourceStatus
from cyberdeck.settings import PROJECT_ROOT, load_frameworks_config
from cyberdeck.utils.http import HttpClient


def mappings() -> Dict[str, Dict[str, object]]:
    return {
        "attack_to_defend": {
            "T1566": ["D3-PH", "D3-MFA", "D3-BA"],
            "T1190": ["D3-PM", "D3-NTA", "D3-EAL"],
            "T1078": ["D3-MFA", "D3-DAM", "D3-BA"],
            "T1486": ["D3-EAL", "D3-NTA"],
        },
        "attack_to_nist": {
            "T1566": ["PR.AT", "DE.CM", "RS.CO"],
            "T1190": ["ID.RA", "PR.PS", "DE.CM", "RS.MI"],
            "T1078": ["PR.AA", "DE.CM"],
            "T1486": ["PR.DS", "RC.RP"],
        },
        "attack_to_iso27001": {
            "T1566": ["A.6", "A.5.7", "A.8.16"],
            "T1190": ["A.8.8", "A.8.23", "A.8.28"],
            "T1078": ["A.5.16", "A.8.15"],
            "T1486": ["A.5.24", "A.8.7"],
        },
        "attack_to_soc2": {
            "T1566": ["Security", "Confidentiality"],
            "T1190": ["Security", "Availability"],
            "T1078": ["Security", "Confidentiality", "Privacy"],
            "T1486": ["Availability", "Processing Integrity"],
        },
        "atlas_to_controls": {
            "AML.TA0004": ["PR.AA", "A.5.16", "Security"],
            "AML.TA0007": ["DE.CM", "A.8.16", "Security"],
            "AML.TA0011": ["RC.RP", "A.5.24", "Availability"],
        },
    }


async def sync_frameworks(sync_all: bool = True) -> list[SourceStatus]:
    config = load_frameworks_config().get("frameworks", {})
    out_dir = PROJECT_ROOT / "data" / "frameworks"
    out_dir.mkdir(parents=True, exist_ok=True)
    statuses: list[SourceStatus] = []
    http = HttpClient(timeout=30)

    attack_url = config.get("mitre_attack_enterprise", {}).get("stix_json")
    if sync_all and attack_url:
        try:
            attack_data = await http.get_json(attack_url)
            _write_json(out_dir / "mitre_attack_enterprise.json", attack_data)
            statuses.append(SourceStatus(name="MITRE ATT&CK Enterprise", status="ok", records=len(attack_data.get("objects", [])), mode="real"))
        except Exception as exc:
            _write_json(out_dir / "mitre_attack_enterprise.json", ATTACK_MINIMAL)
            statuses.append(SourceStatus(name="MITRE ATT&CK Enterprise", status="fallback", records=len(ATTACK_MINIMAL["techniques"]), mode="cache", warning=str(exc)))
    else:
        _write_json(out_dir / "mitre_attack_enterprise.json", ATTACK_MINIMAL)
        statuses.append(SourceStatus(name="MITRE ATT&CK Enterprise", status="cache", records=len(ATTACK_MINIMAL["techniques"]), mode="cache"))

    _write_json(out_dir / "mitre_d3fend_minimal.json", D3FEND_MINIMAL)
    _write_json(out_dir / "mitre_atlas_minimal.json", ATLAS_MINIMAL)
    f3_config = config.get("mitre_f3", {})
    f3_records = 0
    if sync_all and f3_config.get("enabled", True) and f3_config.get("data_json"):
        try:
            f3_payload = validate_f3_records(await http.get_json(f3_config["data_json"]))
            _write_json(F3_DATA_PATH, f3_payload)
            f3_records = len(f3_payload)
            statuses.append(
                SourceStatus(
                    name=F3_SOURCE,
                    status="ok",
                    records=f3_records,
                    mode="real",
                )
            )
        except Exception as exc:
            try:
                cached = validate_f3_records(
                    json.loads(F3_DATA_PATH.read_text(encoding="utf-8"))
                )
                f3_records = len(cached)
            except Exception:
                f3_records = 0
            statuses.append(
                SourceStatus(
                    name=F3_SOURCE,
                    status="fallback" if f3_records else "error",
                    records=f3_records,
                    mode="cache",
                    warning=str(exc),
                )
            )
    elif F3_DATA_PATH.exists():
        try:
            f3_records = len(
                validate_f3_records(json.loads(F3_DATA_PATH.read_text(encoding="utf-8")))
            )
        except Exception:
            f3_records = 0
        statuses.append(
            SourceStatus(
                name=F3_SOURCE,
                status="cache" if f3_records else "error",
                records=f3_records,
                mode="cache",
            )
        )
    _write_yaml(out_dir / "nist_csf_2.yml", {"functions": NIST_CSF_2, "categories": NIST_CSF_CATEGORIES})
    _write_yaml(out_dir / "iso27001_2022_summary.yml", ISO27001_2022_SUMMARY)
    _write_yaml(out_dir / "soc2_tsc.yml", SOC2_TSC)
    for file_name, mapping in mappings().items():
        _write_yaml(PROJECT_ROOT / "cyberdeck" / "frameworks" / "mappings" / f"{file_name}.yml", mapping)
    statuses.extend(
        [
            SourceStatus(name="MITRE D3FEND", status="cache", records=len(D3FEND_MINIMAL), mode="cache"),
            SourceStatus(name="MITRE ATLAS", status="cache", records=len(ATLAS_MINIMAL), mode="cache"),
            SourceStatus(name="NIST CSF 2.0", status="cache", records=len(NIST_CSF_CATEGORIES), mode="cache"),
            SourceStatus(name="ISO/IEC 27001:2022", status="summary", records=len(ISO27001_2022_SUMMARY), mode="cache"),
            SourceStatus(name="SOC 2 TSC", status="summary", records=len(SOC2_TSC), mode="cache"),
        ]
    )
    return statuses


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_yaml(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
