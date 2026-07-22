from __future__ import annotations

from typing import Dict, List

from cyberdeck.utils.text import extract_cves, extract_domains


def extract_iocs(text: str) -> Dict[str, List[str]]:
    return {"cves": extract_cves(text), "domains": extract_domains(text)}
