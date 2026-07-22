from __future__ import annotations

import re
from html import escape
from typing import Iterable, List


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def extract_cves(text: str) -> List[str]:
    return sorted({match.upper() for match in CVE_RE.findall(text or "")})


def extract_domains(text: str) -> List[str]:
    return sorted({match.lower() for match in DOMAIN_RE.findall(text or "")})


def contains_any(text: str, keywords: Iterable[str]) -> bool:
    lowered = (text or "").lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def html_escape(value: object) -> str:
    return escape(str(value), quote=True)
