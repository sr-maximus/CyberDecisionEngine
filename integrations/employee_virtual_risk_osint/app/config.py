from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Settings:
    search_client: str = "mock"
    bing_search_api_key: str = ""
    bing_search_endpoint: str = "https://api.bing.microsoft.com/v7.0/search"
    google_cse_api_key: str = ""
    google_cse_id: str = ""
    hash_salt: str = "change-me-in-production"
    report_password: str = ""
    min_confidence: float = 0.35
    request_timeout_seconds: int = 15
    max_queries_per_employee: int = 500
    catalogs_dir: Path = Path("catalogs")


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        search_client=os.getenv("SEARCH_CLIENT", "mock").strip() or "mock",
        bing_search_api_key=os.getenv("BING_SEARCH_API_KEY", "").strip(),
        bing_search_endpoint=os.getenv("BING_SEARCH_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search").strip(),
        google_cse_api_key=os.getenv("GOOGLE_CSE_API_KEY", "").strip(),
        google_cse_id=os.getenv("GOOGLE_CSE_ID", "").strip(),
        hash_salt=os.getenv("HASH_SALT", "change-me-in-production"),
        report_password=os.getenv("REPORT_PASSWORD", ""),
        min_confidence=float(os.getenv("MIN_CONFIDENCE", "0.35")),
        request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15")),
        max_queries_per_employee=int(os.getenv("MAX_QUERIES_PER_EMPLOYEE", "500")),
    )
