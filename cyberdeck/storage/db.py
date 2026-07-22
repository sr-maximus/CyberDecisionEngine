from __future__ import annotations

import os
import json
import sqlite3
from pathlib import Path
from typing import Iterable, Optional

from cyberdeck.schemas import ThreatEvent
from cyberdeck.settings import resolve_path


def connect(db_path: str = "data/cyberdeck.sqlite") -> sqlite3.Connection:
    path = resolve_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            cve TEXT,
            technique TEXT,
            demo INTEGER NOT NULL,
            observed_at TEXT NOT NULL
        )
        """
    )
    existing = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    for name, sql_type in {
        "original_id": "TEXT",
        "canonical_id": "TEXT",
        "content_hash": "TEXT",
        "record_kind": "TEXT",
        "evidence_status": "TEXT",
        "confidence_score": "REAL",
        "relationship_to_scope": "TEXT",
        "validation_result": "TEXT",
        "asset": "TEXT",
        "host": "TEXT",
        "indicator": "TEXT",
        "external_id": "TEXT",
        "evidence_url": "TEXT",
        "vulnerability_status": "TEXT",
        "attack_mapping_status": "TEXT",
        "payload_json": "TEXT",
    }.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE events ADD COLUMN {name} {sql_type}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_canonical_id ON events (canonical_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events (observed_at)")
    conn.commit()
    return conn


def store_events(events: Iterable[ThreatEvent], db_path: str = "data/cyberdeck.sqlite") -> int:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return _store_events_postgres(events, database_url)
    conn = connect(db_path)
    count = 0
    with conn:
        for event in events:
            conn.execute(
                """
                INSERT OR REPLACE INTO events
                (id, original_id, canonical_id, content_hash, title, category, source, cve, technique, demo, observed_at,
                 record_kind, evidence_status, confidence_score, relationship_to_scope, validation_result, asset, host,
                 indicator, external_id, evidence_url, vulnerability_status, attack_mapping_status, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _event_values(event, sqlite=True),
            )
            count += 1
    conn.close()
    return count


def _store_events_postgres(events: Iterable[ThreatEvent], database_url: str) -> int:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - dependency/runtime guard
        raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc

    count = 0
    with psycopg.connect(database_url) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT NOT NULL,
                cve TEXT,
                technique TEXT,
                demo BOOLEAN NOT NULL DEFAULT FALSE,
                observed_at TEXT NOT NULL,
                original_id TEXT,
                canonical_id TEXT,
                content_hash TEXT,
                record_kind TEXT,
                evidence_status TEXT,
                confidence_score DOUBLE PRECISION,
                relationship_to_scope TEXT,
                validation_result TEXT,
                asset TEXT,
                host TEXT,
                indicator TEXT,
                external_id TEXT,
                evidence_url TEXT,
                vulnerability_status TEXT,
                attack_mapping_status TEXT,
                payload JSONB,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        for name, sql_type in {
            "original_id": "TEXT", "canonical_id": "TEXT", "content_hash": "TEXT", "record_kind": "TEXT",
            "evidence_status": "TEXT", "confidence_score": "DOUBLE PRECISION", "relationship_to_scope": "TEXT",
            "validation_result": "TEXT", "asset": "TEXT", "host": "TEXT", "indicator": "TEXT",
            "external_id": "TEXT", "evidence_url": "TEXT", "vulnerability_status": "TEXT",
            "attack_mapping_status": "TEXT", "payload": "JSONB",
        }.items():
            conn.execute(f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {name} {sql_type}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_canonical_id ON events (canonical_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events (observed_at)")
        with conn.cursor() as cur:
            for event in events:
                cur.execute(
                    """
                    INSERT INTO events
                    (id, original_id, canonical_id, content_hash, title, category, source, cve, technique, demo, observed_at,
                     record_kind, evidence_status, confidence_score, relationship_to_scope, validation_result, asset, host,
                     indicator, external_id, evidence_url, vulnerability_status, attack_mapping_status, payload, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, now())
                    ON CONFLICT (id) DO UPDATE SET
                        original_id = EXCLUDED.original_id,
                        canonical_id = EXCLUDED.canonical_id,
                        content_hash = EXCLUDED.content_hash,
                        title = EXCLUDED.title,
                        category = EXCLUDED.category,
                        source = EXCLUDED.source,
                        cve = EXCLUDED.cve,
                        technique = EXCLUDED.technique,
                        demo = EXCLUDED.demo,
                        observed_at = EXCLUDED.observed_at,
                        record_kind = EXCLUDED.record_kind,
                        evidence_status = EXCLUDED.evidence_status,
                        confidence_score = EXCLUDED.confidence_score,
                        relationship_to_scope = EXCLUDED.relationship_to_scope,
                        validation_result = EXCLUDED.validation_result,
                        asset = EXCLUDED.asset,
                        host = EXCLUDED.host,
                        indicator = EXCLUDED.indicator,
                        external_id = EXCLUDED.external_id,
                        evidence_url = EXCLUDED.evidence_url,
                        vulnerability_status = EXCLUDED.vulnerability_status,
                        attack_mapping_status = EXCLUDED.attack_mapping_status,
                        payload = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    _event_values(event, sqlite=False),
                )
                count += 1
        conn.commit()
    return count


def _event_values(event: ThreatEvent, *, sqlite: bool) -> tuple:
    canonical_id = event.canonical_id or event.id
    payload = event.model_dump_json()
    return (
        canonical_id,
        event.id,
        canonical_id,
        event.content_hash,
        event.title,
        event.category,
        event.source,
        event.cve,
        event.technique,
        int(event.demo) if sqlite else event.demo,
        event.observed_at,
        event.record_kind.value,
        event.evidence_status.value,
        event.confidence_score,
        event.relationship_to_scope,
        event.validation_result,
        event.asset,
        event.host,
        event.indicator,
        event.external_id,
        event.evidence_url,
        event.vulnerability_status,
        event.attack_mapping_status,
        payload if sqlite else json.dumps(json.loads(payload)),
    )


def latest_report(reports_dir: str = "reports") -> Optional[Path]:
    directory = resolve_path(reports_dir)
    reports = sorted(directory.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[0] if reports else None
