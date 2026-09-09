#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cyberdeck.cti.knowledge import (  # noqa: E402
    build_knowledge_manifest,
    rollback_knowledge_source,
    sync_knowledge_sources,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synchronize versioned CTI reference catalogs with last-known-good rollback."
    )
    parser.add_argument("--source", action="append", default=[], help="Source id; repeat to select several.")
    parser.add_argument("--rollback", help="Restore one source from its last-known-good copy.")
    parser.add_argument("--manifest-only", action="store_true", help="Read status without network access.")
    args = parser.parse_args()

    if args.rollback:
        payload = rollback_knowledge_source(args.rollback)
    elif args.manifest_only:
        payload = build_knowledge_manifest()
    else:
        payload = sync_knowledge_sources(args.source or None)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") not in {"failed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
