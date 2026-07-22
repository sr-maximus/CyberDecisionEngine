#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberdeck.reporting.validator import validate_report_bundle
from cyberdeck.schemas import RunContext


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a CyberDecisionEngine report bundle.")
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--executive", required=True, type=Path)
    parser.add_argument("--technical", type=Path)
    args = parser.parse_args()
    technical = args.technical or args.executive.with_name(
        f"{args.executive.stem}-technical{args.executive.suffix}"
    )
    context = RunContext.model_validate_json(args.context.read_text(encoding="utf-8"))
    result = validate_report_bundle(context, args.executive, technical)
    print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))
    return 2 if result.status == "rejected" else 0


if __name__ == "__main__":
    raise SystemExit(main())
