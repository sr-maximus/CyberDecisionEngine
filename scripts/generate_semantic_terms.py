from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config" / "term_registry.json"
TARGET = ROOT / "web" / "src" / "data" / "semanticTerms.generated.ts"
DOC_TARGET = ROOT / "docs" / "TERM_DICTIONARY.md"


def render() -> str:
    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    rows = {
        item["term_id"]: {
            "es": {
                "executive": item["executive_label_es"],
                "technical": item["technical_label_es"],
            },
            "en": {
                "executive": item["english_label"],
                "technical": item["english_label"],
            },
        }
        for item in payload["terms"]
    }
    serialized = json.dumps(rows, ensure_ascii=False, indent=2)
    return (
        "// Generated from config/term_registry.json. Run scripts/generate_semantic_terms.py.\n"
        f"export const semanticRegistryVersion = {json.dumps(payload['version'])};\n"
        f"export const semanticTerms = {serialized} as const;\n\n"
        "export type SemanticTermId = keyof typeof semanticTerms;\n"
        "export function semanticLabel(\n"
        "  termId: SemanticTermId,\n"
        "  language: 'es' | 'en',\n"
        "  audience: 'executive' | 'technical' = 'executive'\n"
        "): string {\n"
        "  return semanticTerms[termId][language][audience];\n"
        "}\n"
    )


def render_dictionary() -> str:
    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    lines = [
        "# Diccionario de términos",
        "",
        f"Versión: `{payload['version']}`. Fuente de verdad: `config/term_registry.json`.",
        "",
    ]
    for item in payload["terms"]:
        lines.extend(
            [
                f"## {item['executive_label_es']} (`{item['term_id']}`)",
                "",
                f"**Definición:** {item['definition']}",
                "",
                f"**Cuándo usarlo:** cuando se satisfacen `{', '.join(item['required_fields']) or 'las condiciones del estado documentado'}` y el estado pertenece a `{', '.join(item['allowed_states']) or 'los estados permitidos por el modelo'}`.",
                "",
                f"**Cuándo no usarlo:** {item['counterexamples'][0] if item['counterexamples'] else 'Cuando falte trazabilidad o el estado sea desconocido.'}",
                "",
                f"**Ejemplo válido:** {item['examples'][0] if item['examples'] else 'Uso con campos requeridos y evidencia trazable.'}",
                "",
                f"**Ejemplo inválido:** {item['counterexamples'][0] if item['counterexamples'] else 'Uso sin campos requeridos.'}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    dictionary = render_dictionary()
    if args.check:
        targets_match = TARGET.exists() and TARGET.read_text(encoding="utf-8") == expected
        docs_match = DOC_TARGET.exists() and DOC_TARGET.read_text(encoding="utf-8") == dictionary
        return 0 if targets_match and docs_match else 1
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(expected, encoding="utf-8")
    DOC_TARGET.parent.mkdir(parents=True, exist_ok=True)
    DOC_TARGET.write_text(dictionary, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
