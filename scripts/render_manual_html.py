from __future__ import annotations

import argparse
import html
import re
import unicodedata
from pathlib import Path

from markdown_it import MarkdownIt


def _slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", "-", ascii_value).strip("-") or "section"


def render_manual(source: Path, output: Path) -> None:
    markdown = source.read_text(encoding="utf-8")
    parser = MarkdownIt("commonmark", {"html": False}).enable("table")
    tokens = parser.parse(markdown)
    headings: list[tuple[int, str, str]] = []
    used: dict[str, int] = {}

    for index, token in enumerate(tokens):
        if token.type != "heading_open" or index + 1 >= len(tokens):
            continue
        label = tokens[index + 1].content.strip()
        base = _slug(label)
        used[base] = used.get(base, 0) + 1
        anchor = base if used[base] == 1 else f"{base}-{used[base]}"
        token.attrSet("id", anchor)
        headings.append((int(token.tag[1]), label, anchor))

    body = parser.renderer.render(tokens, parser.options, {})
    toc = "".join(
        f'<a class="toc-level-{level}" href="#{anchor}">{html.escape(label)}</a>'
        for level, label, anchor in headings
        if level <= 3
    )
    document = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Manual integral | CyberDecisionEngine</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#eef3f5; --surface:#fff; --text:#172332; --muted:#5e7080; --line:#d6e0e5; --accent:#087f83; --code:#11202a; }}
    @media (prefers-color-scheme:dark) {{ :root {{ --bg:#0c151b; --surface:#142129; --text:#edf5f6; --muted:#a9bac3; --line:#2d424d; --accent:#42c3c4; --code:#091116; }} }}
    * {{ box-sizing:border-box; }} html {{ scroll-behavior:smooth; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.65 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    .layout {{ max-width:1440px; margin:0 auto; display:grid; grid-template-columns:280px minmax(0,1fr); gap:28px; padding:24px; }}
    aside {{ position:sticky; top:20px; height:calc(100vh - 40px); overflow:auto; padding:18px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }}
    aside strong {{ display:block; margin-bottom:12px; font-size:16px; }}
    aside a {{ display:block; padding:6px 8px; border-left:2px solid transparent; color:var(--muted); text-decoration:none; font-size:12px; line-height:1.35; }}
    aside a:hover {{ border-color:var(--accent); color:var(--accent); }} .toc-level-2 {{ padding-left:18px; }} .toc-level-3 {{ padding-left:30px; }}
    main {{ min-width:0; padding:34px 44px 64px; border:1px solid var(--line); border-radius:8px; background:var(--surface); box-shadow:0 18px 45px rgba(16,34,44,.08); }}
    h1,h2,h3 {{ line-height:1.25; scroll-margin-top:24px; }} h1 {{ font-size:32px; }} h2 {{ margin-top:38px; padding-bottom:8px; border-bottom:1px solid var(--line); font-size:23px; }} h3 {{ margin-top:28px; font-size:17px; }}
    p,li {{ max-width:92ch; }} a {{ color:var(--accent); }} table {{ width:100%; border-collapse:collapse; font-size:13px; }} th,td {{ padding:9px 10px; border:1px solid var(--line); text-align:left; vertical-align:top; }} th {{ background:color-mix(in srgb,var(--accent) 9%,var(--surface)); }}
    pre {{ overflow:auto; padding:16px; border-radius:6px; background:var(--code); color:#e6f4f4; }} code {{ font-family:"SFMono-Regular",Consolas,monospace; font-size:.9em; }} :not(pre)>code {{ padding:2px 5px; border-radius:4px; background:color-mix(in srgb,var(--accent) 10%,var(--surface)); }}
    blockquote {{ margin-left:0; padding:10px 16px; border-left:3px solid var(--accent); background:color-mix(in srgb,var(--accent) 7%,var(--surface)); color:var(--muted); }}
    @media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; padding:12px; }} aside {{ position:relative; top:0; height:auto; max-height:340px; }} main {{ padding:24px 20px 48px; }} }}
    @media print {{ body {{ background:#fff; }} .layout {{ display:block; padding:0; }} aside {{ display:none; }} main {{ border:0; box-shadow:none; padding:0; }} }}
  </style>
</head>
<body><div class="layout"><aside><strong>CyberDecisionEngine</strong>{toc}</aside><main>{body}</main></div></body>
</html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the CyberDecisionEngine manual as navigable HTML.")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    render_manual(args.source, args.output)


if __name__ == "__main__":
    main()
