"""Shareable document output: `Finding` list -> Markdown / self-contained HTML.

This is an output adapter (same layer as `cbom.py` and `report.py`). It carries
no detection logic: it builds on `summarize()` — the plain-data view of a scan —
and renders it into two human-facing, shareable artifacts:

- ``to_markdown`` — a Markdown report (drops into a README, an issue, a PR).
- ``to_html`` — a single self-contained HTML page (no external assets), light/
  dark aware, meant to be opened in a browser or attached to a post.

Both lead with the verdict headline (the shareable marketing line) and follow
with the actionable table (location + suggested post-quantum migration target).
"""

from __future__ import annotations

import html

from pqc_scanner.findings import Finding
from pqc_scanner.outputs.report import summarize

# Worst-severity -> a semantic tone used to color the HTML verdict banner and to
# pick the Markdown headline emphasis. Order matters: first non-zero wins.
_TONE_BY_SEVERITY = ["CRITICAL", "MEDIUM", "INFO"]
_TONE_COLORS = {
    "CRITICAL": "#d12d2d",
    "MEDIUM": "#c77800",
    "INFO": "#1f7ab5",
    "clean": "#2e7d32",
}

_MD_HEADERS = ["Severity", "Algorithm", "Usage", "Location", "Migrate to"]


def _tone(summary: dict) -> str:
    """The dominant tone of a scan, driven by the worst severity present."""
    for severity in _TONE_BY_SEVERITY:
        if summary.get(severity):
            return severity
    return "clean"


def _md_escape(value: str) -> str:
    """Escape the only Markdown-table-breaking character in our cell values."""
    return value.replace("|", "\\|")


def to_markdown(path: str, findings: list[Finding]) -> str:
    """Render a scan as a shareable Markdown report."""
    report = summarize(path, findings)
    s = report["summary"]

    lines = [
        "# Post-Quantum Exposure Report",
        "",
        f"`{report['tool']} {report['version']}` · scanned `{report['path']}`",
        "",
        f"## Verdict: {report['verdict']}",
        "",
        (
            f"**CRITICAL {s['CRITICAL']}** · MEDIUM {s['MEDIUM']} · "
            f"INFO {s['INFO']} · {s['total']} finding"
            f"{'' if s['total'] == 1 else 's'}"
        ),
        "",
    ]

    if report["findings"]:
        lines.append("## Findings")
        lines.append("")
        lines.append("| " + " | ".join(_MD_HEADERS) + " |")
        lines.append("| " + " | ".join("---" for _ in _MD_HEADERS) + " |")
        for row in report["findings"]:
            cells = [
                row["severity"],
                row["algorithm"],
                row["usage"],
                f"`{row['location']}`",
                row["migration_target"],
            ]
            lines.append("| " + " | ".join(_md_escape(c) for c in cells) + " |")
        lines.append("")
    else:
        lines.append("No quantum-vulnerable cryptography detected.")
        lines.append("")

    lines.append(f"> {report['scope_note']}")
    lines.append("")
    return "\n".join(lines)


_HTML_STYLE = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --line: #e3e3e3;
  --row: #fafafa; --chip-bg: #f0f0f0;
  --critical: #d12d2d; --medium: #c77800; --info: #1f7ab5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16181c; --fg: #e8e8e8; --muted: #9aa0a6; --line: #2c2f36;
    --row: #1c1f24; --chip-bg: #23262c;
    --critical: #ff6b6b; --medium: #f0a83c; --info: #5cb3e6;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.25rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 880px; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }
.sub code { background: var(--chip-bg); padding: .1rem .35rem; border-radius: 4px; }
.verdict {
  border-left: 5px solid var(--tone); background: var(--chip-bg);
  padding: 1rem 1.25rem; border-radius: 8px; margin-bottom: 1.25rem;
}
.verdict .label { font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.verdict .text { font-size: 1.1rem; font-weight: 600; color: var(--tone); margin-top: .15rem; }
.chips { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1.75rem; }
.chip {
  display: inline-flex; align-items: baseline; gap: .4rem; padding: .35rem .7rem;
  border-radius: 999px; background: var(--chip-bg); font-size: .85rem;
}
.chip b { font-size: 1rem; }
.chip.critical b { color: var(--critical); }
.chip.medium b { color: var(--medium); }
.chip.info b { color: var(--info); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .6rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
tbody tr:nth-child(even) { background: var(--row); }
td code { font-size: .82rem; word-break: break-all; }
.badge { font-weight: 700; font-size: .78rem; white-space: nowrap; }
.badge.critical { color: var(--critical); }
.badge.medium { color: var(--medium); }
.badge.info { color: var(--info); }
.clean { padding: 1.25rem; text-align: center; color: var(--muted); }
.note { margin-top: 1.75rem; color: var(--muted); font-size: .8rem; border-top: 1px solid var(--line); padding-top: 1rem; }
""".strip()


def _html_chip(label: str, count: int, cls: str) -> str:
    return f'<span class="chip {cls}"><b>{count}</b> {label}</span>'


def to_html(path: str, findings: list[Finding]) -> str:
    """Render a scan as a single self-contained HTML page (no external assets)."""
    report = summarize(path, findings)
    s = report["summary"]
    tone = _tone(s)
    tone_color = _TONE_COLORS[tone]

    e = html.escape  # local alias for brevity
    header = (
        f'<h1>Post-Quantum Exposure Report</h1>'
        f'<p class="sub"><code>{e(report["tool"])} {e(report["version"])}</code> '
        f'· scanned <code>{e(report["path"])}</code></p>'
    )
    verdict = (
        f'<div class="verdict" style="--tone:{tone_color}">'
        f'<div class="label">Verdict</div>'
        f'<div class="text">{e(report["verdict"])}</div></div>'
    )
    chips = (
        '<div class="chips">'
        + _html_chip("CRITICAL", s["CRITICAL"], "critical")
        + _html_chip("MEDIUM", s["MEDIUM"], "medium")
        + _html_chip("INFO", s["INFO"], "info")
        + f'<span class="chip">{s["total"]} total</span>'
        + "</div>"
    )

    if report["findings"]:
        head = "".join(f"<th>{h}</th>" for h in _MD_HEADERS)
        rows = []
        for row in report["findings"]:
            cls = row["severity"].lower()
            rows.append(
                "<tr>"
                f'<td><span class="badge {cls}">{e(row["severity"])}</span></td>'
                f'<td>{e(row["algorithm"])}</td>'
                f'<td>{e(row["usage"])}</td>'
                f'<td><code>{e(row["location"])}</code></td>'
                f'<td>{e(row["migration_target"])}</td>'
                "</tr>"
            )
        body = (
            '<div class="table-wrap"><table><thead><tr>'
            + head
            + "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )
    else:
        body = '<div class="clean">No quantum-vulnerable cryptography detected.</div>'

    note = f'<p class="note">{e(report["scope_note"])}</p>'

    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Post-Quantum Exposure Report</title>"
        f"<style>{_HTML_STYLE}</style></head><body><main>"
        f"{header}{verdict}{chips}{body}{note}"
        "</main></body></html>\n"
    )
