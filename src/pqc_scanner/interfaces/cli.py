"""CLI interface: a thin wrapper over the engine.

All detection lives in the core (`pqc_scanner.scan` / `pqc_scanner.to_cbom`).
This module only parses arguments and renders output: a colored terminal summary
by default, or a CycloneDX CBOM with ``--json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from rich.console import Console
from rich.table import Table

from pqc_scanner import __version__, scan, to_cbom
from pqc_scanner.findings import Finding, Severity

# Display order and color for each severity. The header count built from these is
# the shareable "at-a-glance" verdict, so it gets the strongest styling.
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.MEDIUM, Severity.INFO]
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.INFO: "cyan",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-audit",
        description="Scan a Python codebase for quantum-vulnerable cryptography.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a CycloneDX CBOM to stdout instead of the colored summary.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pqc-audit {__version__}",
    )
    return parser


def _sort_key(finding: Finding) -> tuple[int, str, int]:
    return (_SEVERITY_ORDER.index(finding.severity), finding.path, finding.line)


def _print_summary(console: Console, path: str, findings: list[Finding]) -> None:
    counts = Counter(f.severity for f in findings)

    console.print(f"[bold]pqc-audit[/bold] {__version__}  ·  scanned [bold]{path}[/bold]")

    header = "  ".join(
        f"[{_SEVERITY_STYLE[sev]}]{sev.value}: {counts.get(sev, 0)}[/]"
        for sev in _SEVERITY_ORDER
    )
    console.print(header)

    if not findings:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity")
    table.add_column("Algorithm")
    table.add_column("Usage")
    table.add_column("Location")
    table.add_column("Migrate to")
    for finding in sorted(findings, key=_sort_key):
        table.add_row(
            f"[{_SEVERITY_STYLE[finding.severity]}]{finding.severity.value}[/]",
            finding.algorithm,
            finding.usage,
            f"{finding.path}:{finding.line}",
            finding.migration_target,
        )
    console.print(table)

    # One-line verdict driven by the worst severity present.
    if counts.get(Severity.CRITICAL):
        console.print("[bold red]Verdict: quantum-critical cryptography in use — migration needed.[/bold red]")
    elif counts.get(Severity.MEDIUM):
        console.print("[yellow]Verdict: quantum-weakened cryptography in use — review recommended.[/yellow]")
    else:
        console.print("[green]Verdict: only post-quantum cryptography detected.[/green]")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = _build_parser().parse_args(argv)

    try:
        findings = scan(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(to_cbom(findings), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    _print_summary(Console(), args.path, findings)
    return 0
