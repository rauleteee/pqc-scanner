"""Structured summary output: `Finding` list -> an agent/JSON-friendly report.

This is an output adapter (same layer as `cbom.py`). It shapes findings into a
compact, self-describing dict: the at-a-glance verdict (the shareable headline)
plus per-finding rows carrying the actionable detail (location + what to migrate
to). The CLI renders its own colored view; this is the plain-data view reused by
the MCP server and any other programmatic caller.
"""

from __future__ import annotations

from collections import Counter

from pqc_scanner import __version__
from pqc_scanner.findings import Finding, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.MEDIUM, Severity.INFO]


def _verdict(counts: Counter) -> str:
    """One-line verdict driven by the worst severity present."""
    if counts.get(Severity.CRITICAL):
        return "quantum-critical cryptography in use — migration needed"
    if counts.get(Severity.MEDIUM):
        return "quantum-weakened cryptography in use — review recommended"
    if counts.get(Severity.INFO):
        return "only post-quantum cryptography detected"
    return "no cryptography detected in scope"


def _location(finding: Finding) -> str:
    """A single human-readable locator for the finding."""
    if finding.origin == "dependency":
        pkg = f"{finding.library} {finding.version}" if finding.version else finding.library
        return f"{pkg} ({finding.path}:{finding.line})"
    return f"{finding.path}:{finding.line}"


def _finding_row(finding: Finding) -> dict:
    return {
        "severity": finding.severity.value,
        "algorithm": finding.algorithm,
        "usage": finding.usage,
        "classification": finding.classification.value,
        "origin": finding.origin,
        "location": _location(finding),
        "library": finding.library,
        "migration_target": finding.migration_target,
    }


def summarize(path: str, findings: list[Finding]) -> dict:
    """Return a structured, JSON-serializable summary of a scan.

    Shape: a headline (counts + verdict) followed by the findings, sorted worst
    first, each with its location and suggested post-quantum migration target.
    """
    counts = Counter(f.severity for f in findings)
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.path, f.line),
    )
    return {
        "tool": "pqc-scanner",
        "version": __version__,
        "path": path,
        "summary": {
            "CRITICAL": counts.get(Severity.CRITICAL, 0),
            "MEDIUM": counts.get(Severity.MEDIUM, 0),
            "INFO": counts.get(Severity.INFO, 0),
            "total": len(findings),
        },
        "verdict": _verdict(counts),
        "findings": [_finding_row(f) for f in ordered],
        "scope_note": (
            "Static analysis of Python source and dependency manifests (v1). "
            "Reports quantum-vulnerable cryptography by CBOM classification "
            "(Shor/Grover) with a suggested migration target per finding; it does "
            "not execute code or inspect runtime, binaries, or live endpoints."
        ),
    }
