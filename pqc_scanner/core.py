"""Core scanning engine.

The public API traverses the repository via `pqc_scanner.discovery` and runs two
detectors, aggregating their `Finding` lists into one result:

* the AST engine (`pqc_scanner.ast_engine`) on every Python source file — the
  high-signal path; and
* the dependency complement (`pqc_scanner.dependencies`) on every recognized
  manifest — a low-signal lookup that seeds the CBOM.
"""

from __future__ import annotations

from pathlib import Path

from pqc_scanner.ast_engine import analyze_file
from pqc_scanner.dependencies import analyze_manifest
from pqc_scanner.discovery import iter_manifest_files, iter_python_files
from pqc_scanner.findings import Finding


def scan(path: str | Path) -> list[Finding]:
    """Scan a local repository and return the list of findings.

    Args:
        path: Root directory (or single file) to analyze.

    Returns:
        List of `Finding`, in deterministic file-traversal order.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
    """
    findings: list[Finding] = []
    for python_file in iter_python_files(path):
        findings.extend(analyze_file(python_file))
    for manifest in iter_manifest_files(path):
        findings.extend(analyze_manifest(manifest))
    return findings
