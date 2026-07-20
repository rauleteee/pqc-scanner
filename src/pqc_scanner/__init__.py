"""PQC Scanner — engine for detecting quantum-vulnerable cryptography.

This package IS the core library. All logic (file traversal, AST analysis, rule
base, classification, findings model) lives here. The interfaces (CLI, MCP,
skill) are thin wrappers in `pqc_scanner.interfaces` that only call this public
API.

Public API:
    scan(path) -> list[Finding]
"""

from __future__ import annotations

from pqc_scanner.core import scan
from pqc_scanner.findings import Classification, Finding, Severity
from pqc_scanner.outputs.cbom import to_cbom
from pqc_scanner.outputs.document import to_html, to_markdown
from pqc_scanner.version import __version__

__all__ = [
    "scan",
    "to_cbom",
    "to_markdown",
    "to_html",
    "Finding",
    "Classification",
    "Severity",
    "__version__",
]
