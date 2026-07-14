"""MCP interface: a thin wrapper exposing the engine as tools for agents.

Like the CLI, this holds no detection logic — it only adapts the core
(`pqc_scanner.scan` / `to_cbom` / `summarize`) to the Model Context Protocol, so
any MCP-capable agent (Claude, Cursor, …) can scan a local repository by talking.

The MCP SDK is an optional dependency: install with ``pip install pqc-audit[mcp]``.
Run the server (stdio transport) with ``pqc-audit-mcp`` or
``python -m pqc_scanner.interfaces.mcp_server``.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from pqc_scanner import scan, to_cbom
from pqc_scanner.outputs.report import summarize

mcp = FastMCP(
    "pqc-audit",
    instructions=(
        "Detects quantum-vulnerable cryptography (RSA, ECC, DH, …) in a local "
        "Python codebase and its dependency manifests, and suggests post-quantum "
        "migration targets. Use scan_repository for an at-a-glance verdict plus "
        "actionable findings, or generate_cbom for a full CycloneDX inventory."
    ),
)


@mcp.tool()
def scan_repository(path: str = ".") -> dict:
    """Scan a local file or directory for quantum-vulnerable cryptography.

    Returns a summary: counts by severity (CRITICAL = broken by Shor, MEDIUM =
    weakened by Grover, INFO = already post-quantum), a one-line verdict, and the
    findings — each with its location and a suggested post-quantum migration
    target (e.g. key exchange -> ML-KEM, signatures -> ML-DSA).

    Args:
        path: A local path to scan (default: current directory).
    """
    return summarize(path, scan(path))


@mcp.tool()
def generate_cbom(path: str = ".") -> dict:
    """Scan a local path and return a CycloneDX 1.6 CBOM (cryptographic BOM).

    Same detection as scan_repository, but shaped as a standard CycloneDX
    Cryptography Bill of Materials suitable for tooling and compliance workflows.

    Args:
        path: A local path to scan (default: current directory).
    """
    return to_cbom(scan(path))


def main() -> None:
    """Console entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
