"""Tests for the MCP interface (thin wrapper over the engine).

Skipped entirely when the optional ``mcp`` SDK is not installed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="MCP SDK not installed (optional 'mcp' extra)")

from pqc_scanner.interfaces import mcp_server  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_tools_are_registered():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    names = {t.name for t in tools}
    assert {"scan_repository", "generate_cbom"} <= names


def test_scan_repository_tool_returns_summary():
    result = mcp_server.scan_repository(str(EXAMPLES))
    assert result["tool"] == "pqc-scanner"
    assert result["summary"]["CRITICAL"] >= 1
    assert result["verdict"].startswith("quantum-critical")
    assert result["findings"]


def test_generate_cbom_tool_returns_cyclonedx():
    cbom = mcp_server.generate_cbom(str(EXAMPLES))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["components"]


def test_call_tool_through_mcp_dispatch():
    # Exercise the actual MCP tool-dispatch path, not just the Python function.
    # FastMCP returns a list of content blocks; a dict result is serialized to
    # JSON in a TextContent block.
    blocks = asyncio.run(
        mcp_server.mcp.call_tool("scan_repository", {"path": str(EXAMPLES)})
    )
    payload = json.loads(blocks[0].text)
    assert payload["summary"]["CRITICAL"] >= 1
    assert payload["verdict"].startswith("quantum-critical")
