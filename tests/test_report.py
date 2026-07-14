"""Tests for the structured summary output adapter."""

from __future__ import annotations

from pathlib import Path

from pqc_scanner import scan
from pqc_scanner.findings import Severity
from pqc_scanner.outputs.report import summarize

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_summarize_shape_and_verdict():
    findings = scan(EXAMPLES)
    report = summarize(str(EXAMPLES), findings)

    assert report["tool"] == "pqc-audit"
    assert report["path"] == str(EXAMPLES)
    assert set(report["summary"]) == {"CRITICAL", "MEDIUM", "INFO", "total"}
    assert report["summary"]["total"] == len(findings)
    # The example carries RSA/ECC key generation -> a quantum-critical verdict.
    assert report["summary"]["CRITICAL"] >= 1
    assert report["verdict"].startswith("quantum-critical")
    assert "static analysis" in report["scope_note"].lower()


def test_summarize_rows_are_actionable_and_sorted():
    findings = scan(EXAMPLES)
    rows = summarize(str(EXAMPLES), findings)["findings"]

    assert len(rows) == len(findings)
    for row in rows:
        # Each row must carry the actionable essentials: what, where, migrate-to.
        assert row["algorithm"]
        assert row["location"]
        assert row["migration_target"]
        assert row["severity"] in {s.value for s in Severity}
    # Worst-first ordering: no MEDIUM/INFO appears before a CRITICAL.
    order = [r["severity"] for r in rows]
    assert order == sorted(order, key=["CRITICAL", "MEDIUM", "INFO"].index)


def test_summarize_empty_scan_has_clean_verdict(tmp_path):
    report = summarize(str(tmp_path), [])
    assert report["summary"]["total"] == 0
    assert report["findings"] == []
    assert "no cryptography" in report["verdict"]
