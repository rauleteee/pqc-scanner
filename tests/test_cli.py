"""Tests for the CLI wrapper (phase 5)."""

from __future__ import annotations

import json

import pytest

from pqc_scanner.interfaces.cli import main

SAMPLE = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
)


def test_summary_reports_counts_and_verdict(tmp_path, capsys):
    (tmp_path / "m.py").write_text(SAMPLE)

    exit_code = main([str(tmp_path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "pqc-audit" in out
    assert "CRITICAL: 1" in out
    assert "RSA-2048" in out
    assert "migration needed" in out


def test_clean_tree_reports_no_findings(tmp_path, capsys):
    (tmp_path / "safe.py").write_text("x = 1\n")

    exit_code = main([str(tmp_path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "No quantum-vulnerable cryptography detected." in out


def test_json_flag_emits_valid_cbom(tmp_path, capsys):
    (tmp_path / "m.py").write_text(SAMPLE)

    exit_code = main([str(tmp_path), "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    doc = json.loads(out)  # stdout must be pure JSON with --json
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["components"][0]["name"] == "RSA-2048"


def test_markdown_flag_emits_report(tmp_path, capsys):
    (tmp_path / "m.py").write_text(SAMPLE)

    exit_code = main([str(tmp_path), "--markdown"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "# Post-Quantum Exposure Report" in out
    assert "| Severity | Algorithm |" in out
    assert "RSA-2048" in out


def test_html_flag_emits_self_contained_page(tmp_path, capsys):
    (tmp_path / "m.py").write_text(SAMPLE)

    exit_code = main([str(tmp_path), "--html"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert out.startswith("<!doctype html>")
    assert "RSA-2048" in out


def test_output_flags_are_mutually_exclusive(tmp_path):
    with pytest.raises(SystemExit):
        main([str(tmp_path), "--json", "--markdown"])


def test_missing_path_returns_error_code(capsys):
    exit_code = main(["/definitely/not/here"])
    err = capsys.readouterr().err

    assert exit_code == 2
    assert "error:" in err


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "pqc-audit" in capsys.readouterr().out
