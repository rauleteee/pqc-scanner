"""Tests for the shareable Markdown / HTML document output adapter."""

from __future__ import annotations

from pathlib import Path

from pqc_scanner import scan, to_html, to_markdown

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_markdown_has_headline_and_actionable_table():
    findings = scan(EXAMPLES)
    md = to_markdown(str(EXAMPLES), findings)

    # Shareable headline (marketing) driven by the worst severity present.
    assert "# Post-Quantum Exposure Report" in md
    assert "## Verdict: quantum-critical" in md
    # A Markdown table with the actionable columns.
    assert "| Severity | Algorithm | Usage | Location | Migrate to |" in md
    # Every finding is rendered as a row (+2 header rows, +1 headline count line).
    assert md.count("\n|") == len(findings) + 2
    # The scope note rides along as a blockquote.
    assert md.rstrip().splitlines()[-1].startswith(">")


def test_html_is_self_contained_and_escaped():
    findings = scan(EXAMPLES)
    doc = to_html(str(EXAMPLES), findings)

    assert doc.startswith("<!doctype html>")
    assert "</html>" in doc.strip()
    # Self-contained: no external asset references.
    assert "http://" not in doc and "https://" not in doc
    assert "<link" not in doc and "src=" not in doc
    # Carries the verdict and one severity badge per finding.
    assert "Verdict" in doc
    assert doc.count('class="badge') == len(findings)


def test_empty_scan_renders_clean_verdict(tmp_path):
    md = to_markdown(str(tmp_path), [])
    html_doc = to_html(str(tmp_path), [])

    assert "No quantum-vulnerable cryptography detected." in md
    assert "no cryptography detected" in md  # verdict line
    assert "No quantum-vulnerable cryptography detected." in html_doc


def test_html_escapes_angle_brackets_from_paths(tmp_path):
    # A path with an angle bracket must not break out into raw HTML.
    weird = tmp_path / "a<b>.py"
    weird.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    doc = to_html(str(tmp_path), scan(tmp_path))
    assert "a<b>.py" not in doc
    assert "a&lt;b&gt;.py" in doc
