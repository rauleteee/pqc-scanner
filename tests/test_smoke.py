"""Phase 0 smoke test: the core exposes its API and the CLI wraps it."""

from pqc_scanner import __version__, scan
from pqc_scanner.interfaces.cli import main


def test_version_defined():
    assert __version__


def test_scan_returns_list():
    # The core always responds with a list (contents depend on the tree).
    assert isinstance(scan("."), list)


def test_cli_starts(capsys):
    exit_code = main([])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "pqc-audit" in captured.out
