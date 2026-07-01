"""Tests for repository file discovery (phase 1)."""

from pathlib import Path

import pytest

from pqc_scanner.detectors.discovery import iter_python_files


def _make_tree(root: Path) -> None:
    """Create a repository-like tree with source, noise and non-Python files."""
    (root / "a.py").write_text("x = 1\n")
    (root / "README.md").write_text("# not python\n")

    (root / "pkg").mkdir()
    (root / "pkg" / "b.py").write_text("y = 2\n")
    (root / "pkg" / "types.pyi").write_text("z: int\n")

    # Directories that must be pruned.
    for noisy in (".git", ".venv", "__pycache__", "node_modules"):
        (root / noisy).mkdir()
        (root / noisy / "ignored.py").write_text("nope = True\n")


def test_finds_python_sources_and_skips_noise(tmp_path):
    _make_tree(tmp_path)

    found = {p.relative_to(tmp_path).as_posix() for p in iter_python_files(tmp_path)}

    assert found == {"a.py", "pkg/b.py", "pkg/types.pyi"}


def test_single_python_file_is_yielded(tmp_path):
    target = tmp_path / "solo.py"
    target.write_text("v = 0\n")

    assert list(iter_python_files(target)) == [target]


def test_single_non_python_file_yields_nothing(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("hello\n")

    assert list(iter_python_files(target)) == []


def test_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_python_files(tmp_path / "does-not-exist"))


def test_order_is_deterministic(tmp_path):
    (tmp_path / "z.py").write_text("")
    (tmp_path / "a.py").write_text("")
    (tmp_path / "m").mkdir()
    (tmp_path / "m" / "b.py").write_text("")

    first = list(iter_python_files(tmp_path))
    second = list(iter_python_files(tmp_path))

    # Repeated runs must match exactly (sorted within each directory level).
    assert first == second
    # Top-level files come before the subdirectory, sorted among themselves.
    rel = [p.relative_to(tmp_path).as_posix() for p in first]
    assert rel == ["a.py", "z.py", "m/b.py"]


def test_custom_exclusions_override_defaults(tmp_path):
    (tmp_path / "keep.py").write_text("")
    (tmp_path / "skip_me").mkdir()
    (tmp_path / "skip_me" / "inner.py").write_text("")

    found = {
        p.relative_to(tmp_path).as_posix()
        for p in iter_python_files(tmp_path, excluded_dirs=frozenset({"skip_me"}))
    }

    assert found == {"keep.py"}
