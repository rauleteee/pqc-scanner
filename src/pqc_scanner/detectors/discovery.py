"""Repository file discovery.

Walks a repository root and yields the Python source files to be analyzed,
pruning noisy directories (VCS metadata, virtual environments, caches, build
artifacts). Keeping traversal here — separate from detection — lets every
interface share the exact same notion of "what counts as a scannable file".
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

# Directory names that never hold first-party source worth scanning. Pruning
# them keeps traversal fast and avoids noise from vendored/generated code and
# virtual environments.
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "node_modules",
        "build",
        "dist",
        ".eggs",
    }
)

# Suffixes treated as Python source.
PYTHON_SUFFIXES: frozenset[str] = frozenset({".py", ".pyi"})

# Dependency manifest filenames understood by the dependency complement
# (phase 6). Matched by exact filename anywhere in the tree.
MANIFEST_NAMES: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile.lock",
    }
)


def iter_python_files(
    root: str | Path,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Iterator[Path]:
    """Yield the Python source files under ``root``.

    Args:
        root: Directory to walk, or a single Python file.
        excluded_dirs: Directory names to prune anywhere in the tree.

    Yields:
        Paths to ``.py``/``.pyi`` files in deterministic (sorted) order.

    Raises:
        FileNotFoundError: If ``root`` does not exist.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    # A single file is a valid target: yield it only if it is Python source.
    if root.is_file():
        if root.suffix in PYTHON_SUFFIXES:
            yield root
        return

    # Do not follow symlinks, so symlink loops cannot trap the walk.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune excluded directories in place so os.walk does not descend into
        # them; sorting keeps the traversal order deterministic.
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dirs)
        for filename in sorted(filenames):
            if Path(filename).suffix in PYTHON_SUFFIXES:
                yield Path(dirpath) / filename


def iter_manifest_files(
    root: str | Path,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Iterator[Path]:
    """Yield the dependency manifest files under ``root``.

    Mirrors :func:`iter_python_files` but matches manifests by exact filename
    (``MANIFEST_NAMES``) rather than suffix, so the dependency complement shares
    the same traversal and pruning rules as the AST engine.

    Args:
        root: Directory to walk, or a single manifest file.
        excluded_dirs: Directory names to prune anywhere in the tree.

    Yields:
        Paths to recognized manifest files in deterministic (sorted) order.

    Raises:
        FileNotFoundError: If ``root`` does not exist.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    # A single file is a valid target: yield it only if it is a known manifest.
    if root.is_file():
        if root.name in MANIFEST_NAMES:
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dirs)
        for filename in sorted(filenames):
            if filename in MANIFEST_NAMES:
                yield Path(dirpath) / filename
