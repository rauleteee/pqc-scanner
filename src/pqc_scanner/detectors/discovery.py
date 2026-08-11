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

# Config/infra files where crypto plausibly appears as strings (SSH keys/configs,
# PEM material, key-gen commands in Dockerfiles/CI/shell). The config detector's
# patterns are anchored, so this set only bounds *where* to look (avoiding a scan
# of every file in the repo), not what counts as a hit.
CONFIG_NAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        "Containerfile",
        "sshd_config",
        "ssh_config",
        "authorized_keys",
        "nginx.conf",
    }
)
# Filename prefixes (variant configs like ``Dockerfile.prod`` / ``.env.local``).
CONFIG_NAME_PREFIXES: tuple[str, ...] = ("Dockerfile", ".env")
CONFIG_SUFFIXES: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".crt",
        ".cer",
        ".pub",
        ".conf",
        ".cnf",
        ".yml",
        ".yaml",
        ".sh",
        ".bash",
        ".dockerfile",
    }
)


def _is_config_file(name: str) -> bool:
    """Whether a filename is a config/infra file the config detector should read."""
    if name in CONFIG_NAMES:
        return True
    if name.startswith(CONFIG_NAME_PREFIXES):
        return True
    return Path(name).suffix in CONFIG_SUFFIXES


# Encrypted-artifact / key-material file extensions the data-at-rest detector reads
# by header/metadata (no decryption). OpenPGP (.gpg/.pgp/.asc) and age (.age).
ARTIFACT_SUFFIXES: frozenset[str] = frozenset({".gpg", ".pgp", ".asc", ".age"})


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


def iter_config_files(
    root: str | Path,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Iterator[Path]:
    """Yield the config/infra files under ``root`` for the configuration detector.

    Mirrors :func:`iter_python_files` but selects files by name/prefix/suffix
    (``_is_config_file``) rather than Python source, sharing the same traversal
    and pruning rules as the other detectors.

    Args:
        root: Directory to walk, or a single config file.
        excluded_dirs: Directory names to prune anywhere in the tree.

    Yields:
        Paths to recognized config/infra files in deterministic (sorted) order.

    Raises:
        FileNotFoundError: If ``root`` does not exist.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    if root.is_file():
        if _is_config_file(root.name):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dirs)
        for filename in sorted(filenames):
            if _is_config_file(filename):
                yield Path(dirpath) / filename


def iter_artifact_files(
    root: str | Path,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Iterator[Path]:
    """Yield the encrypted-artifact / key files under ``root`` (by extension).

    Mirrors the other iterators; selects OpenPGP and age files for the data-at-rest
    detector, sharing the same traversal and pruning rules.

    Raises:
        FileNotFoundError: If ``root`` does not exist.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    if root.is_file():
        if root.suffix.lower() in ARTIFACT_SUFFIXES:
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dirs)
        for filename in sorted(filenames):
            if Path(filename).suffix.lower() in ARTIFACT_SUFFIXES:
                yield Path(dirpath) / filename
