"""Single source of truth for the package version.

Kept as a dependency-free leaf module so any layer (the public facade, the CBOM
and report output adapters, the packaging metadata) can read the version without
importing the package facade — which would otherwise create an import cycle.
``pyproject.toml`` reads ``__version__`` from here via setuptools' dynamic
version, so the number is declared in exactly one place.
"""

from __future__ import annotations

__version__ = "0.1.1"
