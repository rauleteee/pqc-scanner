"""Crypto knowledge base (domain).

All of the scanner's cryptographic knowledge lives here, independent of how files
are parsed: the code rule base consulted by the AST engine, the dependency rule
base consulted by the manifest lookup, and the shared post-quantum migration
targets both point at. Detectors (adapters) import from this package; nothing
here imports a detector.
"""

from __future__ import annotations

from pqc_scanner.knowledge.code import (
    CRYPTO_ROOTS,
    DISPATCH_RULES,
    PKEY_TYPE_RULES,
    ROOT_RULES,
    RULES,
    DispatchRule,
    Rule,
    lookup_dispatch,
    lookup_rule,
)
from pqc_scanner.knowledge.dependencies import DEPENDENCY_RULES, DependencyRule

__all__ = [
    "CRYPTO_ROOTS",
    "DISPATCH_RULES",
    "PKEY_TYPE_RULES",
    "ROOT_RULES",
    "RULES",
    "DispatchRule",
    "Rule",
    "lookup_dispatch",
    "lookup_rule",
    "DEPENDENCY_RULES",
    "DependencyRule",
]
