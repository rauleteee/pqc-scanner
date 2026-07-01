"""Detectors: inbound adapters that read the filesystem and emit `Finding`s.

Each detector turns a source of evidence into domain findings without knowing
anything about how they will be reported:

* ``discovery`` — walks the repository and selects files to analyze.
* ``ast_engine`` — the high-signal source-code detector (Python AST).
* ``dependencies`` — the dependency-manifest complement (lower signal).

They depend inward on the domain (``findings``, ``rules``) and never on the
output or interface layers. The ``core`` use case is what wires them together.
"""
