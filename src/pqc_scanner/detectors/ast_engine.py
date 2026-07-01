"""AST detection engine (phase 2, priority path).

Parses a Python source file with the standard-library ``ast`` module and emits a
`Finding` for every call that (a) resolves — through the file's own imports — to
a known cryptographic package, and (b) matches a rule in the rule base.

Using the AST rather than regex is what keeps false positives low: a comment or a
variable named ``rsa.generate_private_key`` is not a `Call` node, so it is never
reported. Detection deliberately requires both an import from a crypto root and a
matching call, not just the presence of a name.
"""

from __future__ import annotations

import ast
from pathlib import Path

from pqc_scanner.findings import Finding
from pqc_scanner.rules import CRYPTO_ROOTS, lookup_rule


def analyze_file(path: str | Path) -> list[Finding]:
    """Analyze a single Python file and return its findings.

    Unparseable files (syntax errors, unreadable bytes) yield no findings rather
    than aborting a whole-repository scan.
    """
    path = Path(path)
    try:
        # Reading bytes lets ``ast`` honor any PEP 263 encoding declaration.
        source = path.read_bytes()
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, OSError):
        return []

    visitor = _CryptoVisitor(str(path))
    visitor.visit(tree)
    # Report in source order (visitation is not strictly line-ordered for nested
    # calls); keeps output deterministic and easy to read.
    visitor.findings.sort(key=lambda f: (f.line, f.column))
    return visitor.findings


def _literal_int(node: ast.AST) -> int | None:
    """Return the value of an integer literal (``bool`` excluded), else ``None``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(
        node.value, bool
    ):
        return node.value
    return None


def _literal_str(node: ast.AST) -> str | None:
    """Return the value of a string literal, else ``None``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# Well-known small RSA public exponents, never a key size. Guards against reading
# the positional ``public_exponent`` of ``rsa.generate_private_key(65537, 2048)``
# as if it were the key size.
_RSA_EXPONENTS = frozenset({3, 5, 17, 257, 65537})

# Valid AES key lengths in bytes -> we only annotate a size we can trust.
_AES_KEY_BYTES = frozenset({16, 24, 32})

# Elliptic-curve name aliases across libraries collapse to one canonical label,
# so the same curve reads identically whatever binding produced it
# (``SECP256R1`` in pyca, ``P-256`` in pycryptodome, ``prime256v1`` in OpenSSL).
_CURVE_ALIASES = {
    "SECP192R1": "P-192", "PRIME192V1": "P-192", "P192": "P-192",
    "SECP224R1": "P-224", "P224": "P-224",
    "SECP256R1": "P-256", "PRIME256V1": "P-256", "P256": "P-256",
    "SECP384R1": "P-384", "P384": "P-384",
    "SECP521R1": "P-521", "P521": "P-521",
    "SECP256K1": "secp256k1",
}


def _canonical_curve(name: str) -> str:
    """Normalize a curve name to a canonical label (unknown names pass through)."""
    key = name.upper().replace("-", "").replace("_", "")
    return _CURVE_ALIASES.get(key, name)


# An extractor returns the refined display name plus any structured attributes
# (``key_size`` / ``curve`` / ``parameter``) worth carrying on the finding. The
# structured values are what the CBOM output maps cleanly, instead of re-parsing
# the display string (which is ambiguous: ``SHA-1``, ``Diffie-Hellman-2048``...).
_Refinement = tuple[str, dict[str, object]]


def _refine_key_size(call: ast.Call, base: str) -> _Refinement:
    """``RSA`` -> ``RSA-2048`` from a ``key_size=``/``bits=`` kwarg or a size arg.

    A positional size is only trusted when it is the sole positional argument
    (pycryptodome/paramiko ``generate(2048)``): the two-positional pyca form is
    ``(public_exponent, key_size)``, whose first arg is *not* the size.
    """
    for kw in call.keywords:
        if kw.arg in ("key_size", "bits", "key_length"):
            value = _literal_int(kw.value)
            if value is not None:
                return f"{base}-{value}", {"key_size": value}
    if len(call.args) == 1:
        value = _literal_int(call.args[0])
        if value is not None and value not in _RSA_EXPONENTS:
            return f"{base}-{value}", {"key_size": value}
    return base, {}


def _curve_name_from(node: ast.AST) -> str | None:
    """Extract a curve name from a curve argument, or ``None`` if unresolvable.

    A curve is only trusted when it is a **qualified** curve class instance
    (``ec.SECP256R1()`` — a dotted ``module.CurveName``) or a string literal
    (pycryptodome's ``curve="P-256"``). A bare local — ``generate_private_key(curve)``
    or even ``curve=curve()`` where ``curve`` is a variable holding a curve class —
    is *not* a curve name; resolving it needs data flow, which is out of scope. So
    it yields ``None`` and the finding stays a plain ``ECC`` instead of an invented
    ``ECC-curve``.
    """
    if isinstance(node, ast.Call):
        dotted = _dotted_name(node.func)
        # len >= 2 means a qualified access (``ec.SECP256R1``); a length-1 name is
        # a bare local variable, never a curve class.
        if dotted is not None and len(dotted) >= 2:
            return dotted[-1]
        return None
    return _literal_str(node)


def _refine_curve(call: ast.Call, base: str) -> _Refinement:
    """``ECC`` -> ``ECC-P-256`` from a curve instance or ``curve=`` kwarg."""
    name = None
    for kw in call.keywords:
        if kw.arg == "curve":
            name = _curve_name_from(kw.value)
    if name is None and call.args:
        name = _curve_name_from(call.args[0])
    if name is None:
        return base, {}
    curve = _canonical_curve(name)
    return f"{base}-{curve}", {"curve": curve}


def _refine_sym_key(call: ast.Call, base: str) -> _Refinement:
    """``AES`` -> ``AES-128`` only when the key is a bytes literal of valid length."""
    if call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, (bytes, bytearray)):
            if len(arg.value) in _AES_KEY_BYTES:
                bits = len(arg.value) * 8
                return f"{base}-{bits}", {"key_size": bits}
    return base, {}


def _refine_pqc_name(call: ast.Call, base: str) -> _Refinement:
    """``ML-KEM`` -> ``ML-KEM (Kyber512)`` from the first string argument."""
    if call.args:
        name = _literal_str(call.args[0])
        if name is not None:
            return f"{base} ({name})", {"parameter": name}
    return base, {}


# Maps a rule's ``detail`` tag to the extractor that refines the algorithm.
_DETAIL_EXTRACTORS = {
    "key_size": _refine_key_size,
    "curve": _refine_curve,
    "sym_key": _refine_sym_key,
    "pqc_name": _refine_pqc_name,
}


def _dotted_name(node: ast.AST) -> list[str] | None:
    """Return the dotted path of an attribute/name expression, or ``None``.

    ``rsa.generate_private_key`` -> ``["rsa", "generate_private_key"]``;
    ``algorithms.AES`` -> ``["algorithms", "AES"]``; a bare ``name`` -> ``["name"]``.
    Anything not rooted in a plain `Name` (e.g. ``foo().bar``) returns ``None``.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return parts
    return None


class _CryptoVisitor(ast.NodeVisitor):
    """Collects findings by tracking imports and matching call sites."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []
        # Local binding name -> fully-qualified dotted path it refers to.
        self.imports: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        # ``import a.b.c`` binds ``a`` (accessible as a.b.c);
        # ``import a.b.c as d`` binds ``d`` -> a.b.c.
        for alias in node.names:
            if alias.asname:
                self.imports[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.imports[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Skip relative imports (``from . import x``): the target package is not
        # resolvable statically and would never map to a crypto root anyway.
        if node.module is not None:
            for alias in node.names:
                local = alias.asname or alias.name
                self.imports[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        if dotted is not None:
            qualified = self._resolve(dotted)
            if qualified is not None:
                rule = lookup_rule(qualified)
                if rule is not None:
                    algorithm = rule.algorithm
                    detail: dict[str, object] = {}
                    if rule.detail is not None:
                        algorithm, detail = _DETAIL_EXTRACTORS[rule.detail](node, algorithm)
                    self.findings.append(
                        Finding(
                            path=self.path,
                            line=node.lineno,
                            column=node.col_offset,
                            algorithm=algorithm,
                            usage=rule.usage,
                            classification=rule.classification,
                            severity=rule.severity,
                            origin="code",
                            library=qualified.split(".")[0],
                            migration_target=rule.migration_target,
                            symbol=".".join(dotted),
                            key_size=detail.get("key_size"),
                            curve=detail.get("curve"),
                            parameter=detail.get("parameter"),
                        )
                    )
        self.generic_visit(node)

    def _resolve(self, parts: list[str]) -> str | None:
        """Resolve a call's dotted path to a qualified name under a crypto root.

        Returns ``None`` if the head is not an imported name, or if the resolved
        package is not one we treat as cryptographic.
        """
        head = parts[0]
        base = self.imports.get(head)
        if base is None:
            return None
        qualified = ".".join([base, *parts[1:]])
        if qualified.split(".")[0] not in CRYPTO_ROOTS:
            return None
        return qualified
