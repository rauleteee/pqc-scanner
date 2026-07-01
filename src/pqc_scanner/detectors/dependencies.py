"""Dependency manifest analysis (phase 6, complement to the AST engine).

Parses Python dependency manifests (``requirements.txt``, ``pyproject.toml``,
``poetry.lock``, ``Pipfile.lock``) and emits a `Finding` for every declared
package that is a known cryptographic library. This is deliberately a *simple
lookup*, not the "smart" part of the scanner: the mere presence of, say,
``cryptography`` in a manifest is a low-signal indicator (it says the project
*can* use quantum-vulnerable primitives, not that it does). The high-signal
detection is the AST engine; this complement is the seed of the CBOM.

Findings from here carry ``origin="dependency"`` and, instead of a call site,
the manifest location plus the package name and declared version, so a report
can point at exactly which requirement to migrate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from pqc_scanner.findings import Classification, Finding, Severity

try:  # tomllib is standard library on Python 3.11+.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on 3.10.
    tomllib = None  # TOML manifests degrade to "no findings" rather than crash.

# Usage tag for every dependency finding. Unlike a call site (key_generation,
# signing, ...), a manifest only tells us a library is *present*.
_USAGE = "dependency"

# Migration guidance shared across the (small) rule table.
_ASYM_TARGET = "ML-KEM (key establishment) / ML-DSA (signatures)"
_PQC_OK = "already post-quantum — no migration needed"


@dataclass(frozen=True)
class DependencyRule:
    """What the presence of a package means for a post-quantum migration.

    ``provides`` is a short label of the quantum-relevant primitives the library
    exposes (shown as the finding's algorithm), not proof they are used.
    """

    provides: str
    classification: Classification
    severity: Severity
    migration_target: str


def _shor(provides: str) -> DependencyRule:
    return DependencyRule(provides, Classification.SHOR, Severity.CRITICAL, _ASYM_TARGET)


def _pqc(provides: str) -> DependencyRule:
    return DependencyRule(provides, Classification.PQC, Severity.INFO, _PQC_OK)


# Keyed by PEP 503-normalized PyPI distribution name (see ``_normalize``). These
# are the distributions behind the import roots the AST engine already knows.
DEPENDENCY_RULES: dict[str, DependencyRule] = {
    "cryptography": _shor("RSA/ECC/DH/Ed25519"),  # pyca/cryptography
    "pyopenssl": _shor("RSA/ECC (OpenSSL)"),
    "pycryptodome": _shor("RSA/DSA/ECC"),
    "pycryptodomex": _shor("RSA/DSA/ECC"),
    "pycrypto": _shor("RSA/DSA/ECC"),  # legacy, also unmaintained
    "paramiko": _shor("RSA/ECDSA (SSH)"),
    "pynacl": _shor("Ed25519/Curve25519"),
    "ecdsa": _shor("ECDSA"),
    "rsa": _shor("RSA"),  # python-rsa
    "oqs": _pqc("ML-KEM/ML-DSA"),  # liboqs-python
    "liboqs-python": _pqc("ML-KEM/ML-DSA"),
}


def _normalize(name: str) -> str:
    """Normalize a distribution name per PEP 503 (lowercase, runs of ``-_.``)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


# A PEP 508 requirement head: the name, optional extras, then the rest (specifier
# and/or environment marker), e.g. ``cryptography[ssh]>=41.0 ; python_version>'3'``.
_REQUIREMENT_HEAD = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")

# A pinned exact version (``==1.2.3``); anything looser leaves the version unknown.
_PINNED = re.compile(r"==\s*([A-Za-z0-9][A-Za-z0-9.!+*_-]*)")


def _extract_version(spec: str) -> str | None:
    """Return the exactly-pinned version from a specifier, else ``None``."""
    match = _PINNED.search(spec)
    return match.group(1) if match else None


# The leading version token of a Poetry constraint (``^41.0``, ``~1.5``, ``2.0``,
# ``>=3,<4`` -> ``3``). Poetry constraints are version-centric, so unlike a pip
# range this names a concrete target worth surfacing.
_POETRY_VERSION = re.compile(r"(\d[A-Za-z0-9.!+*_-]*)")


def _poetry_version(constraint: str) -> str | None:
    """Return the version named by a Poetry constraint string, else ``None``."""
    if "*" in constraint.strip()[:1]:  # a wildcard ``*`` pins nothing
        return None
    match = _POETRY_VERSION.search(constraint)
    return match.group(1) if match else None


def _parse_requirement_string(text: str) -> tuple[str, str | None] | None:
    """Parse one PEP 508 requirement into ``(name, version_or_None)``.

    Returns ``None`` when the string is not a plain requirement (an option line,
    a URL/VCS reference, blank, or unparseable).
    """
    stripped = text.strip()
    if not stripped or stripped.startswith(("#", "-")):
        return None
    # Drop an environment marker before matching the specifier.
    stripped = stripped.split(";", 1)[0].strip()
    match = _REQUIREMENT_HEAD.match(stripped)
    if match is None:
        return None
    name, rest = match.group(1), match.group(2)
    # A bare URL/VCS requirement (``name @ https://...``) carries no PyPI version.
    if rest.lstrip().startswith("@"):
        return name, None
    return name, _extract_version(rest)


def _find_line(text: str, name: str) -> int:
    """Best-effort 1-based line where ``name`` is declared in ``text``.

    Formats parsed structurally (TOML/JSON) carry no line info, so we locate the
    package by name to keep the finding actionable. Defaults to line 1.
    """
    token = re.compile(rf"(?<![A-Za-z0-9._-]){re.escape(name)}(?![A-Za-z0-9._-])", re.IGNORECASE)
    for i, raw in enumerate(text.splitlines(), start=1):
        if token.search(raw):
            return i
    return 1


# --- Per-format parsers: each yields (name, version_or_None, line) triples. ---


def _parse_requirements(text: str) -> list[tuple[str, str | None, int]]:
    results: list[tuple[str, str | None, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        # Strip a trailing inline comment (whitespace-separated ``#``).
        line = re.split(r"\s#", raw, maxsplit=1)[0]
        parsed = _parse_requirement_string(line)
        if parsed is not None:
            results.append((parsed[0], parsed[1], i))
    return results


def _iter_requirement_strings(value: object):
    """Yield requirement strings from a PEP 621 dependency value (list of str)."""
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                yield item


def _parse_pyproject(text: str) -> list[tuple[str, str | None, int]]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []

    results: list[tuple[str, str | None, int]] = []
    project = data.get("project", {}) if isinstance(data, dict) else {}

    # PEP 621: [project].dependencies and [project.optional-dependencies].
    specs: list[str] = list(_iter_requirement_strings(project.get("dependencies")))
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            specs.extend(_iter_requirement_strings(group))
    for spec in specs:
        parsed = _parse_requirement_string(spec)
        if parsed is not None:
            results.append((parsed[0], parsed[1], _find_line(text, parsed[0])))

    # Poetry: [tool.poetry.dependencies] maps name -> constraint (str or table).
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data, dict) else {}
    poetry_deps = poetry.get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, constraint in poetry_deps.items():
            if name.lower() == "python":  # the interpreter pin, not a package
                continue
            version = None
            if isinstance(constraint, str):
                version = _poetry_version(constraint)
            elif isinstance(constraint, dict):
                v = constraint.get("version")
                version = _poetry_version(v) if isinstance(v, str) else None
            results.append((name, version, _find_line(text, name)))

    return results


def _parse_poetry_lock(text: str) -> list[tuple[str, str | None, int]]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    results: list[tuple[str, str | None, int]] = []
    packages = data.get("package", []) if isinstance(data, dict) else []
    if isinstance(packages, list):
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not isinstance(name, str):
                continue
            version = pkg.get("version")
            version = version if isinstance(version, str) else None
            results.append((name, version, _find_line(text, name)))
    return results


def _parse_pipfile_lock(text: str) -> list[tuple[str, str | None, int]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    results: list[tuple[str, str | None, int]] = []
    for section in ("default", "develop"):
        packages = data.get(section, {})
        if not isinstance(packages, dict):
            continue
        for name, spec in packages.items():
            version = None
            if isinstance(spec, dict):
                v = spec.get("version")
                version = _extract_version(v) if isinstance(v, str) else None
            results.append((name, version, _find_line(text, name)))
    return results


# Filename -> parser. Kept in sync with ``discovery.MANIFEST_NAMES``.
_PARSERS = {
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "poetry.lock": _parse_poetry_lock,
    "Pipfile.lock": _parse_pipfile_lock,
}


def analyze_manifest(path: str | Path) -> list[Finding]:
    """Analyze a single dependency manifest and return its findings.

    Unrecognized or unreadable manifests yield no findings rather than aborting a
    whole-repository scan. A package declared more than once within the same
    manifest (e.g. Pipfile ``default`` and ``develop``) is reported once.
    """
    path = Path(path)
    parser = _PARSERS.get(path.name)
    if parser is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    for name, version, line in parser(text):
        normalized = _normalize(name)
        rule = DEPENDENCY_RULES.get(normalized)
        if rule is None or normalized in seen:
            continue
        seen.add(normalized)
        findings.append(
            Finding(
                path=str(path),
                line=line,
                column=0,
                algorithm=rule.provides,
                usage=_USAGE,
                classification=rule.classification,
                severity=rule.severity,
                origin="dependency",
                library=normalized,
                migration_target=rule.migration_target,
                symbol=normalized if version is None else f"{normalized}=={version}",
                version=version,
            )
        )
    findings.sort(key=lambda f: (f.line, f.library))
    return findings
