"""CycloneDX CBOM output (phase 4).

Serializes a list of `Finding` into a CycloneDX 1.6 Cryptography Bill of
Materials (CBOM). Each distinct cryptographic asset becomes a
``cryptographic-asset`` component; every place it is used becomes an entry in
that component's ``evidence.occurrences``. The scanner's own value-add
(severity, quantum classification, migration target) rides along as namespaced
``properties`` so nothing schema-breaking is invented.

Schema reference: CycloneDX 1.6 (verified against the official
``bom-1.6.schema.json``). Enum values used here — ``assetType`` ``algorithm``;
``primitive`` in {pke, signature, key-agree, kem, block-cipher, stream-cipher,
hash}; ``cryptoFunctions`` in {keygen, encrypt, digest}; ``nistQuantumSecurity
Level`` an integer 0-6 — are all valid members of that schema.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from datetime import datetime, timezone

from pqc_scanner.findings import Classification, Finding

SPEC_VERSION = "1.6"

# usage -> CycloneDX cryptoFunctions. Every detected call either generates a key,
# constructs a cipher for encryption, or builds a hash for digesting.
_CRYPTO_FUNCTIONS: dict[str, list[str]] = {
    "key_generation": ["keygen"],
    "signing": ["keygen"],
    "key_exchange": ["keygen"],
    "encryption": ["encrypt"],
    "hashing": ["digest"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _primitive(finding: Finding) -> str:
    """Map a finding to a CycloneDX ``algorithmProperties.primitive`` value."""
    usage = finding.usage
    if usage == "hashing":
        return "hash"
    if usage == "encryption":
        base = finding.algorithm.split("-", 1)[0]
        return "stream-cipher" if base == "RC4" else "block-cipher"
    if usage == "signing":
        return "signature"
    if usage == "key_exchange":
        return "kem" if finding.classification is Classification.PQC else "key-agree"
    # key_generation: RSA is public-key encryption; bare EC keygen defaults to
    # signature (the dominant EC use). Migration guidance covers both roles.
    return "pke" if finding.algorithm.startswith("RSA") else "signature"


def _algorithm_properties(finding: Finding) -> dict:
    props: dict = {
        "primitive": _primitive(finding),
        "cryptoFunctions": _CRYPTO_FUNCTIONS.get(finding.usage, ["keygen"]),
    }
    if finding.curve is not None:
        props["curve"] = finding.curve
    if finding.key_size is not None:
        props["parameterSetIdentifier"] = str(finding.key_size)
    elif finding.parameter is not None:
        props["parameterSetIdentifier"] = finding.parameter
    # Broken by Shor -> no quantum security. We stay silent for Grover/PQC rather
    # than assert a level we cannot derive precisely from static use alone.
    if finding.classification is Classification.SHOR:
        props["nistQuantumSecurityLevel"] = 0
    return props


def _bom_ref(finding: Finding) -> str:
    return f"crypto:{finding.library}:{finding.algorithm}:{finding.usage}"


def _occurrence(finding: Finding) -> dict:
    return {
        "location": finding.path,
        "line": finding.line,
        "offset": finding.column,
        "symbol": finding.symbol,
    }


def _component(representative: Finding, occurrences: list[Finding]) -> dict:
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(representative),
        "name": representative.algorithm,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": _algorithm_properties(representative),
        },
        "evidence": {"occurrences": [_occurrence(f) for f in occurrences]},
        "properties": [
            {"name": "pqc-audit:classification", "value": representative.classification.value},
            {"name": "pqc-audit:severity", "value": representative.severity.value},
            {"name": "pqc-audit:migrationTarget", "value": representative.migration_target},
        ],
    }


def _crypto_components(findings: list[Finding]) -> list[dict]:
    # Group findings that describe the same asset (same binding, algorithm and
    # usage) so one component carries all of its occurrences, the CBOM-idiomatic
    # shape. Insertion order is preserved for deterministic output.
    groups: OrderedDict[tuple[str, str, str], list[Finding]] = OrderedDict()
    for finding in findings:
        key = (finding.library, finding.algorithm, finding.usage)
        groups.setdefault(key, []).append(finding)
    return [_component(group[0], group) for group in groups.values()]


def _dependency_component(finding: Finding) -> dict:
    """Model a crypto dependency as a CycloneDX ``library`` component.

    A manifest entry is not a used algorithm, so it is a ``library`` (with a purl
    and version when pinned) rather than a ``cryptographic-asset``. The scanner's
    quantum assessment rides along as namespaced ``properties``.
    """
    purl = f"pkg:pypi/{finding.library}"
    component: dict = {
        "type": "library",
        "bom-ref": f"dependency:{finding.library}:{finding.version or 'unknown'}",
        "name": finding.library,
        "properties": [
            {"name": "pqc-audit:classification", "value": finding.classification.value},
            {"name": "pqc-audit:severity", "value": finding.severity.value},
            {"name": "pqc-audit:migrationTarget", "value": finding.migration_target},
            {"name": "pqc-audit:provides", "value": finding.algorithm},
        ],
        "evidence": {"occurrences": [{"location": finding.path, "line": finding.line}]},
    }
    if finding.version is not None:
        component["version"] = finding.version
        purl = f"{purl}@{finding.version}"
    component["purl"] = purl
    return component


def _dependency_components(findings: list[Finding]) -> list[dict]:
    # One component per distinct package (first version wins); insertion order
    # preserved for deterministic output.
    seen: set[str] = set()
    components: list[dict] = []
    for finding in findings:
        if finding.library in seen:
            continue
        seen.add(finding.library)
        components.append(_dependency_component(finding))
    return components


def _components(findings: list[Finding]) -> list[dict]:
    # Code findings become cryptographic-asset components; dependency findings
    # become library components. Code first, then dependencies.
    code = [f for f in findings if f.origin != "dependency"]
    deps = [f for f in findings if f.origin == "dependency"]
    return _crypto_components(code) + _dependency_components(deps)


def to_cbom(
    findings: list[Finding],
    *,
    serial_number: str | None = None,
    timestamp: str | None = None,
) -> dict:
    """Build a CycloneDX 1.6 CBOM document (a JSON-serializable dict).

    Args:
        findings: Findings to serialize.
        serial_number: Override the ``urn:uuid`` serial (for reproducible output).
        timestamp: Override the metadata timestamp (RFC 3339).
    """
    from pqc_scanner import __version__

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or _now_iso(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-audit",
                        "version": __version__,
                    }
                ]
            },
        },
        "components": _components(findings),
    }
