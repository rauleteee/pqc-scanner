"""Findings model.

A `Finding` is the unit of output of the engine: one detected use of a
cryptographic primitive, with everything an interface needs to render an
actionable report (location, algorithm, classification, severity and — the
lead-generating field — the suggested post-quantum migration target).

The value types are `str`-based enums so the model both reads as a self-checking
domain (a typo like ``Usage("keygeneration")`` fails fast) and serializes cleanly
to JSON: a ``str`` enum's JSON form is its string value, matching the CycloneDX
CBOM alignment (phase 4).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Classification(str, Enum):
    """Why a primitive is (or is not) a quantum concern."""

    SHOR = "SHOR"  # Asymmetric primitive broken by Shor's algorithm.
    GROVER = "GROVER"  # Symmetric/hash primitive weakened by Grover's algorithm.
    PQC = "PQC"  # Already post-quantum; reported as informative, not a defect.


class Severity(str, Enum):
    """Severity derived from the classification."""

    CRITICAL = "CRITICAL"  # Broken by Shor.
    MEDIUM = "MEDIUM"  # Weakened by Grover / insufficient size.
    INFO = "INFO"  # Already post-quantum.


class Usage(str, Enum):
    """What the detected primitive is used for at the call site.

    ``DEPENDENCY`` is the usage of a manifest finding, where all we know is that a
    crypto library is *present* — there is no call site telling us how it is used.
    """

    KEY_GENERATION = "key_generation"
    SIGNING = "signing"
    KEY_EXCHANGE = "key_exchange"
    ENCRYPTION = "encryption"
    HASHING = "hashing"
    DEPENDENCY = "dependency"


class Origin(str, Enum):
    """Where a finding came from."""

    CODE = "code"  # A resolved call site in Python source (AST engine).
    DEPENDENCY = "dependency"  # A declared package in a manifest (dependency lookup).


@dataclass(frozen=True)
class Finding:
    """A single detected cryptographic usage."""

    path: str  # File path where the usage was found.
    line: int  # 1-based line number of the call.
    column: int  # 0-based column offset of the call.
    algorithm: str  # Detected algorithm, e.g. "RSA-2048", "ECC-P-256", "AES".
    usage: Usage  # What the primitive is used for (or DEPENDENCY for manifests).
    classification: Classification
    severity: Severity
    origin: Origin  # CODE (with location) or DEPENDENCY (package + version).
    library: str  # Detected import root / binding, e.g. "cryptography", "paramiko".
    # For code findings ``library`` is the import root; for dependency findings it
    # is the normalized PyPI distribution name and ``version`` its declared pin.
    migration_target: str  # Suggested PQC target, e.g. "ML-KEM" / "ML-DSA".
    symbol: str  # The detected API call, e.g. "rsa.generate_private_key".
    # Structured detail extracted from the call site (None when not determinable).
    key_size: int | None = None  # Key/modulus size in bits, e.g. 2048.
    curve: str | None = None  # Canonical elliptic curve name, e.g. "P-256".
    parameter: str | None = None  # Scheme/parameter set, e.g. "Kyber512" (PQC).
    version: str | None = None  # Declared package version (dependency findings).

    def to_dict(self) -> dict:
        """Serialize to a plain dict (enums as their string values)."""
        data = asdict(self)
        data["usage"] = self.usage.value
        data["classification"] = self.classification.value
        data["severity"] = self.severity.value
        data["origin"] = self.origin.value
        return data
