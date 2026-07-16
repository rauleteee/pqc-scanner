"""Dependency rule base: PyPI package -> quantum relevance -> migration target.

The knowledge half of the dependency complement: which crypto libraries, if
merely *declared* in a manifest, carry quantum-vulnerable primitives. This is a
low-signal indicator by design (presence, not use), so the table is deliberately
small — the seed of the CBOM, not the "smart" detection.

Kept here, in the domain, alongside the code rule base (`code.py`): both are
crypto knowledge. The manifest *parsing* lives in the detector adapter
(`detectors/dependencies.py`), which consults this table but owns none of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqc_scanner.findings import Classification, Severity
from pqc_scanner.knowledge.targets import ALREADY_PQC, ML_KEM_DSA


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
    return DependencyRule(provides, Classification.SHOR, Severity.CRITICAL, ML_KEM_DSA)


def _pqc(provides: str) -> DependencyRule:
    return DependencyRule(provides, Classification.PQC, Severity.INFO, ALREADY_PQC)


# Keyed by PEP 503-normalized PyPI distribution name (see the detector's
# ``_normalize``). These are the distributions behind the import roots the AST
# engine already knows.
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
    # High-level JOSE / JWT libraries: wrap asymmetric crypto (RS*/ES*/EdDSA).
    "authlib": _shor("JOSE/OAuth: RSA/EC/OKP"),
    "python-jose": _shor("JOSE: RSA/EC"),
    "jwcrypto": _shor("JOSE: RSA/EC/OKP"),
    "pyjwt": _shor("JWT: RSA/EC signatures"),
    "josepy": _shor("JOSE: RSA/EC"),
    "oqs": _pqc("ML-KEM/ML-DSA"),  # liboqs-python
    "liboqs-python": _pqc("ML-KEM/ML-DSA"),
}
