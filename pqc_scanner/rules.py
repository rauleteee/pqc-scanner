"""Rule base: crypto API -> algorithm -> classification -> migration target.

This is the knowledge core of the scanner. A rule maps a recognized callable
(identified by the last two components of its fully-qualified name, e.g.
``rsa.generate_private_key`` or ``algorithms.AES``) to what it means for a
post-quantum migration.

Detection only fires when the callable resolves to one of ``CRYPTO_ROOTS`` (see
the AST engine), which is what keeps false positives low. A rule may also declare
a ``detail`` extractor so the engine can refine the reported algorithm from the
call's arguments (key size, curve, symmetric key length, PQC scheme name).
"""

from __future__ import annotations

from dataclasses import dataclass

from pqc_scanner.findings import Classification, Severity

# Top-level import roots we treat as cryptographic. A call is only considered if
# it resolves (through the file's imports) to one of these packages, so a local
# function that merely happens to be named ``generate_private_key`` is ignored.
CRYPTO_ROOTS: frozenset[str] = frozenset(
    {
        "cryptography",  # pyca/cryptography
        "OpenSSL",  # pyOpenSSL
        "Crypto",  # pycryptodome / PyCrypto
        "Cryptodome",  # pycryptodomex
        "paramiko",  # SSH
        "nacl",  # PyNaCl
        "ecdsa",  # python-ecdsa
        "oqs",  # liboqs-python (already PQC)
    }
)

# Common migration-target strings, shared across rules for consistency.
_ML_KEM_DSA = "ML-KEM (key establishment) / ML-DSA (signatures)"
_ML_KEM = "ML-KEM"
_ML_DSA = "ML-DSA"
_ML_KEM_ECDH_DSA = "ML-KEM (ECDH) / ML-DSA (ECDSA)"
_AES256 = "AES-256"
_STRONG_HASH = "SHA-256 / SHA-3"
_ALREADY_PQC = "already post-quantum — no migration needed"


@dataclass(frozen=True)
class Rule:
    """What a recognized cryptographic call means for migration.

    ``detail`` names an optional argument-extractor (see the AST engine) that
    refines ``algorithm`` from the call site, e.g. ``"key_size"`` turns ``RSA``
    into ``RSA-2048``. ``None`` means the algorithm is reported as-is.
    """

    algorithm: str
    usage: str
    classification: Classification
    severity: Severity
    migration_target: str
    detail: str | None = None


# Convenience builders keep the (large) table below readable.
def _shor(algorithm, usage, target, detail=None):
    return Rule(algorithm, usage, Classification.SHOR, Severity.CRITICAL, target, detail)


def _grover(algorithm, usage, target=_AES256, detail=None):
    return Rule(algorithm, usage, Classification.GROVER, Severity.MEDIUM, target, detail)


def _pqc(algorithm, usage):
    return Rule(algorithm, usage, Classification.PQC, Severity.INFO, _ALREADY_PQC, "pqc_name")


# Keyed by the (module_leaf, attribute) pair of a call's qualified name.
RULES: dict[tuple[str, str], Rule] = {
    # --- pyca/cryptography: asymmetric (broken by Shor) ---
    ("rsa", "generate_private_key"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("dsa", "generate_private_key"): _shor("DSA", "signing", _ML_DSA, "key_size"),
    ("ec", "generate_private_key"): _shor("ECC", "key_generation", _ML_KEM_ECDH_DSA, "curve"),
    ("dh", "generate_parameters"): _shor("Diffie-Hellman", "key_exchange", _ML_KEM, "key_size"),
    ("Ed25519PrivateKey", "generate"): _shor("Ed25519", "signing", _ML_DSA),
    ("Ed448PrivateKey", "generate"): _shor("Ed448", "signing", _ML_DSA),
    ("X25519PrivateKey", "generate"): _shor("X25519", "key_exchange", _ML_KEM),
    ("X448PrivateKey", "generate"): _shor("X448", "key_exchange", _ML_KEM),
    # --- pyca/cryptography: symmetric & hashes (weakened by Grover / obsolete) ---
    ("algorithms", "AES"): _grover("AES", "encryption", detail="sym_key"),
    ("algorithms", "TripleDES"): _grover("3DES", "encryption"),
    ("algorithms", "Blowfish"): _grover("Blowfish", "encryption"),
    ("algorithms", "ARC4"): _grover("RC4", "encryption"),
    ("hashes", "SHA1"): _grover("SHA-1", "hashing", _STRONG_HASH),
    ("hashes", "MD5"): _grover("MD5", "hashing", _STRONG_HASH),
    # --- pycryptodome (Crypto / Cryptodome) ---
    ("RSA", "generate"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("DSA", "generate"): _shor("DSA", "signing", _ML_DSA, "key_size"),
    ("ECC", "generate"): _shor("ECC", "key_generation", _ML_KEM_ECDH_DSA, "curve"),
    ("AES", "new"): _grover("AES", "encryption", detail="sym_key"),
    ("DES3", "new"): _grover("3DES", "encryption"),
    ("DES", "new"): _grover("DES", "encryption"),
    ("ARC4", "new"): _grover("RC4", "encryption"),
    ("SHA1", "new"): _grover("SHA-1", "hashing", _STRONG_HASH),
    ("MD5", "new"): _grover("MD5", "hashing", _STRONG_HASH),
    # --- paramiko (SSH keys) ---
    ("RSAKey", "generate"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("ECDSAKey", "generate"): _shor("ECDSA", "signing", _ML_DSA),
    ("DSSKey", "generate"): _shor("DSA", "signing", _ML_DSA, "key_size"),
    # --- PyNaCl ---
    ("SigningKey", "generate"): _shor("Ed25519", "signing", _ML_DSA),
    ("PrivateKey", "generate"): _shor("Curve25519", "key_exchange", _ML_KEM),
    # --- python-ecdsa ---
    ("SigningKey", "from_secret_exponent"): _shor("ECDSA", "signing", _ML_DSA),
    # --- liboqs (already post-quantum -> informative) ---
    ("oqs", "Signature"): _pqc("ML-DSA/SLH-DSA", "signing"),
    ("oqs", "KeyEncapsulation"): _pqc("ML-KEM", "key_exchange"),
}


def lookup_rule(qualified_name: str) -> Rule | None:
    """Return the rule for a fully-qualified callable name, or ``None``.

    The key is the last two dotted components, e.g. both
    ``cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`` and a
    direct ``from ...rsa import generate_private_key`` resolve to the same
    ``("rsa", "generate_private_key")`` rule.
    """
    parts = qualified_name.split(".")
    if len(parts) < 2:
        return None
    return RULES.get((parts[-2], parts[-1]))
