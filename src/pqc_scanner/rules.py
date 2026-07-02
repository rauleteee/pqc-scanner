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
        "rsa",  # python-rsa (pure-Python RSA; distinct from pyca's ``rsa`` module)
        "M2Crypto",  # OpenSSL wrapper: native RSA/DSA/DH/EC key generation
        "oqs",  # liboqs-python (already PQC)
        "authlib",  # high-level JOSE/JWT: its own JWK key-generation API
        "hashlib",  # stdlib: the most common way to invoke MD5/SHA-1
    }
)

# Common migration-target strings, shared across rules for consistency.
_ML_KEM_DSA = "ML-KEM (key establishment) / ML-DSA (signatures)"
_ML_KEM = "ML-KEM"
_ML_DSA = "ML-DSA"
_ML_KEM_ECDH_DSA = "ML-KEM (ECDH) / ML-DSA (ECDSA)"
_ML_DSA_KEM_OKP = "ML-DSA (Ed25519/Ed448) / ML-KEM (X25519/X448)"
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
    # --- stdlib hashlib: same weak hashes via the most common entry point ---
    # ``usedforsecurity=False`` (Python 3.9+) suppresses the finding (see engine).
    ("hashlib", "md5"): _grover("MD5", "hashing", _STRONG_HASH, "weak_hash"),
    ("hashlib", "sha1"): _grover("SHA-1", "hashing", _STRONG_HASH, "weak_hash"),
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
    # MD4 is fully broken (worse than MD5); still used for NTLM hashes (impacket).
    ("MD4", "new"): _grover("MD4", "hashing", _STRONG_HASH),
    # --- python-rsa (pure-Python RSA): the public entry point is ``rsa.newkeys`` ---
    ("rsa", "newkeys"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    # --- paramiko (SSH keys) ---
    ("RSAKey", "generate"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("ECDSAKey", "generate"): _shor("ECDSA", "signing", _ML_DSA),
    ("DSSKey", "generate"): _shor("DSA", "signing", _ML_DSA, "key_size"),
    # --- python-ecdsa ---
    ("SigningKey", "from_secret_exponent"): _shor("ECDSA", "signing", _ML_DSA),
    # --- liboqs (already post-quantum -> informative) ---
    ("oqs", "Signature"): _pqc("ML-DSA/SLH-DSA", "signing"),
    ("oqs", "KeyEncapsulation"): _pqc("ML-KEM", "key_exchange"),
}


# Package-specific rules: some class names mean *different* algorithms depending
# on the library (``SigningKey.generate`` is Ed25519 in PyNaCl but ECDSA in
# python-ecdsa). These are keyed by the originating import root as well, and are
# consulted before the root-agnostic ``RULES`` table.
ROOT_RULES: dict[tuple[str, str, str], Rule] = {
    # PyNaCl
    ("nacl", "SigningKey", "generate"): _shor("Ed25519", "signing", _ML_DSA),
    ("nacl", "PrivateKey", "generate"): _shor("Curve25519", "key_exchange", _ML_KEM),
    # python-ecdsa: SigningKey.generate(curve=...) is ECDSA, not Ed25519.
    ("ecdsa", "SigningKey", "generate"): _shor("ECDSA", "signing", _ML_DSA),
    # authlib: its JWK classes expose their own key generation, wrapping
    # cryptography. A user app calls these directly, so cover them here (the
    # ``oct`` symmetric key class is intentionally omitted — not a Shor concern).
    ("authlib", "RSAKey", "generate_key"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("authlib", "ECKey", "generate_key"): _shor("ECC", "key_generation", _ML_KEM_ECDH_DSA, "curve"),
    ("authlib", "OKPKey", "generate_key"): _shor("OKP (Ed/X)", "key_generation", _ML_DSA_KEM_OKP),
    # M2Crypto's native key generation are module-level functions whose names
    # (``gen_key``/``gen_params``) are M2Crypto-specific, so key them by root to
    # avoid ever colliding with the same class names in other libraries. Real use
    # includes Salt (``M2Crypto.RSA.gen_key(bits, ...)`` in salt/modules/x509.py).
    ("M2Crypto", "RSA", "gen_key"): _shor("RSA", "key_generation", _ML_KEM_DSA, "key_size"),
    ("M2Crypto", "DSA", "gen_params"): _shor("DSA", "signing", _ML_DSA, "key_size"),
    ("M2Crypto", "EC", "gen_params"): _shor("ECC", "key_generation", _ML_KEM_ECDH_DSA, "curve"),
    ("M2Crypto", "DH", "gen_params"): _shor("Diffie-Hellman", "key_exchange", _ML_KEM),
}


# pyOpenSSL's native key generation is an instance method whose *argument* carries
# the algorithm: ``pkey.generate_key(TYPE_RSA, bits)``. The receiver (``pkey``) is a
# runtime value we cannot resolve, but the ``TYPE_*`` constant resolves through the
# file's imports to ``OpenSSL.crypto`` — a very specific, low-false-positive signal.
# The engine keys this by the resolved constant (see ``_check_pyopenssl_pkey``).
PKEY_TYPE_RULES: dict[str, Rule] = {
    "OpenSSL.crypto.TYPE_RSA": _shor("RSA", "key_generation", _ML_KEM_DSA),
    "OpenSSL.crypto.TYPE_DSA": _shor("DSA", "signing", _ML_DSA),
}


def lookup_rule(qualified_name: str) -> Rule | None:
    """Return the rule for a fully-qualified callable name, or ``None``.

    The key is the last two dotted components, e.g. both
    ``cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`` and a
    direct ``from ...rsa import generate_private_key`` resolve to the same
    ``("rsa", "generate_private_key")`` rule. When a class name is shared across
    libraries, a ``ROOT_RULES`` entry keyed by the import root (first component)
    disambiguates and takes precedence.
    """
    parts = qualified_name.split(".")
    if len(parts) < 2:
        return None
    root, leaf, attr = parts[0], parts[-2], parts[-1]
    # A package-specific rule (keyed by import root) wins over the generic one.
    specific = ROOT_RULES.get((root, leaf, attr))
    if specific is not None:
        return specific
    return RULES.get((leaf, attr))
