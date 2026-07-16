"""Code rule base: crypto API -> algorithm -> classification -> migration target.

This is the knowledge core for the AST engine. A rule maps a recognized callable
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

from pqc_scanner.findings import Classification, Severity, Usage
from pqc_scanner.knowledge.targets import (
    AES256,
    ALREADY_PQC,
    ML_DSA,
    ML_DSA_KEM_OKP,
    ML_KEM,
    ML_KEM_DSA,
    ML_KEM_ECDH_DSA,
    STRONG_HASH,
)

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
        "fastecdsa",  # ECDSA key generation (gen_private_key / gen_keypair)
        "libnacl",  # libsodium wrapper (Ed25519 / Curve25519 keypairs)
        "pysodium",  # libsodium wrapper (Ed25519 / Curve25519 keypairs)
        "oqs",  # liboqs-python (already PQC)
        "authlib",  # high-level JOSE/JWT: its own JWK key-generation API
        "jwcrypto",  # JOSE: JWK.generate(kty=...) string dispatcher
        "asyncssh",  # SSH: generate_private_key(alg) string dispatcher
        "oscrypto",  # asymmetric.generate_pair(algo) string dispatcher
        "hashlib",  # stdlib: the most common way to invoke MD5/SHA-1
    }
)


@dataclass(frozen=True)
class Rule:
    """What a recognized cryptographic call means for migration.

    ``detail`` names an optional argument-extractor (see the AST engine) that
    refines ``algorithm`` from the call site, e.g. ``"key_size"`` turns ``RSA``
    into ``RSA-2048``. ``None`` means the algorithm is reported as-is.
    """

    algorithm: str
    usage: Usage
    classification: Classification
    severity: Severity
    migration_target: str
    detail: str | None = None


# Convenience builders keep the (large) table below readable. They also lift the
# plain ``usage`` string into the typed `Usage` domain enum, so a typo in the
# table fails fast at import time rather than silently producing a bad finding.
def _shor(algorithm, usage, target, detail=None):
    return Rule(algorithm, Usage(usage), Classification.SHOR, Severity.CRITICAL, target, detail)


def _grover(algorithm, usage, target=AES256, detail=None):
    return Rule(algorithm, Usage(usage), Classification.GROVER, Severity.MEDIUM, target, detail)


def _pqc(algorithm, usage):
    return Rule(algorithm, Usage(usage), Classification.PQC, Severity.INFO, ALREADY_PQC, "pqc_name")


# Keyed by the (module_leaf, attribute) pair of a call's qualified name.
RULES: dict[tuple[str, str], Rule] = {
    # --- pyca/cryptography: asymmetric (broken by Shor) ---
    ("rsa", "generate_private_key"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    ("dsa", "generate_private_key"): _shor("DSA", "signing", ML_DSA, "key_size"),
    ("ec", "generate_private_key"): _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
    ("dh", "generate_parameters"): _shor("Diffie-Hellman", "key_exchange", ML_KEM, "key_size"),
    ("Ed25519PrivateKey", "generate"): _shor("Ed25519", "signing", ML_DSA),
    ("Ed448PrivateKey", "generate"): _shor("Ed448", "signing", ML_DSA),
    ("X25519PrivateKey", "generate"): _shor("X25519", "key_exchange", ML_KEM),
    ("X448PrivateKey", "generate"): _shor("X448", "key_exchange", ML_KEM),
    # --- pyca/cryptography: symmetric & hashes (weakened by Grover / obsolete) ---
    ("algorithms", "AES"): _grover("AES", "encryption", detail="sym_key"),
    ("algorithms", "TripleDES"): _grover("3DES", "encryption"),
    ("algorithms", "Blowfish"): _grover("Blowfish", "encryption"),
    ("algorithms", "ARC4"): _grover("RC4", "encryption"),
    ("hashes", "SHA1"): _grover("SHA-1", "hashing", STRONG_HASH),
    ("hashes", "MD5"): _grover("MD5", "hashing", STRONG_HASH),
    # --- stdlib hashlib: same weak hashes via the most common entry point ---
    # ``usedforsecurity=False`` (Python 3.9+) suppresses the finding (see engine).
    ("hashlib", "md5"): _grover("MD5", "hashing", STRONG_HASH, "weak_hash"),
    ("hashlib", "sha1"): _grover("SHA-1", "hashing", STRONG_HASH, "weak_hash"),
    # --- pycryptodome (Crypto / Cryptodome) ---
    ("RSA", "generate"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    ("DSA", "generate"): _shor("DSA", "signing", ML_DSA, "key_size"),
    ("ECC", "generate"): _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
    ("AES", "new"): _grover("AES", "encryption", detail="sym_key"),
    ("DES3", "new"): _grover("3DES", "encryption"),
    ("DES", "new"): _grover("DES", "encryption"),
    ("ARC4", "new"): _grover("RC4", "encryption"),
    ("SHA1", "new"): _grover("SHA-1", "hashing", STRONG_HASH),
    ("MD5", "new"): _grover("MD5", "hashing", STRONG_HASH),
    # MD4 is fully broken (worse than MD5); still used for NTLM hashes (impacket).
    ("MD4", "new"): _grover("MD4", "hashing", STRONG_HASH),
    # --- python-rsa (pure-Python RSA): the public entry point is ``rsa.newkeys`` ---
    ("rsa", "newkeys"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    # --- paramiko (SSH keys) ---
    ("RSAKey", "generate"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    ("ECDSAKey", "generate"): _shor("ECDSA", "signing", ML_DSA),
    ("DSSKey", "generate"): _shor("DSA", "signing", ML_DSA, "key_size"),
    # --- python-ecdsa ---
    ("SigningKey", "from_secret_exponent"): _shor("ECDSA", "signing", ML_DSA),
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
    ("nacl", "SigningKey", "generate"): _shor("Ed25519", "signing", ML_DSA),
    ("nacl", "PrivateKey", "generate"): _shor("Curve25519", "key_exchange", ML_KEM),
    # python-ecdsa: SigningKey.generate(curve=...) is ECDSA, not Ed25519.
    ("ecdsa", "SigningKey", "generate"): _shor("ECDSA", "signing", ML_DSA),
    # authlib: its JWK classes expose their own key generation, wrapping
    # cryptography. A user app calls these directly, so cover them here (the
    # ``oct`` symmetric key class is intentionally omitted — not a Shor concern).
    ("authlib", "RSAKey", "generate_key"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    ("authlib", "ECKey", "generate_key"): _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
    ("authlib", "OKPKey", "generate_key"): _shor("OKP (Ed/X)", "key_generation", ML_DSA_KEM_OKP),
    # M2Crypto's native key generation are module-level functions whose names
    # (``gen_key``/``gen_params``) are M2Crypto-specific, so key them by root to
    # avoid ever colliding with the same class names in other libraries. Real use
    # includes Salt (``M2Crypto.RSA.gen_key(bits, ...)`` in salt/modules/x509.py).
    ("M2Crypto", "RSA", "gen_key"): _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    ("M2Crypto", "DSA", "gen_params"): _shor("DSA", "signing", ML_DSA, "key_size"),
    ("M2Crypto", "EC", "gen_params"): _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
    ("M2Crypto", "DH", "gen_params"): _shor("Diffie-Hellman", "key_exchange", ML_KEM),
    # fastecdsa: module-level ECDSA key generation (``keys`` submodule).
    ("fastecdsa", "keys", "gen_private_key"): _shor("ECDSA", "signing", ML_DSA),
    ("fastecdsa", "keys", "gen_keypair"): _shor("ECDSA", "signing", ML_DSA),
    # libsodium wrappers (libnacl / pysodium): top-level module functions, so the
    # leaf equals the import root. ``sign`` -> Ed25519; ``box``/``kx`` -> Curve25519.
    ("libnacl", "libnacl", "crypto_sign_keypair"): _shor("Ed25519", "signing", ML_DSA),
    ("libnacl", "libnacl", "crypto_box_keypair"): _shor("Curve25519", "key_exchange", ML_KEM),
    ("libnacl", "libnacl", "crypto_kx_keypair"): _shor("Curve25519", "key_exchange", ML_KEM),
    ("pysodium", "pysodium", "crypto_sign_keypair"): _shor("Ed25519", "signing", ML_DSA),
    ("pysodium", "pysodium", "crypto_box_keypair"): _shor("Curve25519", "key_exchange", ML_KEM),
    ("pysodium", "pysodium", "crypto_kx_keypair"): _shor("Curve25519", "key_exchange", ML_KEM),
}


# pyOpenSSL's native key generation is an instance method whose *argument* carries
# the algorithm: ``pkey.generate_key(TYPE_RSA, bits)``. The receiver (``pkey``) is a
# runtime value we cannot resolve, but the ``TYPE_*`` constant resolves through the
# file's imports to ``OpenSSL.crypto`` — a very specific, low-false-positive signal.
# The engine keys this by the resolved constant (see ``_check_pyopenssl_pkey``).
PKEY_TYPE_RULES: dict[str, Rule] = {
    "OpenSSL.crypto.TYPE_RSA": _shor("RSA", "key_generation", ML_KEM_DSA),
    "OpenSSL.crypto.TYPE_DSA": _shor("DSA", "signing", ML_DSA),
}


@dataclass(frozen=True)
class DispatchRule:
    """Key generation whose algorithm rides in a string argument.

    Several APIs pick the algorithm from a string literal at the call site
    (``JWK.generate(kty="RSA")``, ``generate_private_key("ssh-rsa")``,
    ``generate_pair("rsa")``). Because the selector is a literal, this stays
    low-false-positive without data flow — the same idea as the pyOpenSSL
    ``TYPE_*`` heuristic, but keyed on a string instead of a constant.

    ``arg`` is the keyword to read; if absent, the engine falls back to the first
    positional argument. A literal found in ``table`` yields its `Rule`. Any other
    literal — or a non-literal / missing selector — yields ``default``. ``default``
    of ``None`` means "not a finding": used for JOSE, where ``kty="oct"`` is a
    symmetric key (no Shor concern) and an unresolved ``kty`` must not be guessed.
    A non-``None`` ``default`` is for APIs where *every* selector is asymmetric and
    Shor-broken (SSH keys, ``generate_pair``), so even an unreadable selector is
    still a real finding.
    """

    arg: str
    table: dict[str, Rule]
    default: Rule | None = None


# JOSE key-type table shared by jwcrypto and authlib. ``oct`` is deliberately
# absent (symmetric key -> no Shor finding), and ``default=None`` suppresses it.
_JOSE_KTY: dict[str, Rule] = {
    "rsa": _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
    "ec": _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
    "okp": _shor("OKP (Ed/X)", "key_generation", ML_DSA_KEM_OKP),
}

# Keyed by (import root, leaf, attr), like ``ROOT_RULES``.
DISPATCH_RULES: dict[tuple[str, str, str], DispatchRule] = {
    # jwcrypto: ``jwk.JWK.generate(kty="RSA"|"EC"|"OKP"|"oct", ...)``.
    ("jwcrypto", "JWK", "generate"): DispatchRule("kty", _JOSE_KTY, default=None),
    # authlib high-level: ``JsonWebKey.generate_key(kty, crv_or_size, ...)`` — the
    # kty is the first positional argument.
    ("authlib", "JsonWebKey", "generate_key"): DispatchRule("kty", _JOSE_KTY, default=None),
    # asyncssh: ``generate_private_key("ssh-rsa"|"ssh-ed25519"|"ecdsa-...", ...)``.
    # Every SSH key algorithm is asymmetric and Shor-broken, so an unknown or
    # unreadable selector still defaults to a CRITICAL generic-SSH-key finding.
    ("asyncssh", "asyncssh", "generate_private_key"): DispatchRule(
        "alg_name",
        {
            "ssh-rsa": _shor("RSA", "key_generation", ML_KEM_DSA),
            "ssh-dss": _shor("DSA", "signing", ML_DSA),
            "ssh-ed25519": _shor("Ed25519", "signing", ML_DSA),
            "ssh-ed448": _shor("Ed448", "signing", ML_DSA),
        },
        default=_shor("SSH key (RSA/DSA/ECDSA/EdDSA)", "key_generation", ML_KEM_DSA),
    ),
    # oscrypto: ``asymmetric.generate_pair("rsa"|"dsa"|"ec", ...)`` — all Shor-broken.
    ("oscrypto", "asymmetric", "generate_pair"): DispatchRule(
        "algorithm",
        {
            "rsa": _shor("RSA", "key_generation", ML_KEM_DSA, "key_size"),
            "dsa": _shor("DSA", "signing", ML_DSA, "key_size"),
            "ec": _shor("ECC", "key_generation", ML_KEM_ECDH_DSA, "curve"),
        },
        default=_shor("RSA/DSA/ECC", "key_generation", ML_KEM_ECDH_DSA),
    ),
}


def lookup_dispatch(qualified_name: str) -> DispatchRule | None:
    """Return the string-dispatch rule for a qualified callable, or ``None``.

    Keyed like ``ROOT_RULES`` by ``(root, leaf, attr)`` so the same class/function
    name in another library cannot collide.
    """
    parts = qualified_name.split(".")
    if len(parts) < 2:
        return None
    return DISPATCH_RULES.get((parts[0], parts[-2], parts[-1]))


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
