"""Encrypted-artifact rule base: what a file's crypto header/metadata means.

The knowledge half of the data-at-rest detector. This closes the other half of
"harvest now, decrypt later": not the code that *generates* crypto, but the
already-encrypted files an attacker can record today and decrypt once a quantum
computer exists. The detector identifies the algorithm from format headers
**without decrypting or asking for keys**.

The precision nuance that keeps false positives low: Shor breaks the *asymmetric*
layer, so the HNDL risk lives in the **asymmetric key wrapping / recipient key**,
not in the symmetric bulk cipher. Seeing "AES" is not a finding (AES-256 is fine;
Grover only weakens it). So this table maps the *public-key* algorithm of the
wrapping/recipient — every one of which is broken by Shor -> CRITICAL.

Kept in the domain (like the other rule bases); the detector adapter
(`detectors/artifacts.py`) parses the bytes and consults this table, owning none.
"""

from __future__ import annotations

from pqc_scanner.knowledge.targets import ML_DSA, ML_KEM, ML_KEM_DSA

# OpenPGP public-key algorithm registry (RFC 9580 / RFC 4880, section 9.1). Every
# asymmetric algorithm OpenPGP defines is broken by Shor, so all map to a CRITICAL
# finding; the value is (display name, migration target) chosen by the algorithm's
# role (key transport / agreement -> ML-KEM; signature -> ML-DSA).
PGP_PUBKEY_ALGORITHMS: dict[int, tuple[str, str]] = {
    1: ("RSA", ML_KEM_DSA),  # RSA (Encrypt or Sign)
    2: ("RSA", ML_KEM_DSA),  # RSA Encrypt-Only
    3: ("RSA", ML_KEM_DSA),  # RSA Sign-Only
    16: ("ElGamal", ML_KEM),  # ElGamal Encrypt-Only
    17: ("DSA", ML_DSA),
    18: ("ECDH", ML_KEM),
    19: ("ECDSA", ML_DSA),
    20: ("ElGamal", ML_KEM),  # ElGamal Encrypt or Sign (legacy/deprecated)
    22: ("EdDSA", ML_DSA),  # EdDSA legacy format
    25: ("X25519", ML_KEM),
    26: ("X448", ML_KEM),
    27: ("Ed25519", ML_DSA),
    28: ("Ed448", ML_DSA),
}

# age recipient stanza type -> (display name, migration target). age's asymmetric
# recipients are X25519 (native) and P-256 via the PIV/YubiKey plugin; both are
# broken by Shor. The ``scrypt`` stanza is passphrase-based (symmetric) and is
# intentionally absent — it carries no quantum-vulnerable key wrapping.
AGE_RECIPIENTS: dict[str, tuple[str, str]] = {
    "X25519": ("X25519", ML_KEM),
    "piv-p256": ("ECDH-P-256", ML_KEM),
}
