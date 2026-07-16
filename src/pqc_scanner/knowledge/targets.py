"""Post-quantum migration targets — the single source of truth for the strings.

Both knowledge tables (code rules and dependency rules) point at these same
constants, so the guidance a user reads is identical whether a primitive was
found at a call site or as a declared package. Defining them once avoids the
drift of the same sentence written in two places.

Targets follow NIST's standardized PQC selections: ML-KEM (FIPS 203) for key
establishment, ML-DSA (FIPS 204) for signatures.
"""

from __future__ import annotations

# Asymmetric primitives broken by Shor -> the standardized PQC replacements.
ML_KEM_DSA = "ML-KEM (key establishment) / ML-DSA (signatures)"
ML_KEM = "ML-KEM"
ML_DSA = "ML-DSA"
ML_KEM_ECDH_DSA = "ML-KEM (ECDH) / ML-DSA (ECDSA)"
ML_DSA_KEM_OKP = "ML-DSA (Ed25519/Ed448) / ML-KEM (X25519/X448)"

# Symmetric/hash primitives weakened by Grover -> larger, still-classical sizes.
AES256 = "AES-256"
STRONG_HASH = "SHA-256 / SHA-3"

# Already post-quantum: reported for completeness, nothing to migrate.
ALREADY_PQC = "already post-quantum — no migration needed"
