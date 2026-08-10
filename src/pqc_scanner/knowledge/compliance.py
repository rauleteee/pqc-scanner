"""Regulatory compliance mapping — the single source of truth for the deadlines.

Turns a finding's quantum classification into the regulatory deadline that drives
its urgency. This is the piece that converts a technical finding into a business
argument: "this must be migrated by 2030" is what a decision-maker acts on.

Kept in the domain, alongside the rule bases, because it is crypto-regulatory
knowledge — not parsing and not presentation. Output adapters look it up by a
finding's `Classification`; the `Finding` entity itself stays free of it (findings
is the innermost entity and must not import this package, which would cycle).

Grounding:
- NIST IR 8547 (transition to PQC standards): classical asymmetric primitives
  broken by Shor (RSA, ECDSA, ECDH, DH, EdDSA) are **deprecated after 2030** and
  **disallowed after 2035**. CNSA 2.0 sets the same 2030-2035 window for national
  security systems. The "harvest now, decrypt later" (HNDL) risk applies today.
- NIST SP 800-131A governs the Grover-weakened / legacy primitives (SHA-1, MD5,
  DES/3DES, RC4, AES-128): these are a classical-strength issue, not a PQC
  deadline — the guidance is to move to AES-256 / SHA-256+ now.
- The standardized replacements are FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA).
"""

from __future__ import annotations

from pqc_scanner.findings import Classification

# Keyed by quantum classification: the deadline is a function of *why* a primitive
# is at risk, not of the specific algorithm, so one note serves every Shor finding.
COMPLIANCE_BY_CLASSIFICATION: dict[Classification, str] = {
    Classification.SHOR: (
        "NIST IR 8547 / CNSA 2.0: deprecated after 2030, disallowed after 2035 — "
        "harvest-now-decrypt-later risk applies today"
    ),
    Classification.GROVER: (
        "Not a PQC deadline; classical-strength issue — move to AES-256 / SHA-256+ "
        "(NIST SP 800-131A)"
    ),
    Classification.PQC: "Post-quantum compliant (NIST FIPS 203/204/205)",
}


def compliance_for(classification: Classification) -> str:
    """Return the regulatory compliance note for a finding's classification."""
    return COMPLIANCE_BY_CLASSIFICATION[classification]


# Compact, shareable deadline chip — the full sentence above rides in the JSON/
# CBOM ``compliance`` field; a terminal or document table cell wants a short label.
SHORT_DEADLINE_BY_CLASSIFICATION: dict[Classification, str] = {
    Classification.SHOR: "2030 → 2035",
    Classification.GROVER: "—",
    Classification.PQC: "compliant",
}


def short_deadline_for(classification: Classification) -> str:
    """Return the compact deadline label for a finding's classification."""
    return SHORT_DEADLINE_BY_CLASSIFICATION[classification]
