"""Config/infra rule base: anchored patterns for crypto declared outside code.

The knowledge half of the configuration detector. Quantum-vulnerable cryptography
often lives as *strings* in config/infra files rather than in Python calls: SSH
public keys and configs, PEM key material, and key-generation commands baked into
Dockerfiles or CI. The AST engine cannot see these, so a separate detector feeds
the same `Finding`/CBOM model from here.

The design rule that keeps false positives low — the whole value of this over the
naive substring-grep tutorials — is that **every pattern is anchored on structure**
that only a real cryptographic declaration has:

- a PEM header names its algorithm (``BEGIN RSA PRIVATE KEY``);
- an SSH public key is a key-type token immediately followed by its base64 wire
  format, which always begins ``AAAA`` (a length-prefixed copy of the type name);
- a key-gen command is the tool plus its algorithm selector (``ssh-keygen -t rsa``,
  ``openssl genrsa``).

A bare occurrence of the word "RSA" in a comment never matches any of these.

Kept in the domain (like `code.py`/`dependencies.py`): the detector adapter
(`detectors/config.py`) only walks files and applies these rules; it owns none.
Everything here is asymmetric and broken by Shor -> CRITICAL. Symmetric/TLS cipher
directives (Grover-weakened) and SSH algorithm directives are deferred (higher
noise) to a later increment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pqc_scanner.findings import Classification, Severity, Usage
from pqc_scanner.knowledge.targets import ML_KEM_DSA, ML_KEM_ECDH_DSA, ML_DSA


@dataclass(frozen=True)
class ConfigRule:
    """A single anchored config pattern and what a match means for migration.

    ``regex`` may expose a named group ``size`` (a key length in bits); when it
    matches a plausible value the detector refines ``algorithm`` (``RSA`` ->
    ``RSA-2048``). ``symbol`` is a fixed, human-readable label for the match (the
    raw match can include a whole base64 key, so it is not used verbatim).
    """

    regex: re.Pattern[str]
    algorithm: str
    usage: Usage
    classification: Classification
    severity: Severity
    migration_target: str
    library: str  # source tag, e.g. "openssh" / "pem" / "openssl" (CBOM grouping)
    symbol: str


def _shor(regex: str, algorithm: str, target: str, library: str, symbol: str) -> ConfigRule:
    """A CRITICAL (Shor-broken) config rule; all v1 config patterns are asymmetric."""
    return ConfigRule(
        regex=re.compile(regex),
        algorithm=algorithm,
        usage=Usage.CONFIGURATION,
        classification=Classification.SHOR,
        severity=Severity.CRITICAL,
        migration_target=target,
        library=library,
        symbol=symbol,
    )


# A base64 blob in SSH wire format always starts with ``AAAA`` (it encodes the
# 4-byte length of the key-type string that follows). Requiring it after the
# key-type token is what makes these patterns near-zero-false-positive.
_SSH_B64 = r"\s+AAAA[0-9A-Za-z+/]+"

CONFIG_RULES: tuple[ConfigRule, ...] = (
    # --- PEM private-key blocks: the header names the algorithm ---
    _shor(r"-----BEGIN RSA PRIVATE KEY-----", "RSA", ML_KEM_DSA, "pem", "BEGIN RSA PRIVATE KEY"),
    _shor(r"-----BEGIN DSA PRIVATE KEY-----", "DSA", ML_DSA, "pem", "BEGIN DSA PRIVATE KEY"),
    _shor(r"-----BEGIN EC PRIVATE KEY-----", "ECC", ML_KEM_ECDH_DSA, "pem", "BEGIN EC PRIVATE KEY"),
    # OpenSSH-format private key: the header does not name the type, but every
    # SSH key type it can hold (RSA/DSA/ECDSA/Ed25519) is asymmetric -> CRITICAL.
    _shor(
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "SSH private key",
        ML_KEM_DSA,
        "openssh",
        "BEGIN OPENSSH PRIVATE KEY",
    ),
    # --- SSH public keys (authorized_keys / *.pub / embedded) ---
    _shor(r"(?:^|\s)ssh-rsa" + _SSH_B64, "RSA", ML_KEM_DSA, "openssh", "ssh-rsa public key"),
    _shor(r"(?:^|\s)ssh-dss" + _SSH_B64, "DSA", ML_DSA, "openssh", "ssh-dss public key"),
    _shor(
        r"(?:^|\s)ssh-ed25519" + _SSH_B64, "Ed25519", ML_DSA, "openssh", "ssh-ed25519 public key"
    ),
    _shor(
        r"(?:^|\s)ecdsa-sha2-nistp(?:256|384|521)" + _SSH_B64,
        "ECDSA",
        ML_DSA,
        "openssh",
        "ecdsa-sha2 public key",
    ),
    # --- ssh-keygen key generation (Dockerfiles / CI / shell) ---
    _shor(
        r"\bssh-keygen\b[^\n]*?-t\s+rsa\b(?:[^\n]*?-b\s+(?P<size>\d+))?",
        "RSA",
        ML_KEM_DSA,
        "ssh-keygen",
        "ssh-keygen -t rsa",
    ),
    _shor(r"\bssh-keygen\b[^\n]*?-t\s+dsa\b", "DSA", ML_DSA, "ssh-keygen", "ssh-keygen -t dsa"),
    _shor(
        r"\bssh-keygen\b[^\n]*?-t\s+ecdsa\b", "ECDSA", ML_DSA, "ssh-keygen", "ssh-keygen -t ecdsa"
    ),
    _shor(
        r"\bssh-keygen\b[^\n]*?-t\s+ed25519\b",
        "Ed25519",
        ML_DSA,
        "ssh-keygen",
        "ssh-keygen -t ed25519",
    ),
    # --- openssl key generation ---
    _shor(
        r"\bopenssl\s+genrsa\b(?:[^\n]*?\b(?P<size>\d{3,5})\b)?",
        "RSA",
        ML_KEM_DSA,
        "openssl",
        "openssl genrsa",
    ),
    _shor(
        r"\bopenssl\s+req\b[^\n]*?-newkey\s+rsa:(?P<size>\d+)",
        "RSA",
        ML_KEM_DSA,
        "openssl",
        "openssl req -newkey rsa",
    ),
    _shor(
        r"\bopenssl\s+genpkey\b[^\n]*?-algorithm\s+RSA\b",
        "RSA",
        ML_KEM_DSA,
        "openssl",
        "openssl genpkey -algorithm RSA",
    ),
    _shor(r"\bopenssl\s+ecparam\b", "ECC", ML_KEM_ECDH_DSA, "openssl", "openssl ecparam"),
    _shor(
        r"\bopenssl\s+genpkey\b[^\n]*?-algorithm\s+EC\b",
        "ECC",
        ML_KEM_ECDH_DSA,
        "openssl",
        "openssl genpkey -algorithm EC",
    ),
    _shor(
        r"\bopenssl\s+(?:gendsa|dsaparam)\b", "DSA", ML_DSA, "openssl", "openssl gendsa/dsaparam"
    ),
)

# Plausible RSA key sizes in bits; a captured ``size`` outside this set is dropped
# rather than annotate an untrusted number (keeps the algorithm label honest).
RSA_KEY_SIZES: frozenset[int] = frozenset({512, 1024, 2048, 3072, 4096, 8192})
