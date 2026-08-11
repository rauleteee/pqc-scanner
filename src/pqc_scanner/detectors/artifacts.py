"""Encrypted-artifact detection engine (data-at-rest).

Input adapter (a sibling of the AST, dependency and config detectors) that reads
the *headers/metadata* of encrypted files and key material to name the asymmetric
algorithm protecting them, **without decrypting or requesting any key**. It parses
formats and consults `knowledge/artifacts.py`; it owns no crypto knowledge.

Scope (v1): OpenPGP (``.gpg``/``.pgp``/``.asc``, binary or ASCII-armored) and age
(``.age``). Both are read only far enough to recover the public-key algorithm of
the recipient / key wrapping — the layer Shor breaks and the real HNDL risk. The
symmetric bulk cipher (AES) is deliberately not reported: AES-256 is fine and
flagging it would be a false alarm.

Every parse is defensive: any malformed or unrecognized structure yields no
finding rather than a guess, keeping false positives at zero.
"""

from __future__ import annotations

import base64
from pathlib import Path

from pqc_scanner.findings import Classification, Finding, Origin, Severity, Usage
from pqc_scanner.knowledge import AGE_RECIPIENTS, PGP_PUBKEY_ALGORITHMS

# OpenPGP packet tags we read, mapped to a human label for the finding's symbol.
_PGP_TAG_LABEL: dict[int, str] = {
    1: "PGP encrypted session key",
    2: "PGP signature",
    5: "PGP secret key",
    6: "PGP public key",
}


def analyze_artifact(path: str | Path) -> list[Finding]:
    """Analyze one encrypted-artifact / key file and return its findings.

    Unreadable files yield no findings rather than aborting a whole-repo scan.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError:
        return []

    suffix = path.suffix.lower()
    if suffix == ".age" or raw[:21] == b"age-encryption.org/v1" or _is_age_armor(raw):
        rules = _analyze_age(raw)
    else:
        rules = _analyze_openpgp(raw)

    return [_finding(str(path), algorithm, target, library, symbol) for algorithm, target, library, symbol in rules]


def _finding(path: str, algorithm: str, target: str, library: str, symbol: str) -> Finding:
    # All v1 artifact matches are asymmetric key wrapping/material -> Shor/CRITICAL.
    # The artifact is the unit (line 1); its value is the algorithm, not a call site.
    return Finding(
        path=path,
        line=1,
        column=0,
        algorithm=algorithm,
        usage=Usage.DATA_AT_REST,
        classification=Classification.SHOR,
        severity=Severity.CRITICAL,
        origin=Origin.ARTIFACT,
        library=library,
        migration_target=target,
        symbol=symbol,
    )


# --- OpenPGP -------------------------------------------------------------------

def _analyze_openpgp(raw: bytes) -> list[tuple[str, str, str, str]]:
    """Return (algorithm, target, library, symbol) tuples for an OpenPGP file."""
    data = _dearmor(raw) if b"-----BEGIN PGP" in raw[:64] else raw
    if data is None:
        return []
    results: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for tag, body in _iter_pgp_packets(data):
        if tag not in _PGP_TAG_LABEL:
            continue
        algo_id = _pgp_algo(tag, body)
        if algo_id is None:
            continue
        rule = PGP_PUBKEY_ALGORITHMS.get(algo_id)
        if rule is None:  # unknown/unassigned algorithm id -> do not guess
            continue
        name, target = rule
        label = _PGP_TAG_LABEL[tag]
        key = (label, name)
        if key in seen:  # dedup subkeys/recipients of the same algorithm
            continue
        seen.add(key)
        results.append((name, target, "openpgp", f"{label} ({name})"))
    return results


def _iter_pgp_packets(data: bytes):
    """Yield ``(tag, body)`` for each OpenPGP packet; stop on any malformed byte.

    Handles old- and new-format packet headers (RFC 9580 section 4.2). Partial and
    indeterminate lengths abort the walk rather than risk misreading — enough to
    reach the leading key/session-key/signature packets, which is all we need.
    """
    i, n = 0, len(data)
    while i < n:
        ctb = data[i]
        if not ctb & 0x80:  # not a packet boundary
            return
        i += 1
        if ctb & 0x40:  # new format
            tag = ctb & 0x3F
            if i >= n:
                return
            first = data[i]
            i += 1
            if first < 192:
                length = first
            elif first < 224:
                if i >= n:
                    return
                length = ((first - 192) << 8) + data[i] + 192
                i += 1
            elif first == 255:
                if i + 4 > n:
                    return
                length = int.from_bytes(data[i : i + 4], "big")
                i += 4
            else:  # partial body length -> unsupported, stop
                return
        else:  # old format
            tag = (ctb >> 2) & 0x0F
            ltype = ctb & 0x03
            if ltype == 0:
                if i >= n:
                    return
                length = data[i]
                i += 1
            elif ltype == 1:
                if i + 2 > n:
                    return
                length = int.from_bytes(data[i : i + 2], "big")
                i += 2
            elif ltype == 2:
                if i + 4 > n:
                    return
                length = int.from_bytes(data[i : i + 4], "big")
                i += 4
            else:  # indeterminate length -> stop
                return
        body = data[i : i + length]
        if len(body) < length:
            return
        yield tag, body
        i += length


def _pgp_algo(tag: int, body: bytes) -> int | None:
    """Return the public-key algorithm id from a packet body, or ``None``.

    Offsets follow the packet's version, per RFC 9580. Only the common versions
    are read; anything else returns ``None`` (no guess).
    """
    if not body:
        return None
    version = body[0]
    if tag == 1:  # Public-Key Encrypted Session Key: v3 = version, keyid(8), algo
        if version == 3 and len(body) >= 10:
            return body[9]
        return None
    if tag in (5, 6):  # Secret-/Public-Key: version, timestamp(4), [v3 validity(2)], algo
        if version in (4, 6) and len(body) >= 6:
            return body[5]
        if version == 3 and len(body) >= 8:
            return body[7]
        return None
    if tag == 2:  # Signature: v4/v6 = version, sig type, algo
        if version in (4, 6) and len(body) >= 3:
            return body[2]
        return None
    return None


# --- age -----------------------------------------------------------------------

def _analyze_age(raw: bytes) -> list[tuple[str, str, str, str]]:
    """Return (algorithm, target, library, symbol) tuples for an age file."""
    data = _dearmor(raw) if _is_age_armor(raw) else raw
    if data is None:
        return []
    text = data.decode("utf-8", errors="ignore")
    results: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("-> "):
            continue
        parts = line[3:].split()
        if not parts:
            continue
        rtype = parts[0]
        rule = AGE_RECIPIENTS.get(rtype)
        if rule is None or rtype in seen:
            continue
        seen.add(rtype)
        name, target = rule
        results.append((name, target, "age", f"age {rtype} recipient"))
    return results


def _is_age_armor(raw: bytes) -> bool:
    return b"-----BEGIN AGE ENCRYPTED FILE-----" in raw[:64]


# --- shared armor --------------------------------------------------------------

def _dearmor(raw: bytes) -> bytes | None:
    """Extract and base64-decode the body of an ASCII-armored block.

    Drops armor header lines (``Key: value``), blank lines and the PGP CRC line
    (``=...``). Returns ``None`` if the base64 body cannot be decoded.
    """
    text = raw.decode("latin-1", errors="ignore")
    lines = text.splitlines()
    body: list[str] = []
    started = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("-----BEGIN "):
            started = True
            continue
        if stripped.startswith("-----END "):
            break
        if not started:
            continue
        if not stripped or stripped.startswith("=") or _is_armor_header(stripped):
            continue
        body.append(stripped)
    if not body:
        return None
    try:
        # binascii.Error (raised on bad base64) is a subclass of ValueError.
        return base64.b64decode("".join(body), validate=False)
    except ValueError:
        return None


def _is_armor_header(line: str) -> bool:
    # An armor header is ``Word: value`` (e.g. ``Version: GnuPG``). base64 never
    # contains a space, so a ": " reliably marks a header rather than key data.
    return ": " in line
