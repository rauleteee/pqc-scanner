"""Tests for the encrypted-artifact (data-at-rest) detection engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_scanner.detectors.artifacts import analyze_artifact
from pqc_scanner.detectors.discovery import iter_artifact_files
from pqc_scanner.findings import Classification, Origin, Severity, Usage
from pqc_scanner.outputs.cbom import to_cbom

_SCHEMA = Path(__file__).resolve().parent / "schema" / "bom-1.6.schema.json"


def _new_packet(tag: int, body: bytes) -> bytes:
    """A new-format OpenPGP packet with a one-octet length (bodies stay < 192)."""
    return bytes([0xC0 | tag, len(body)]) + body


def _pkesk_v3(algo: int) -> bytes:
    # version(3) + key id(8) + public-key algorithm + (dummy) session key material.
    return _new_packet(1, bytes([3]) + b"\x00" * 8 + bytes([algo]) + b"\x01\x02")


def _pubkey_v4(algo: int) -> bytes:
    # version(4) + timestamp(4) + public-key algorithm + (dummy) key material.
    return _new_packet(6, bytes([4, 0, 0, 0, 0, algo]) + b"\x01\x02")


def test_openpgp_rsa_session_key_detected(tmp_path):
    f = tmp_path / "message.gpg"
    f.write_bytes(_pkesk_v3(1))  # algo 1 = RSA
    (finding,) = analyze_artifact(f)
    assert finding.algorithm == "RSA"
    assert finding.origin is Origin.ARTIFACT
    assert finding.usage is Usage.DATA_AT_REST
    assert finding.classification is Classification.SHOR
    assert finding.severity is Severity.CRITICAL
    assert finding.symbol == "PGP encrypted session key (RSA)"


def test_openpgp_ecdh_and_eddsa_and_x_algorithms(tmp_path):
    cases = {18: "ECDH", 19: "ECDSA", 22: "EdDSA", 25: "X25519", 27: "Ed25519"}
    for algo, name in cases.items():
        f = tmp_path / f"k{algo}.gpg"
        f.write_bytes(_pubkey_v4(algo))
        (finding,) = analyze_artifact(f)
        assert finding.algorithm == name


def test_openpgp_symmetric_only_is_not_flagged(tmp_path):
    # A passphrase (symmetric) SKESK packet (tag 3) carries no asymmetric wrapping,
    # so there is no Shor risk -> no finding. This is the key false-positive guard:
    # seeing AES-encrypted data is not a reason to alarm.
    f = tmp_path / "sym.gpg"
    f.write_bytes(_new_packet(3, bytes([4, 9, 3, 10]) + b"\x00\x00"))  # cipher 9 = AES-256
    assert analyze_artifact(f) == []


def test_openpgp_unknown_algorithm_id_is_not_guessed(tmp_path):
    f = tmp_path / "future.gpg"
    f.write_bytes(_pubkey_v4(99))  # unassigned algorithm id
    assert analyze_artifact(f) == []


def test_random_bytes_yield_no_finding(tmp_path):
    f = tmp_path / "noise.gpg"
    f.write_bytes(bytes(range(256)) * 4)
    assert analyze_artifact(f) == []


# A real GnuPG ASCII-armored message encrypted to an ECC (cv25519) key: its PKESK
# packet names public-key algorithm 18 (ECDH). Embedded so the test needs no gpg.
_REAL_ECC_ASC = """-----BEGIN PGP MESSAGE-----

hF4D9aCVQSY4oQ0SAQdAsG7KqPlCNewwVqaP6dna/m07v5fLW3c3ztB2wznDyTkw
VF6HVCaGwsJxXYZbUSm7cAgen/u2sGOhK+XLY5LId6fE2mrLhoUadZ5PWve/avGD
0lYBvPk4ts5AJqRx8SKCvqPCD5pOhA04vqVyNVGpSf5JVjg+rNtJ86W3B+jezeua
KLWmKL8dKnKK0F2tKZEVSkqePpBFHOxyXfXBfgzCUP2vbMG2mxo/jg==
=r/bv
-----END PGP MESSAGE-----
"""


def test_openpgp_real_armored_message(tmp_path):
    f = tmp_path / "real.asc"
    f.write_text(_REAL_ECC_ASC)
    (finding,) = analyze_artifact(f)
    assert finding.algorithm == "ECDH"
    assert finding.symbol == "PGP encrypted session key (ECDH)"


def test_age_x25519_recipient_detected(tmp_path):
    f = tmp_path / "secret.age"
    f.write_text(
        "age-encryption.org/v1\n"
        "-> X25519 TEjIkQabc\n"
        "body\n"
        "--- mac\n"
    )
    (finding,) = analyze_artifact(f)
    assert finding.algorithm == "X25519"
    assert finding.classification is Classification.SHOR
    assert finding.symbol == "age X25519 recipient"


def test_age_scrypt_passphrase_is_not_flagged(tmp_path):
    # scrypt = passphrase-based (symmetric), no asymmetric key wrapping -> no finding.
    f = tmp_path / "pass.age"
    f.write_text("age-encryption.org/v1\n-> scrypt abcd 18\nbody\n--- mac\n")
    assert analyze_artifact(f) == []


def test_unreadable_file_yields_no_findings(tmp_path):
    assert analyze_artifact(tmp_path / "missing.gpg") == []


def test_artifact_findings_produce_valid_cbom(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    f = tmp_path / "message.gpg"
    f.write_bytes(_pkesk_v3(1))
    doc = to_cbom(analyze_artifact(f))
    jsonschema.validate(doc, json.loads(_SCHEMA.read_text()))
    (component,) = doc["components"]
    assert component["type"] == "cryptographic-asset"
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["pqc-audit:severity"] == "CRITICAL"
    assert "2030" in props["pqc-audit:compliance"]


def test_discovery_selects_artifact_files(tmp_path):
    for name in ("a.gpg", "b.pgp", "c.asc", "d.age", "e.txt", "f.py"):
        (tmp_path / name).write_text("x")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.gpg").write_text("x")
    names = {p.name for p in iter_artifact_files(tmp_path)}
    assert names == {"a.gpg", "b.pgp", "c.asc", "d.age"}
