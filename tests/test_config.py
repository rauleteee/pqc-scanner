"""Tests for the configuration/infrastructure detection engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_scanner.detectors.config import analyze_config
from pqc_scanner.detectors.discovery import iter_config_files
from pqc_scanner.findings import Classification, Origin, Severity, Usage
from pqc_scanner.outputs.cbom import to_cbom

_SCHEMA = Path(__file__).resolve().parent / "schema" / "bom-1.6.schema.json"


def _algorithms(findings):
    return {f.algorithm for f in findings}


def test_pem_private_key_blocks_detected(tmp_path):
    f = tmp_path / "keys.pem"
    f.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----BEGIN DSA PRIVATE KEY-----\n"
        "-----BEGIN EC PRIVATE KEY-----\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    )
    findings = analyze_config(f)
    assert _algorithms(findings) == {"RSA", "DSA", "ECC", "SSH private key"}
    for finding in findings:
        assert finding.origin is Origin.CONFIG
        assert finding.usage is Usage.CONFIGURATION
        assert finding.classification is Classification.SHOR
        assert finding.severity is Severity.CRITICAL


def test_pkcs8_and_certificate_blocks_are_not_guessed(tmp_path):
    # These headers do not name an algorithm -> classifying them would be a guess.
    f = tmp_path / "mixed.pem"
    f.write_text(
        "-----BEGIN PRIVATE KEY-----\n"       # PKCS#8: algorithm not in header
        "-----BEGIN PUBLIC KEY-----\n"
        "-----BEGIN CERTIFICATE-----\n"
    )
    assert analyze_config(f) == []


def test_ssh_public_keys_detected(tmp_path):
    f = tmp_path / "authorized_keys"
    f.write_text(
        "ssh-rsa AAAAB3NzaC1yc2Eabc user@host\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1abc deploy@ci\n"
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhabc svc@host\n"
        'command="x" ssh-dss AAAAB3NzaC1kc3Mabc legacy@host\n'
    )
    findings = analyze_config(f)
    assert _algorithms(findings) == {"RSA", "Ed25519", "ECDSA", "DSA"}
    assert all(f.origin is Origin.CONFIG for f in findings)


def test_ssh_key_token_without_base64_blob_is_not_a_match(tmp_path):
    # The AAAA wire-format anchor is what prevents false positives on prose.
    f = tmp_path / "notes.conf"
    f.write_text(
        "# rotate the ssh-rsa host key next quarter\n"
        "ssh-rsa\n"
        "ssh-ed25519 not-base64\n"
    )
    assert analyze_config(f) == []


def test_comment_mentioning_algorithms_does_not_match(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("# uses RSA and ECDSA and openssl somewhere, prose only\n")
    assert analyze_config(f) == []


def test_openssl_genrsa_extracts_key_size(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("RUN openssl genrsa -out /k.pem 2048\n")
    (finding,) = analyze_config(f)
    assert finding.algorithm == "RSA-2048"
    assert finding.key_size == 2048


def test_openssl_genrsa_ignores_implausible_size(tmp_path):
    # A digit run that is not a real RSA size must not be annotated.
    f = tmp_path / "Dockerfile"
    f.write_text("RUN openssl genrsa -out /key123.pem\n")
    (finding,) = analyze_config(f)
    assert finding.algorithm == "RSA"
    assert finding.key_size is None


def test_openssl_req_newkey_and_ecparam_and_genpkey(tmp_path):
    f = tmp_path / "gen.sh"
    f.write_text(
        "openssl req -x509 -newkey rsa:4096 -keyout k.pem -out c.pem\n"
        "openssl ecparam -genkey -name prime256v1\n"
        "openssl genpkey -algorithm EC -out ec.pem\n"
        "openssl dsaparam -out dsap.pem 2048\n"
    )
    findings = analyze_config(f)
    assert _algorithms(findings) == {"RSA-4096", "ECC", "DSA"}


def test_ssh_keygen_types(tmp_path):
    f = tmp_path / "setup.sh"
    f.write_text(
        "ssh-keygen -t rsa -b 4096 -f a\n"
        "ssh-keygen -t dsa -f b\n"
        "ssh-keygen -t ecdsa -f c\n"
        "ssh-keygen -t ed25519 -f d\n"
    )
    findings = analyze_config(f)
    assert _algorithms(findings) == {"RSA-4096", "DSA", "ECDSA", "Ed25519"}


def test_findings_carry_location(tmp_path):
    f = tmp_path / "authorized_keys"
    f.write_text("\nssh-rsa AAAAB3NzaC1yc2Eabc user@host\n")
    (finding,) = analyze_config(f)
    assert finding.line == 2
    assert finding.symbol == "ssh-rsa public key"


def test_unreadable_file_yields_no_findings(tmp_path):
    missing = tmp_path / "nope.pem"
    assert analyze_config(missing) == []


def test_discovery_selects_config_files(tmp_path):
    (tmp_path / "Dockerfile").write_text("x")
    (tmp_path / "Dockerfile.prod").write_text("x")
    (tmp_path / ".env.local").write_text("x")
    (tmp_path / "app.conf").write_text("x")
    (tmp_path / "key.pem").write_text("x")
    (tmp_path / "main.py").write_text("x")  # not a config file
    (tmp_path / "README.md").write_text("x")  # not a config file
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.pem").write_text("x")  # pruned dir

    names = {p.name for p in iter_config_files(tmp_path)}
    assert names == {"Dockerfile", "Dockerfile.prod", ".env.local", "app.conf", "key.pem"}


def test_config_findings_produce_valid_cbom(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    f = tmp_path / "authorized_keys"
    f.write_text("ssh-rsa AAAAB3NzaC1yc2Eabc user@host\n")
    doc = to_cbom(analyze_config(f))
    jsonschema.validate(doc, json.loads(_SCHEMA.read_text()))
    (component,) = doc["components"]
    assert component["type"] == "cryptographic-asset"
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["pqc-audit:severity"] == "CRITICAL"
    assert "2030" in props["pqc-audit:compliance"]
