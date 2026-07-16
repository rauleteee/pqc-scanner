"""Tests for CycloneDX CBOM output (phase 4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_scanner import scan, to_cbom
from pqc_scanner.findings import Classification, Finding, Origin, Severity, Usage

EXAMPLE = Path(__file__).resolve().parent.parent / "examples"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "bom-1.6.schema.json"

FIXED_KWARGS = dict(
    serial_number="urn:uuid:00000000-0000-4000-8000-000000000000",
    timestamp="2026-07-01T00:00:00+00:00",
)


def _finding(**overrides) -> Finding:
    base = dict(
        path="a.py",
        line=1,
        column=0,
        algorithm="RSA-2048",
        usage=Usage.KEY_GENERATION,
        classification=Classification.SHOR,
        severity=Severity.CRITICAL,
        origin=Origin.CODE,
        library="cryptography",
        migration_target="ML-KEM / ML-DSA",
        symbol="rsa.generate_private_key",
        key_size=2048,
    )
    base.update(overrides)
    return Finding(**base)


def test_envelope_fields():
    doc = to_cbom([], **FIXED_KWARGS)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"] == FIXED_KWARGS["serial_number"]
    assert doc["metadata"]["tools"]["components"][0]["name"] == "pqc-audit"
    assert doc["components"] == []


def test_serialnumber_is_urn_uuid_when_not_overridden():
    doc = to_cbom([])
    assert doc["serialNumber"].startswith("urn:uuid:")


def test_component_shape_for_rsa():
    doc = to_cbom([_finding()], **FIXED_KWARGS)
    (component,) = doc["components"]
    assert component["type"] == "cryptographic-asset"
    assert component["name"] == "RSA-2048"
    algo = component["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] == "pke"
    assert algo["parameterSetIdentifier"] == "2048"
    assert algo["nistQuantumSecurityLevel"] == 0
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["pqc-audit:severity"] == "CRITICAL"
    assert props["pqc-audit:classification"] == "SHOR"


def test_curve_maps_to_curve_field():
    finding = _finding(algorithm="ECC-P-256", usage=Usage.KEY_GENERATION, key_size=None, curve="P-256")
    algo = to_cbom([finding], **FIXED_KWARGS)["components"][0]["cryptoProperties"][
        "algorithmProperties"
    ]
    assert algo["curve"] == "P-256"
    assert "parameterSetIdentifier" not in algo


def test_same_asset_groups_occurrences():
    a = _finding(path="one.py", line=3)
    b = _finding(path="two.py", line=9)
    doc = to_cbom([a, b], **FIXED_KWARGS)
    # One component, two occurrences (same library/algorithm/usage).
    (component,) = doc["components"]
    occ = component["evidence"]["occurrences"]
    assert [o["location"] for o in occ] == ["one.py", "two.py"]
    assert occ[0]["line"] == 3 and occ[0]["symbol"] == "rsa.generate_private_key"


def test_distinct_assets_are_separate_components():
    rsa = _finding()
    aes = _finding(
        algorithm="AES",
        usage=Usage.ENCRYPTION,
        classification=Classification.GROVER,
        severity=Severity.MEDIUM,
        library="cryptography",
        symbol="algorithms.AES",
        key_size=None,
    )
    doc = to_cbom([rsa, aes], **FIXED_KWARGS)
    assert len(doc["components"]) == 2


def test_pqc_key_exchange_primitive_is_kem():
    finding = _finding(
        algorithm="ML-KEM (Kyber512)",
        usage=Usage.KEY_EXCHANGE,
        classification=Classification.PQC,
        severity=Severity.INFO,
        library="oqs",
        symbol="oqs.KeyEncapsulation",
        key_size=None,
        parameter="Kyber512",
    )
    algo = to_cbom([finding], **FIXED_KWARGS)["components"][0]["cryptoProperties"][
        "algorithmProperties"
    ]
    assert algo["primitive"] == "kem"
    assert algo["parameterSetIdentifier"] == "Kyber512"
    # No quantum level asserted for an already-PQC asset.
    assert "nistQuantumSecurityLevel" not in algo


def _dependency_finding(**overrides) -> Finding:
    base = dict(
        path="requirements.txt",
        line=2,
        column=0,
        algorithm="RSA/ECC/DH/Ed25519",
        usage=Usage.DEPENDENCY,
        classification=Classification.SHOR,
        severity=Severity.CRITICAL,
        origin=Origin.DEPENDENCY,
        library="cryptography",
        migration_target="ML-KEM / ML-DSA",
        symbol="cryptography==41.0.7",
        version="41.0.7",
    )
    base.update(overrides)
    return Finding(**base)


def test_dependency_becomes_library_component():
    doc = to_cbom([_dependency_finding()], **FIXED_KWARGS)
    (component,) = doc["components"]
    assert component["type"] == "library"
    assert component["name"] == "cryptography"
    assert component["version"] == "41.0.7"
    assert component["purl"] == "pkg:pypi/cryptography@41.0.7"
    occ = component["evidence"]["occurrences"][0]
    assert occ["location"] == "requirements.txt" and occ["line"] == 2
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["pqc-audit:severity"] == "CRITICAL"
    assert props["pqc-audit:provides"] == "RSA/ECC/DH/Ed25519"


def test_dependency_without_version_omits_version_and_pins_purl():
    doc = to_cbom([_dependency_finding(version=None, symbol="paramiko", library="paramiko")], **FIXED_KWARGS)
    (component,) = doc["components"]
    assert "version" not in component
    assert component["purl"] == "pkg:pypi/paramiko"


def test_code_and_dependency_components_coexist():
    doc = to_cbom([_finding(), _dependency_finding()], **FIXED_KWARGS)
    types = [c["type"] for c in doc["components"]]
    assert types == ["cryptographic-asset", "library"]


def test_dependency_component_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    if not SCHEMA_PATH.exists():
        pytest.skip("CycloneDX schema not vendored")
    schema = json.loads(SCHEMA_PATH.read_text())
    doc = to_cbom([_finding(), _dependency_finding()], **FIXED_KWARGS)
    jsonschema.validate(instance=doc, schema=schema)


def test_output_is_json_serializable():
    doc = to_cbom(scan(EXAMPLE), **FIXED_KWARGS)
    # Round-trips without error and stays a dict.
    assert isinstance(json.loads(json.dumps(doc)), dict)


@pytest.mark.skipif(not SCHEMA_PATH.exists(), reason="CycloneDX schema not vendored")
def test_validates_against_cyclonedx_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    doc = to_cbom(scan(EXAMPLE), **FIXED_KWARGS)
    jsonschema.validate(instance=doc, schema=schema)
