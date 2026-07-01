"""Tests for the AST detection engine (phase 2)."""

from __future__ import annotations

from pathlib import Path

from pqc_scanner.detectors.ast_engine import analyze_file
from pqc_scanner.findings import Classification, Severity

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_sample.py"


def _by_algorithm(findings):
    return {f.algorithm: f for f in findings}


def test_example_sample_detects_expected_primitives():
    findings = analyze_file(EXAMPLE)
    by_algo = _by_algorithm(findings)

    # Granularity: RSA carries its key size, ECC its curve; the AES key is a
    # variable so its size cannot be inferred and stays generic.
    assert set(by_algo) == {"RSA-2048", "ECC-P-256", "AES"}

    assert by_algo["RSA-2048"].severity is Severity.CRITICAL
    assert by_algo["RSA-2048"].classification is Classification.SHOR
    assert by_algo["RSA-2048"].usage == "key_generation"
    assert "ML-" in by_algo["RSA-2048"].migration_target

    assert by_algo["ECC-P-256"].severity is Severity.CRITICAL
    assert by_algo["AES"].severity is Severity.MEDIUM
    assert by_algo["AES"].classification is Classification.GROVER


def test_findings_carry_location(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.line == 3
    assert finding.symbol == "rsa.generate_private_key"
    assert finding.origin == "code"
    assert finding.library == "cryptography"
    assert finding.algorithm == "RSA-2048"
    assert Path(finding.path) == src


def test_comment_and_variable_name_do_not_match(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "# rsa.generate_private_key mentioned in a comment\n"
        "label = 'rsa.generate_private_key'\n"
        "handler = rsa.generate_private_key  # referenced, not called\n"
    )
    assert analyze_file(src) == []


def test_same_named_local_function_is_not_reported(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "def generate_private_key():\n"
        "    return 1\n"
        "\n"
        "generate_private_key()\n"
    )
    # No crypto import -> the local call must not resolve to a rule.
    assert analyze_file(src) == []


def test_aliased_import_resolves(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa as r\n"
        "r.generate_private_key(key_size=2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-2048"


def test_dotted_module_import_resolves(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "import cryptography.hazmat.primitives.asymmetric.ec as ec\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
    )
    by_algo = _by_algorithm(analyze_file(src))
    assert "ECC-P-256" in by_algo


def test_syntax_error_yields_no_findings(tmp_path):
    src = tmp_path / "broken.py"
    src.write_text("def oops(:\n")
    assert analyze_file(src) == []


def test_pycryptodome_positional_key_size(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.PublicKey import RSA\n"
        "RSA.generate(4096)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-4096"
    assert finding.severity is Severity.CRITICAL


def test_pycryptodome_ecc_curve_kwarg(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.PublicKey import ECC\n"
        "ECC.generate(curve='P-256')\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC-P-256"


def test_aes_bytes_literal_reveals_key_size(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.Cipher import AES\n"
        "AES.new(b'0123456789abcdef', AES.MODE_EAX)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "AES-128"
    assert finding.classification is Classification.GROVER


def test_paramiko_rsa_key_generation(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "import paramiko\n"
        "paramiko.RSAKey.generate(2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-2048"
    assert finding.usage == "key_generation"


def test_ed25519_class_method_is_detected(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "Ed25519PrivateKey.generate()\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "Ed25519"
    assert finding.usage == "signing"
    assert finding.migration_target == "ML-DSA"


def test_positional_public_exponent_is_not_read_as_key_size(tmp_path):
    # pyca signature is (public_exponent, key_size); the first positional 65537
    # must NOT be reported as an RSA size.
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA"


def test_curve_aliases_normalize_to_canonical(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.PublicKey import ECC\n"
        "ECC.generate(curve='prime256v1')\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC-P-256"


def test_invalid_aes_key_length_stays_generic(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.Cipher import AES\n"
        "AES.new(b'too-short', AES.MODE_EAX)\n"  # 9 bytes -> not a valid AES key
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "AES"


def test_findings_sorted_by_location(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "def f():\n"
        "    return ec.generate_private_key(ec.SECP256R1())\n"
        "def g():\n"
        "    return rsa.generate_private_key(key_size=2048)\n"
    )
    lines = [f.line for f in analyze_file(src)]
    assert lines == sorted(lines)


def test_pqc_library_reported_as_info(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "import oqs\n"
        "oqs.KeyEncapsulation('Kyber512')\n"
    )
    (finding,) = analyze_file(src)
    assert finding.classification is Classification.PQC
    assert finding.severity is Severity.INFO
    assert finding.algorithm == "ML-KEM (Kyber512)"
