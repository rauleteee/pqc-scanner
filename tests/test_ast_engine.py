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


def test_ec_curve_passed_as_variable_is_not_invented(tmp_path):
    # ``ec.generate_private_key(curve)`` — the curve is a variable, not resolvable
    # statically. The finding must stay a plain ``ECC`` (still CRITICAL), never an
    # invented ``ECC-curve`` from the variable's name.
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def make(curve):\n"
        "    return ec.generate_private_key(curve)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC"
    assert finding.curve is None
    assert finding.severity is Severity.CRITICAL


def test_ec_curve_variable_called_is_not_invented(tmp_path):
    # ``ec.generate_private_key(curve=curve())`` where ``curve`` is a variable
    # holding a curve class (real pattern in certbot). The call must not read the
    # variable name ``curve`` as the curve; it stays a plain ``ECC``.
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def make(curve):\n"
        "    return ec.generate_private_key(curve=curve())\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC"
    assert finding.curve is None


def test_ec_curve_instance_via_kwarg(tmp_path):
    # ``curve=ec.SECP256R1()`` (instance as keyword) must still resolve the curve.
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(curve=ec.SECP384R1())\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC-P-384"
    assert finding.curve == "P-384"


def test_ec_curve_method_call_is_not_invented(tmp_path):
    # ``ec.generate_private_key(self.oid.curve())`` (PGPy) and
    # ``ec.generate_private_key(curve=algorithm.signing_algorithm_info())``
    # (aws-encryption-sdk): the argument is a *method* call that returns a curve,
    # not a curve class. Its leaf (``curve`` / ``signing_algorithm_info``) must not
    # be read as the curve name — the finding stays a plain ``ECC``.
    src = tmp_path / "m.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def make(self, algorithm):\n"
        "    a = ec.generate_private_key(self.oid.curve())\n"
        "    b = ec.generate_private_key(curve=algorithm.signing_algorithm_info())\n"
    )
    findings = analyze_file(src)
    assert [f.algorithm for f in findings] == ["ECC", "ECC"]
    assert all(f.curve is None for f in findings)


def test_python_rsa_newkeys_detected(tmp_path):
    # python-rsa (root ``rsa``) exposes key generation as ``rsa.newkeys(nbits)`` —
    # a different library from pyca's ``rsa`` module. The sole positional argument
    # is the key size.
    src = tmp_path / "m.py"
    src.write_text("import rsa\n(pub, priv) = rsa.newkeys(2048)\n")
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-2048"
    assert finding.key_size == 2048
    assert finding.severity is Severity.CRITICAL
    assert finding.usage == "key_generation"


def test_m2crypto_key_generation_detected(tmp_path):
    # M2Crypto's native OpenSSL key generation (real API used by e.g. Salt).
    src = tmp_path / "m.py"
    src.write_text(
        "from M2Crypto import RSA, DSA, EC, DH\n"
        "r = RSA.gen_key(2048, 65537)\n"
        "d = DSA.gen_params(1024)\n"
        "e = EC.gen_params(EC.NID_secp384r1)\n"
        "h = DH.gen_params(2048, 2)\n"
    )
    by_algo = _by_algorithm(analyze_file(src))
    assert set(by_algo) == {"RSA", "DSA-1024", "ECC", "Diffie-Hellman"}
    assert by_algo["RSA"].classification is Classification.SHOR
    assert by_algo["ECC"].curve is None  # NID constant is not a resolvable curve
    assert by_algo["Diffie-Hellman"].usage == "key_exchange"


def test_m2crypto_gen_key_via_dotted_import(tmp_path):
    # The Salt pattern: ``import M2Crypto; M2Crypto.RSA.gen_key(bits, ...)``.
    src = tmp_path / "m.py"
    src.write_text(
        "import M2Crypto\n"
        "rsa = M2Crypto.RSA.gen_key(bits, M2Crypto.m2.RSA_F4, cb)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA"  # ``bits`` is a variable -> no size
    assert finding.classification is Classification.SHOR


def test_md4_new_detected(tmp_path):
    # impacket hashes NTLM passwords with MD4 (fully broken) via pycryptodome.
    src = tmp_path / "m.py"
    src.write_text("from Cryptodome.Hash import MD4\nh = MD4.new()\n")
    (finding,) = analyze_file(src)
    assert finding.algorithm == "MD4"
    assert finding.severity is Severity.MEDIUM
    assert finding.classification is Classification.GROVER


def test_aes_bytes_literal_reveals_key_size(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from Crypto.Cipher import AES\n"
        "AES.new(b'0123456789abcdef', AES.MODE_EAX)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "AES-128"
    assert finding.classification is Classification.GROVER


def test_signingkey_generate_is_ecdsa_for_python_ecdsa(tmp_path):
    # SigningKey.generate is Ed25519 in PyNaCl but ECDSA in python-ecdsa; the
    # import root must disambiguate so we don't mislabel one as the other.
    src = tmp_path / "m.py"
    src.write_text(
        "from ecdsa import SigningKey, NIST256p\n"
        "SigningKey.generate(curve=NIST256p)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECDSA"
    assert finding.severity is Severity.CRITICAL


def test_signingkey_generate_is_ed25519_for_pynacl(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from nacl.signing import SigningKey\n"
        "SigningKey.generate()\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "Ed25519"


def test_pynacl_privatekey_generate_is_curve25519(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from nacl.public import PrivateKey\n"
        "PrivateKey.generate()\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "Curve25519"
    assert finding.usage == "key_exchange"


def test_authlib_rsakey_generate_key(tmp_path):
    # authlib's own JWK API, wrapping cryptography. A user app calls this directly.
    src = tmp_path / "m.py"
    src.write_text(
        "from authlib.jose import RSAKey\n"
        "RSAKey.generate_key(2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-2048"
    assert finding.usage == "key_generation"
    assert finding.severity is Severity.CRITICAL


def test_authlib_eckey_generate_key_with_crv_kwarg(tmp_path):
    # JOSE libraries use ``crv=`` (not ``curve=``) for the curve.
    src = tmp_path / "m.py"
    src.write_text(
        "from authlib.jose import ECKey\n"
        "ECKey.generate_key(crv='P-256')\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "ECC-P-256"


def test_authlib_okpkey_generate_key(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from authlib.jose import OKPKey\n"
        "OKPKey.generate_key(crv='Ed25519')\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "OKP (Ed/X)"
    assert finding.severity is Severity.CRITICAL


def test_stdlib_hashlib_md5_and_sha1_are_flagged(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "import hashlib\n"
        "hashlib.md5(b'x')\n"
        "hashlib.sha1(b'y')\n"
        "hashlib.sha256(b'z')\n"  # strong: must NOT be flagged
    )
    by_algo = _by_algorithm(analyze_file(src))
    assert set(by_algo) == {"MD5", "SHA-1"}
    assert by_algo["MD5"].severity is Severity.MEDIUM


def test_hashlib_usedforsecurity_false_is_suppressed(tmp_path):
    # An explicit non-security digest (e.g. a cache key) is not a finding.
    src = tmp_path / "m.py"
    src.write_text(
        "import hashlib\n"
        "hashlib.md5(b'cache-key', usedforsecurity=False)\n"
    )
    assert analyze_file(src) == []


def test_pyopenssl_native_pkey_generate_key(tmp_path):
    # pyOpenSSL's instance API: the receiver is a runtime value, but the TYPE_RSA
    # argument resolves to OpenSSL.crypto and carries the algorithm.
    src = tmp_path / "m.py"
    src.write_text(
        "from OpenSSL import crypto\n"
        "from OpenSSL.crypto import TYPE_RSA\n"
        "pkey = crypto.PKey()\n"
        "pkey.generate_key(TYPE_RSA, 2048)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "RSA-2048"
    assert finding.usage == "key_generation"
    assert finding.severity is Severity.CRITICAL
    assert finding.library == "OpenSSL"


def test_pyopenssl_pkey_generate_key_qualified_type(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(
        "from OpenSSL import crypto\n"
        "k = crypto.PKey()\n"
        "k.generate_key(crypto.TYPE_DSA, 1024)\n"
    )
    (finding,) = analyze_file(src)
    assert finding.algorithm == "DSA-1024"


def test_generate_key_without_openssl_type_is_ignored(tmp_path):
    # A generate_key call whose arg is not an OpenSSL TYPE_* constant must not fire
    # (guards the heuristic against false positives on unrelated APIs).
    src = tmp_path / "m.py"
    src.write_text(
        "obj = SomeThing()\n"
        "obj.generate_key(42, 2048)\n"
    )
    assert analyze_file(src) == []


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
