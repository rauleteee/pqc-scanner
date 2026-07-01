"""Tests for the dependency manifest complement (phase 6)."""

from __future__ import annotations

from pqc_scanner import scan
from pqc_scanner.detectors.dependencies import _normalize, analyze_manifest
from pqc_scanner.detectors.discovery import iter_manifest_files
from pqc_scanner.findings import Classification, Severity


def _by_library(findings):
    return {f.library: f for f in findings}


# --- normalization --------------------------------------------------------


def test_normalize_follows_pep503():
    assert _normalize("pyOpenSSL") == "pyopenssl"
    assert _normalize("PyNaCl") == "pynacl"
    assert _normalize("liboqs_python") == "liboqs-python"
    assert _normalize("Foo.Bar_baz") == "foo-bar-baz"


# --- requirements.txt -----------------------------------------------------


def test_requirements_detects_crypto_and_pins_version(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "# comment line\n"
        "cryptography==41.0.7\n"
        "pyOpenSSL>=23.0  # inline comment\n"
        "requests==2.31.0\n"
        "paramiko\n"
    )
    findings = analyze_manifest(manifest)
    libs = _by_library(findings)

    assert set(libs) == {"cryptography", "pyopenssl", "paramiko"}  # requests ignored
    assert libs["cryptography"].version == "41.0.7"
    assert libs["cryptography"].line == 2
    assert libs["pyopenssl"].version is None  # not exactly pinned
    assert libs["paramiko"].version is None
    for finding in findings:
        assert finding.origin == "dependency"
        assert finding.severity is Severity.CRITICAL
        assert finding.classification is Classification.SHOR


def test_requirements_handles_extras_markers_and_options(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "-r base.txt\n"
        "-e ./local\n"
        "cryptography[ssh]==42.0.0 ; python_version >= '3.9'\n"
        "rsa @ https://example.com/rsa-4.9.whl\n"
    )
    libs = _by_library(analyze_manifest(manifest))
    assert libs["cryptography"].version == "42.0.0"  # extras + marker stripped
    assert "rsa" in libs and libs["rsa"].version is None  # URL requirement, no version


def test_requirements_detects_jose_jwt_ecosystem(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "Authlib==1.3.0\n"
        "python-jose==3.3.0\n"
        "PyJWT==2.8.0\n"
        "jwcrypto==1.5.0\n"
    )
    libs = _by_library(analyze_manifest(manifest))
    assert set(libs) == {"authlib", "python-jose", "pyjwt", "jwcrypto"}
    assert all(f.classification is Classification.SHOR for f in libs.values())
    assert libs["pyjwt"].version == "2.8.0"


def test_requirements_reports_pqc_library_as_info(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("oqs==0.10.0\n")
    (finding,) = analyze_manifest(manifest)
    assert finding.classification is Classification.PQC
    assert finding.severity is Severity.INFO


def test_duplicate_package_reported_once(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("cryptography==1.0\ncryptography==2.0\n")
    findings = analyze_manifest(manifest)
    assert len(findings) == 1


# --- pyproject.toml -------------------------------------------------------


def test_pyproject_pep621_and_optional_dependencies(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[project]\n"
        'name = "app"\n'
        'dependencies = ["cryptography==41.0.7", "requests>=2"]\n'
        "\n"
        "[project.optional-dependencies]\n"
        'ssh = ["paramiko==3.4.0"]\n'
    )
    libs = _by_library(analyze_manifest(manifest))
    assert set(libs) == {"cryptography", "paramiko"}
    assert libs["cryptography"].version == "41.0.7"
    assert libs["paramiko"].version == "3.4.0"
    # Line is located best-effort by name.
    assert manifest.read_text().splitlines()[libs["cryptography"].line - 1].strip().startswith(
        "dependencies"
    )


def test_pyproject_poetry_table_skips_python(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'cryptography = "41.0.7"\n'
        'ecdsa = { version = "0.18.0", optional = true }\n'
    )
    libs = _by_library(analyze_manifest(manifest))
    assert set(libs) == {"cryptography", "ecdsa"}  # no "python"
    assert libs["cryptography"].version == "41.0.7"
    assert libs["ecdsa"].version == "0.18.0"


def test_pyproject_malformed_yields_nothing(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("this is = not valid toml [[[\n")
    assert analyze_manifest(manifest) == []


# --- poetry.lock ----------------------------------------------------------


def test_poetry_lock_parses_packages(tmp_path):
    manifest = tmp_path / "poetry.lock"
    manifest.write_text(
        '[[package]]\nname = "cryptography"\nversion = "41.0.7"\n\n'
        '[[package]]\nname = "click"\nversion = "8.1.7"\n\n'
        '[[package]]\nname = "pynacl"\nversion = "1.5.0"\n'
    )
    libs = _by_library(analyze_manifest(manifest))
    assert set(libs) == {"cryptography", "pynacl"}
    assert libs["cryptography"].version == "41.0.7"


# --- Pipfile.lock ---------------------------------------------------------


def test_pipfile_lock_parses_default_and_develop(tmp_path):
    manifest = tmp_path / "Pipfile.lock"
    manifest.write_text(
        '{"default": {"cryptography": {"version": "==41.0.7"}, '
        '"flask": {"version": "==3.0.0"}}, '
        '"develop": {"ecdsa": {"version": "==0.18.0"}}}'
    )
    libs = _by_library(analyze_manifest(manifest))
    assert set(libs) == {"cryptography", "ecdsa"}
    assert libs["cryptography"].version == "41.0.7"
    assert libs["ecdsa"].version == "0.18.0"


def test_pipfile_lock_malformed_yields_nothing(tmp_path):
    manifest = tmp_path / "Pipfile.lock"
    manifest.write_text("{not json")
    assert analyze_manifest(manifest) == []


# --- discovery + integration ---------------------------------------------


def test_unknown_manifest_name_is_ignored(tmp_path):
    other = tmp_path / "setup.cfg"
    other.write_text("[metadata]\nname = app\n")
    assert analyze_manifest(other) == []


def test_iter_manifest_files_finds_known_names(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography\n")
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    (tmp_path / "README.md").write_text("# nope\n")
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "Pipfile.lock").write_text("{}")
    # Pruned directory must be skipped.
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "requirements.txt").write_text("cryptography\n")

    found = {p.name for p in iter_manifest_files(tmp_path)}
    assert found == {"requirements.txt", "pyproject.toml", "Pipfile.lock"}


def test_scan_merges_code_and_dependency_findings(tmp_path):
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    (tmp_path / "requirements.txt").write_text("cryptography==41.0.7\n")

    findings = scan(tmp_path)
    origins = {f.origin for f in findings}
    assert origins == {"code", "dependency"}
    dep = next(f for f in findings if f.origin == "dependency")
    assert dep.library == "cryptography" and dep.version == "41.0.7"
