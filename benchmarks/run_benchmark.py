"""Reproducible validation battery against real open-source Python projects.

Runs the scanner over a corpus of well-known repositories and writes a
human-reviewable Markdown report. For every code finding the report includes the
**actual source line**, so results can be cross-checked against the real code
without trusting the tool — the point is to audit precision (no false positives)
and detail quality (right curve / key size), not just count hits.

Usage:
    python benchmarks/run_benchmark.py            # clone corpus if missing, scan, report
    python benchmarks/run_benchmark.py --corpus /path/to/existing/clones
    python benchmarks/run_benchmark.py --no-clone # scan only what's already present

Outputs (git-ignored):
    benchmarks/corpus/<repo>/     shallow clones
    benchmarks/results/REPORT.md  the reviewable report
    benchmarks/results/<repo>.json  each repo's CycloneDX CBOM
"""

from __future__ import annotations

import argparse
import json
import linecache
import subprocess
import time
from collections import Counter
from pathlib import Path

from pqc_scanner import Finding, Severity, scan, to_cbom
from pqc_scanner.detectors.discovery import iter_python_files

# Corpus chosen for a recall + precision spread. Three groups:
#   1) Original core: projects that really generate keys (paramiko, certbot, PyJWT),
#      a crypto-heavy stress case (pyca/cryptography), and a control that should stay
#      near-empty (requests: no direct key generation).
#   2) Second wave (JOSE/JWK + assorted): authlib, python-ecdsa, PyNaCl, pyOpenSSL,
#      pycryptodome, liboqs-python, mitmproxy, django, httpx, josepy.
#   3) Third wave (this session): 20 more real libraries, deliberately biased toward
#      crypto libs NOT yet in the rule catalog (rsa, M2Crypto, PGPy, jwcrypto,
#      eth-account, coincurve, python-jose, pyjks) to hunt false negatives, plus big
#      real-world users of covered libs (ansible, salt, scapy, twisted, impacket,
#      borg, trustme, oauthlib, werkzeug, fabric, sshtunnel, aws-encryption-sdk).
REPOS: dict[str, str] = {
    # --- wave 1 ---
    "paramiko": "https://github.com/paramiko/paramiko.git",
    "certbot": "https://github.com/certbot/certbot.git",
    "pyjwt": "https://github.com/jpadilla/pyjwt.git",
    "cryptography": "https://github.com/pyca/cryptography.git",
    "requests": "https://github.com/psf/requests.git",
    # --- wave 2 ---
    "liboqs-python": "https://github.com/open-quantum-safe/liboqs-python.git",
    "pycryptodome": "https://github.com/Legrandin/pycryptodome.git",
    "pynacl": "https://github.com/pyca/pynacl.git",
    "python-ecdsa": "https://github.com/tlsfuzzer/python-ecdsa.git",
    "pyopenssl": "https://github.com/pyca/pyopenssl.git",
    "authlib": "https://github.com/lepture/authlib.git",
    "mitmproxy": "https://github.com/mitmproxy/mitmproxy.git",
    "django": "https://github.com/django/django.git",
    "httpx": "https://github.com/encode/httpx.git",
    "josepy": "https://github.com/certbot/josepy.git",
    # --- wave 3 (this session): FN-hunt crypto libs not yet in the catalog ---
    "rsa": "https://github.com/sybrenstuvel/python-rsa.git",
    "m2crypto": "https://gitlab.com/m2crypto/m2crypto.git",
    "pgpy": "https://github.com/SecurityInnovation/PGPy.git",
    "jwcrypto": "https://github.com/latchset/jwcrypto.git",
    "eth-account": "https://github.com/ethereum/eth-account.git",
    "coincurve": "https://github.com/ofek/coincurve.git",
    "python-jose": "https://github.com/mpdavis/python-jose.git",
    "pyjks": "https://github.com/kurtbrose/pyjks.git",
    # --- wave 3: real-world users of covered libs (precision + recall) ---
    "ansible": "https://github.com/ansible/ansible.git",
    "salt": "https://github.com/saltstack/salt.git",
    "scapy": "https://github.com/secdev/scapy.git",
    "twisted": "https://github.com/twisted/twisted.git",
    "impacket": "https://github.com/fortra/impacket.git",
    "borg": "https://github.com/borgbackup/borg.git",
    "trustme": "https://github.com/python-trio/trustme.git",
    "oauthlib": "https://github.com/oauthlib/oauthlib.git",
    "werkzeug": "https://github.com/pallets/werkzeug.git",
    "fabric": "https://github.com/fabric/fabric.git",
    "sshtunnel": "https://github.com/pahaz/sshtunnel.git",
    "aws-encryption-sdk": "https://github.com/aws/aws-encryption-sdk-python.git",
    # --- wave 4 (this session): probe UNCOVERED patterns, not more of the same ---
    #   String-dispatcher key generation (algorithm carried in a string arg, so
    #   resolvable without taint — same shape as the pyOpenSSL TYPE_* heuristic):
    "asyncssh": "https://github.com/ronf/asyncssh.git",  # generate_private_key("ssh-rsa")
    "oscrypto": "https://github.com/wbond/oscrypto.git",  # asymmetric.generate_pair("rsa", ...)
    #   libsodium wrappers with their own roots (not PyNaCl's ``nacl``):
    "libnacl": "https://github.com/saltstack/libnacl.git",  # crypto_box_keypair()
    "pysodium": "https://github.com/stef/pysodium.git",  # crypto_sign_keypair()
    #   Other asymmetric key generators outside the catalog:
    "fastecdsa": "https://github.com/AntonKueltz/fastecdsa.git",  # keys.gen_private_key(curve)
    "eth-keys": "https://github.com/ethereum/eth-keys.git",  # secp256k1 PrivateKey
    "web3": "https://github.com/ethereum/web3.py.git",  # secp256k1 via eth-keys
}

HERE = Path(__file__).resolve().parent
_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.MEDIUM: 1, Severity.INFO: 2}


def ensure_clone(name: str, url: str, corpus: Path, allow_clone: bool) -> Path | None:
    """Return the local path to a repo, shallow-cloning it if missing."""
    dest = corpus / name
    if dest.exists():
        return dest
    if not allow_clone:
        return None
    corpus.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {name} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", "-q", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  FAILED to clone {name}: {result.stderr.strip()[:120]}")
        return None
    return dest


def _source_line(path: str, line: int) -> str:
    return linecache.getline(path, line).strip()


def _rel(path: str, repo_root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return path


def render_repo(name: str, findings: list[Finding], repo_root: Path) -> tuple[str, Counter]:
    """Render one repo's findings as a markdown section + severity counter."""
    counts = Counter(f.severity for f in findings)
    n_code = sum(1 for f in findings if f.origin == "code")
    n_dep = sum(1 for f in findings if f.origin == "dependency")

    lines = [
        f"## {name}",
        "",
        f"`{n_code}` code findings · `{n_dep}` dependency findings · "
        f"CRITICAL {counts.get(Severity.CRITICAL, 0)}, "
        f"MEDIUM {counts.get(Severity.MEDIUM, 0)}, "
        f"INFO {counts.get(Severity.INFO, 0)}",
        "",
        "| Severity | Algorithm | Origin | Location | Source line / package |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.path, f.line)):
        if f.origin == "code":
            loc = f"{_rel(f.path, repo_root)}:{f.line}"
            evidence = f"`{_source_line(f.path, f.line)[:70]}`"
        else:
            loc = f"{_rel(f.path, repo_root)}:{f.line}"
            evidence = f"{f.library} {f.version or '(unpinned)'}"
        lines.append(
            f"| {f.severity.value} | {f.algorithm} | {f.origin} | {loc} | {evidence} |"
        )
    lines.append("")
    return "\n".join(lines), counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(HERE / "corpus"), help="dir holding the clones")
    parser.add_argument("--out", default=str(HERE / "results"), help="dir for the report")
    parser.add_argument("--no-clone", action="store_true", help="don't clone missing repos")
    args = parser.parse_args()

    corpus = Path(args.corpus)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    header = [
        "# PQC Scanner — validation battery",
        "",
        "Generated by `benchmarks/run_benchmark.py`. Each code finding shows the real",
        "source line so you can verify it is a genuine crypto call (precision) and that",
        "the detail (curve / key size) is right. Scans include test files on purpose —",
        "that is where key generation often lives.",
        "",
    ]
    sections: list[str] = []
    totals: Counter = Counter()
    tot_files = tot_code = tot_dep = 0
    tot_time = 0.0
    summary_rows = ["| Repo | Files | Code | Dep | CRITICAL | MEDIUM | INFO | time |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- |"]

    for name, url in REPOS.items():
        print(f"[{name}]")
        repo_root = ensure_clone(name, url, corpus, allow_clone=not args.no_clone)
        if repo_root is None:
            print(f"  skipped (not present and cloning disabled)")
            summary_rows.append(f"| {name} | — | — | — | — | — | — | skipped |")
            continue
        start = time.perf_counter()
        findings = scan(repo_root)
        elapsed = time.perf_counter() - start
        section, counts = render_repo(name, findings, repo_root)
        n_files = sum(1 for _ in iter_python_files(repo_root))
        # Persist each repo's CBOM next to the report (reuse the scan above).
        (out / f"{name}.json").write_text(json.dumps(to_cbom(findings), indent=2))
        totals.update(counts)
        n_code = sum(1 for f in findings if f.origin == "code")
        n_dep = sum(1 for f in findings if f.origin == "dependency")
        tot_files += n_files
        tot_code += n_code
        tot_dep += n_dep
        tot_time += elapsed
        summary_rows.append(
            f"| {name} | {n_files} | {n_code} | {n_dep} | "
            f"{counts.get(Severity.CRITICAL, 0)} | {counts.get(Severity.MEDIUM, 0)} | "
            f"{counts.get(Severity.INFO, 0)} | {elapsed:.2f}s |"
        )
        sections.append(section)

    summary_rows.append(
        f"| **TOTAL** | **{tot_files}** | **{tot_code}** | **{tot_dep}** | "
        f"**{totals.get(Severity.CRITICAL, 0)}** | **{totals.get(Severity.MEDIUM, 0)}** | "
        f"**{totals.get(Severity.INFO, 0)}** | **{tot_time:.2f}s** |"
    )
    report = "\n".join(header + ["## Summary", ""] + summary_rows + [""] + sections)
    report_path = out / "REPORT.md"
    report_path.write_text(report)
    print(f"\nReport written to {report_path}")
    print(f"Totals: {dict(totals)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
