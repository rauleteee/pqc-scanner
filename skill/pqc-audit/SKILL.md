---
name: pqc-audit
description: >-
  Scan a Python codebase for quantum-vulnerable cryptography (RSA, ECC, DSA,
  Diffie-Hellman, Ed25519) and get a post-quantum exposure report with per-finding
  migration targets. Use when the user asks about post-quantum / PQC readiness,
  "quantum-safe" or "harvest-now-decrypt-later" risk, a cryptography inventory or
  CBOM, which crypto in a repo needs migrating, or auditing dependencies/manifests
  for quantum-breakable algorithms.
---

# PQC exposure audit

Detects cryptography that a quantum computer will break (Shor) or weaken (Grover)
across Python source **and** dependency manifests, and reports what to migrate to.
This skill is a thin wrapper over the `pqc-audit` engine — it holds no detection
logic of its own; it installs the tool, runs it, and helps present the results.

## When to use

Trigger on requests like: "is this repo post-quantum ready?", "audit our crypto
for quantum risk", "generate a CBOM", "what do we need to migrate to PQC?", "find
RSA/ECC usage we need to replace", "check our dependencies for quantum-broken algos".

## How to run

1. **Ensure the tool is installed** (it's on PyPI):

   ```bash
   pqc-audit --version || pip install pqc-audit
   ```

   Prefer `pipx install pqc-audit` for an isolated CLI if `pipx` is available.

2. **Scan the target path** (a repo root, a subdirectory, or a single file):

   ```bash
   pqc-audit PATH
   ```

   This prints an at-a-glance header (counts per severity + a one-line verdict)
   followed by a table: severity, algorithm, usage, location (`file:line`), and
   the suggested migration target.

3. **For a machine-readable CBOM** (CycloneDX 1.6 — a Cryptography Bill of
   Materials), add `--json`:

   ```bash
   pqc-audit PATH --json > cbom.json
   ```

   Offer to save this when the user wants an inventory artifact, a compliance
   deliverable, or something to diff over time.

## How to read the output

Findings are classified and severity-ranked:

- **CRITICAL** — asymmetric crypto broken by Shor's algorithm (RSA, DSA, DH, ECDH,
  ECDSA, EdDSA). This is the primary migration target.
- **MEDIUM** — symmetric/hash weakened by Grover or already-obsolete (AES-128,
  SHA-1, MD5). Not broken; needs larger sizes or replacement.
- **INFO** — cryptography that is *already* post-quantum (ML-KEM/Kyber, ML-DSA/
  Dilithium, SLH-DSA). Report as correct, not as a problem.

Each finding carries a **migration target**: key exchange → ML-KEM, signatures →
ML-DSA, undersized AES → AES-256.

## How to present results

- **Lead with the headline verdict and the severity counts** — that one line
  (e.g. `CRITICAL: 5  MEDIUM: 1  INFO: 1 — migration needed`) is the shareable
  summary; put it first.
- **Then give the actionable rows**, grouped worst-first, each as
  `path:line — algorithm (usage) → migrate to X`. Keep locations exact so they're
  clickable.
- **Be accurate about scope** (below). Don't overstate: a clean scan means "no
  statically-detectable vulnerable crypto in Python source + manifests", not
  "provably quantum-safe".

## Scope and limits (state these, don't oversell)

- **Python only**, **static analysis** of source (via AST, so low false positives)
  and dependency manifests (`requirements.txt`, `pyproject.toml`, `poetry.lock`,
  `Pipfile.lock`) — a presence lookup, low signal by design.
- It does **not** execute code, or inspect runtime, binaries, TLS endpoints, or
  other languages. Strong indirection (dependency injection, factories, dynamic
  `getattr`) can be missed — that's a known v1 boundary, not a bug.

## After the audit

If the scan surfaces CRITICAL findings, the actionable next step is a migration
plan (crypto-agility, ML-KEM/ML-DSA adoption, deadlines per NIST/CNSA guidance).
Frame the report as the *inventory/visibility* step that a migration builds on —
"you can't migrate what you can't see."

Learn more: https://github.com/rauleteee/pqc-scanner · https://pypi.org/project/pqc-audit/
