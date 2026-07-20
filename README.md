# PQC Scanner

Open-source CLI that scans a local repository for cryptography vulnerable to
quantum computing (RSA, ECC, ...) and produces an exposure report with concrete
post-quantum migration targets.

> You can't migrate what you can't see. PQC Scanner is the inventory/visibility
> step of a post-quantum migration: it finds where quantum-vulnerable
> cryptography lives in your code and dependencies, and tells you what to move it to.

> **Status:** v1, Python only. AST detection engine, dependency-manifest
> complement, rule base, CycloneDX CBOM output and CLI are in place.

## What it detects

Two static detectors feed one report:

- **Source code (AST) — high signal.** Parses Python with the standard `ast`
  module and reports *real uses* of vulnerable primitives (a crypto import **plus**
  a matching call), so comments or variable names never trigger a finding.
  Extracts detail: RSA/DSA/DH key size, EC curve (normalized across libraries —
  `SECP256R1`/`P-256`/`prime256v1` → `P-256`), AES key length, PQC scheme.
- **Dependency manifests — complement.** Parses `requirements.txt`,
  `pyproject.toml` (PEP 621 + Poetry), `poetry.lock` and `Pipfile.lock` and flags
  declared cryptographic libraries with their version. Low signal on its own (it
  says a library is present, not that a primitive is used), but it seeds the CBOM.

Each finding carries: location, algorithm, usage context, quantum classification
(Shor / Grover / already-PQC), severity, origin (code location | package+version)
and a **suggested PQC migration target** (key exchange → ML-KEM, signatures → ML-DSA).

## Installation

With [pipx](https://pipx.pypa.io) for an isolated CLI:

```bash
pipx install pqc-audit
```

Or from a local clone:

```bash
git clone https://github.com/rauleteee/pqc-scanner
cd pqc-scanner
pipx install .                  # isolated, adds the `pqc-audit` command
```

Or for development:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
pqc-audit [PATH]              # colored terminal summary (default PATH: .)
pqc-audit [PATH] --json       # CycloneDX 1.6 CBOM to stdout
pqc-audit [PATH] --markdown   # shareable Markdown report to stdout
pqc-audit [PATH] --html       # self-contained HTML report to stdout
python -m pqc_scanner [PATH]  # equivalent, without installing
```

Running it against the bundled `examples/` (Python source + a `requirements.txt`):

```text
pqc-audit 0.1.0  ·  scanned examples
CRITICAL: 5  MEDIUM: 1  INFO: 1
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Algorithm          ┃ Usage          ┃ Location              ┃ Migrate to             ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ RSA/ECC/DH/Ed25519 │ dependency     │ examples/requirements │ ML-KEM / ML-DSA        │
│ CRITICAL │ RSA/ECC (OpenSSL)  │ dependency     │ examples/requirements │ ML-KEM / ML-DSA        │
│ CRITICAL │ RSA/ECDSA (SSH)    │ dependency     │ examples/requirements │ ML-KEM / ML-DSA        │
│ CRITICAL │ RSA-2048           │ key_generation │ examples/vulnerable_… │ ML-KEM / ML-DSA        │
│ CRITICAL │ ECC-P-256          │ key_generation │ examples/vulnerable_… │ ML-KEM (ECDH) / ML-DSA │
│ MEDIUM   │ AES                │ encryption     │ examples/vulnerable_… │ AES-256                │
│ INFO     │ ML-KEM/ML-DSA      │ dependency     │ examples/requirements │ already post-quantum   │
└──────────┴────────────────────┴────────────────┴───────────────────────┴────────────────────────┘
Verdict: quantum-critical cryptography in use — migration needed.
```

The header count (`CRITICAL: 5  MEDIUM: 1  INFO: 1`) is the at-a-glance verdict.

### JSON / CBOM output

`--json` emits a **CycloneDX 1.6 CBOM** (Cryptography Bill of Materials),
validated against the official schema. Code findings become `cryptographic-asset`
components; dependency findings become `library` components (with `purl` and
version). The scanner's assessment (severity, quantum classification, migration
target) rides along as namespaced `properties`.

```bash
pqc-audit path/to/repo --json > cbom.json
```

### Shareable report (Markdown / HTML)

`--markdown` and `--html` render the same scan as a human-facing report — the
verdict headline followed by the actionable table (location + migration target).
The HTML is a single self-contained page (no external assets), light/dark aware,
ready to open in a browser or attach to a report.

```bash
pqc-audit path/to/repo --markdown > pqc-report.md
pqc-audit path/to/repo --html > pqc-report.html
```

## MCP server (for AI agents)

The same engine is exposed over the [Model Context Protocol](https://modelcontextprotocol.io),
so any MCP-capable agent (Claude, Cursor, …) can scan a local repo conversationally.

```bash
pip install ".[mcp]"     # installs the optional MCP SDK
pqc-audit-mcp            # runs the server over stdio
```

Register it with Claude Code:

```bash
claude mcp add pqc-audit -- pqc-audit-mcp
```

Or add it to a client config (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pqc-audit": { "command": "pqc-audit-mcp" }
  }
}
```

It exposes two tools:

- **`scan_repository(path)`** — an at-a-glance verdict, severity counts, and the
  findings, each with its location and suggested post-quantum migration target.
- **`generate_cbom(path)`** — the full CycloneDX 1.6 CBOM.

## Skill (for Claude Code)

A [Claude Skill](https://docs.claude.com/en/docs/claude-code/skills) wraps the same
engine so an agent audits a repo the moment you *ask* — "is this repo post-quantum
ready?" — without you remembering the command. It lives in [`skill/pqc-audit/`](skill/pqc-audit).

Install it for your user:

```bash
mkdir -p ~/.claude/skills
cp -r skill/pqc-audit ~/.claude/skills/
```

The skill installs `pqc-audit` on demand, runs it, and presents the verdict plus
actionable migration targets. Like the CLI and MCP server, it holds no detection
logic — it's a third thin surface over the one engine.

## Architecture

The engine is a **library**; the interfaces are **thin wrappers**. All detection
logic lives in the `pqc_scanner` core, exposed through a small public API:

```python
from pqc_scanner import scan, to_cbom
findings = scan(path)          # list[Finding]  (code + dependency findings)
cbom = to_cbom(findings)       # CycloneDX 1.6 CBOM dict
```

The CLI and the MCP server are just thin faces of the same engine (a skill is next).

## Tests

```bash
pytest
```

## v1 scope

- **Python** ecosystem only.
- **Static** analysis of local files: source code (AST) + dependency manifests.
- Outputs: colored terminal summary + JSON aligned with CycloneDX CBOM.

**Known limit (by design):** the AST engine detects direct, statically-resolvable
use; strong indirection (dependency injection, factories, dynamic `getattr`) is
out of scope until a future data-flow/taint layer. The dependency complement is a
presence lookup, not proof a primitive is used.

See [`CLAUDE.md`](CLAUDE.md) for the full design and build plan.

## License

MIT — see [`LICENSE`](LICENSE).
