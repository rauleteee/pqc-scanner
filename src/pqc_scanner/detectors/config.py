"""Configuration/infrastructure detection engine.

Input adapter (a sibling of the AST engine and the dependency lookup) for crypto
that lives as *strings* outside Python code: SSH keys and configs, PEM key
material, and key-generation commands in Dockerfiles / CI / shell. It only walks
lines and applies the anchored patterns owned by `knowledge/config.py`; it holds
no crypto knowledge of its own.

Precision comes from the rule base: every pattern is anchored on structure that
only a genuine cryptographic declaration has (a PEM header, an SSH wire-format
``AAAA`` blob, a key-gen command with its algorithm selector), so a stray mention
of "RSA" in a comment is never a finding.
"""

from __future__ import annotations

from pathlib import Path

from pqc_scanner.findings import Finding, Origin
from pqc_scanner.knowledge import CONFIG_RULES, RSA_KEY_SIZES


def analyze_config(path: str | Path) -> list[Finding]:
    """Analyze one config/infra file and return its findings.

    Unreadable files yield no findings rather than aborting a whole-repo scan.
    """
    path = Path(path)
    try:
        # Config files are text; decode leniently so a stray binary byte or an
        # unusual encoding never derails the scan.
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in CONFIG_RULES:
            match = rule.regex.search(line)
            if match is None:
                continue
            algorithm = rule.algorithm
            key_size = _matched_size(match)
            if key_size is not None:
                algorithm = f"{algorithm}-{key_size}"
            findings.append(
                Finding(
                    path=str(path),
                    line=lineno,
                    column=match.start(),
                    algorithm=algorithm,
                    usage=rule.usage,
                    classification=rule.classification,
                    severity=rule.severity,
                    origin=Origin.CONFIG,
                    library=rule.library,
                    migration_target=rule.migration_target,
                    symbol=rule.symbol,
                    key_size=key_size,
                )
            )
    # Deterministic order (a line can match several rules; stable within a line).
    findings.sort(key=lambda f: (f.line, f.column, f.symbol))
    return findings


def _matched_size(match) -> int | None:
    """Return a trusted RSA key size from the rule's ``size`` group, else ``None``.

    A number outside the set of plausible RSA sizes (e.g. a byte count or an
    unrelated digit run captured loosely) is dropped rather than annotated, so the
    algorithm label never carries an invented size.
    """
    if "size" not in match.re.groupindex:
        return None
    raw = match.group("size")
    if raw is None:
        return None
    value = int(raw)
    return value if value in RSA_KEY_SIZES else None
