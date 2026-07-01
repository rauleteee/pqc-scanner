# Benchmarks

Reproducible validation battery for the scanner against real open-source Python
projects. It exists to check the two things that matter most for this tool:
**low false positives** and **actionable, correct findings**.

## Run it

```bash
pip install -e ".[dev]"          # scanner must be importable
python benchmarks/run_benchmark.py
```

This shallow-clones the corpus into `benchmarks/corpus/`, scans each repo, and
writes:

- `benchmarks/results/REPORT.md` — the reviewable report. Every code finding shows
  the **real source line**, so you can verify it is a genuine crypto call and that
  the detail (curve / key size) is right — without trusting the tool.
- `benchmarks/results/<repo>.json` — each repo's CycloneDX CBOM.

Both output folders are git-ignored (clones are large, results are regenerated).

## Options

```bash
python benchmarks/run_benchmark.py --corpus /path/to/existing/clones --no-clone
```

## How to read the report

- **`requests` should stay near-empty** — it depends on crypto transitively but does
  not generate keys. Findings there would signal false positives.
- Scans **include test files on purpose**: that is where key generation frequently
  lives in these projects.
- Cross-check a few rows: open the file at `location`, confirm the source line is a
  real vulnerable call, and that the reported algorithm/curve/size matches.
