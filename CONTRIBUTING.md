# Contributing to NightWatch

NightWatch welcomes small, reviewable improvements to detection logic, parsers, evaluation, documentation, and tests.

## Before opening a change

1. Keep the change defensive and local-first.
2. Add or update a reproducible fixture.
3. Add tests for the intended behavior and at least one relevant benign case.
4. If detector output changes, update the labeled regression corpus intentionally.
5. Explain expected false-positive and false-negative trade-offs.

## Local checks

```bash
python -m pip install -e ".[dev]"
pytest -q
python scripts/evaluate_sample.py samples/demo.jsonl samples/demo.truth.json --fail-on-regression
python scripts/evaluate_sample.py samples/benign.jsonl samples/benign.truth.json --fail-on-regression
```

## New detector checklist

A detector should expose the triggering entity, time range, evidence, rule ID, and why the signal fired. Avoid rules that only emit a boolean without auditable evidence.

Do not submit real secrets or private production telemetry.
