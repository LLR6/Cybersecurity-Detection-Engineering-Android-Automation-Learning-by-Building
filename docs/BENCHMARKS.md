# Benchmarks

## Positive regression corpus

Input: `samples/demo.jsonl`  
Truth: `samples/demo.truth.json`

Checks exact `rule_id + entity` matches and reports TP / FP / FN, Precision, Recall and F1.

## Benign regression corpus

Input: `samples/benign.jsonl`  
Truth: `samples/benign.truth.json`

Expected alerts: zero.

This corpus exists to catch false-positive regressions when detector logic changes.

## CI contract

```bash
python scripts/evaluate_sample.py samples/demo.jsonl samples/demo.truth.json --fail-on-regression
python scripts/evaluate_sample.py samples/benign.jsonl samples/benign.truth.json --fail-on-regression
```

These fixtures are regression tests, not production accuracy measurements.
