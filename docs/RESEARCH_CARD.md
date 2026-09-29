# NightWatch Research Card

## Question

Can a small, evidence-first local detector make alert review more transparent by preserving *why* a rule fired, *why* alerts were grouped, and *why* known-benign signals were suppressed?

## Hypotheses

1. Explicit rule evidence reduces ambiguity compared with boolean alert output.
2. Correlation edges make Case grouping easier to audit.
3. Versioned suppression receipts reduce tuning opacity.
4. Positive and benign regression corpora catch different classes of detector regression.

## Method

- Normalize local JSONL / Suricata / Zeek-style telemetry.
- Apply small explainable heuristic detectors.
- Preserve rule-specific evidence.
- Group alerts into Cases with explicit time/entity relationships.
- Evaluate fixed positive and benign corpora in CI.
- Keep suppression decisions in an auditable side artifact.

## Current metrics

- TP / FP / FN
- Precision
- Recall
- F1
- Case count
- Suppressed alert count

## Current evidence

The repository currently demonstrates that:

- fixed labeled positive fixtures can be detected;
- a benign corpus can remain at zero expected alerts;
- suppressions are recorded rather than silently discarded;
- Case reports and regression artifacts are reproducible in CI.

This does **not** establish production detection accuracy.

## Threats to validity

- synthetic and small fixtures;
- environment-specific benign behavior;
- heuristic thresholds;
- incomplete parser coverage;
- limited diversity of labeled sequences.

## Next experiment

Create several benign workload families with periodic update/check-in behavior, then measure how rule thresholds and suppression patterns behave across those environments.
