# Engineering Decisions

## D1 — Evidence before verdicts

NightWatch alerts must expose entity, time range and rule-specific evidence. A detector that only returns `suspicious=true` is not sufficient.

## D2 — Suppression is configuration, not deletion

Known-benign suppressions remain auditable through a separate receipt. This makes tuning reversible and reviewable.

## D3 — Regression corpora include both positive and benign cases

A detector change can regress in two directions: missing known signals or adding false positives. CI gates both.

## D4 — Local-first inputs

Parsers operate on supplied local files. NightWatch does not actively probe or collect from networks.

## D5 — Case correlation must be explainable

Grouping alerts into a Case should preserve the evidence relationships that caused the merge.
