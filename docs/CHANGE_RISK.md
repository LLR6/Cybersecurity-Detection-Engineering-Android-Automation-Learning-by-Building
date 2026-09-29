# Change Risk Policy

## Low risk
Documentation, synthetic examples, additive runbooks.

## Medium risk
New parser fields, new report fields, new suppression options.

## High risk
Detector threshold changes, rule semantics, case-correlation behavior, suppression matching, ATT&CK mapping, input parsing that changes event meaning.

High-risk changes require:
- positive regression fixtures;
- benign regression fixtures;
- benchmark delta review;
- tuning documentation update;
- CHANGELOG entry.

A change that lowers false positives by silently suppressing evidence is not acceptable.
