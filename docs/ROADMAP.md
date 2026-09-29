# Roadmap

## Current foundation

- Auth failure → success sequence detection
- Port fan-out / scan detection
- Periodic outbound connection detection
- DNS anomaly detection
- JSONL / Zeek / Suricata ingestion
- Case correlation
- Explainable suppression audit
- Labeled positive regression corpus
- Benign zero-alert regression corpus

## Next

### Rule quality
- per-rule labeled fixtures;
- threshold sensitivity reports;
- richer negative examples;
- missing-field degradation tests.

### Case quality
- case split / merge evaluation;
- entity-role awareness;
- configurable correlation policies;
- case-level suppression.

### Telemetry
- additional Zeek fields;
- selected endpoint-event schema;
- TLS / process context when supplied locally.

## Later

- rule-pack versioning;
- ATT&CK coverage report;
- replay benchmark across multiple synthetic environments.

## Non-goals

- autonomous incident verdicts;
- reputation lookups that silently leave the local environment;
- claiming production accuracy from synthetic samples.
