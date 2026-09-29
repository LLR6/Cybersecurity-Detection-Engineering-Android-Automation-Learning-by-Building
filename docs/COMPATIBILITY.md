# Compatibility

## Runtime

- Python: **3.11+**
- CI: Python **3.12**
- CLI: `nightwatch`

## Input formats

Current supported inputs:

- NightWatch JSONL
- Suricata EVE JSON
- Zeek connection logs

Missing or malformed fields may reduce detector coverage; they are not silently interpreted as evidence.

## Versioned artifacts

- suppression audit output
- evaluation truth: `nightwatch-eval/v1`
- evaluation report: `nightwatch-evaluation-report/v1`

## Policy

New fields may be added to reports in minor releases. Existing field meaning should not change silently.
