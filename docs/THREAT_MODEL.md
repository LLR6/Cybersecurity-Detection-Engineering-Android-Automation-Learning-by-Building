# Threat Model

NightWatch is a local-first defensive detector. Its primary job is to transform supplied telemetry into explainable alerts and cases. It is **not** a containment or prevention system.

## Assets

The project should protect:

- local telemetry supplied by the analyst;
- local suppression configuration;
- generated reports and case evidence;
- the integrity of rule-to-evidence attribution;
- the analyst's workstation from unintended file access or command execution.

## Trust boundaries

```text
external telemetry file
        │ untrusted
        ▼
 parser / normalizer
        │ structured local events
        ▼
 detection rules
        │ alerts + evidence
        ▼
 case correlation
        │
        ├── suppression config (operator-controlled)
        └── reports / benchmark artifacts
```

Telemetry content is untrusted. A file being local does not make its fields trustworthy.

## Threats considered

### Malformed telemetry

Inputs may contain:

- invalid JSON;
- missing fields;
- oversized strings;
- unexpected timestamps;
- duplicated events;
- adversarial field values intended to confuse formatting.

Expected behavior: reject malformed records with source location where possible, or safely normalize supported fields.

### Evidence confusion

A detector can be technically correct while attaching the wrong entity or source evidence.

Mitigations:

- alerts retain explicit rule IDs and entities;
- cases preserve source references;
- correlation edges record shared entities and time deltas;
- labeled regression fixtures gate known behavior.

### Silent suppression

A broad suppression could hide legitimate alerts.

Mitigations:

- suppressions require explicit rule/entity patterns;
- suppression reason is preserved;
- suppressed alerts can be emitted to an audit JSON;
- narrow matching is recommended in tuning guidance.

### Report injection

Telemetry text may contain Markdown-like or terminal-like content.

Reports should treat source content as evidence text, not executable instructions. NightWatch does not execute commands contained in telemetry.

## Threats not solved

NightWatch does not guarantee:

- detection of every malicious activity;
- absence of false positives;
- trusted ground truth from upstream logs;
- tamper-proof storage;
- endpoint isolation;
- autonomous response.

## Security invariants

A change should be treated as suspicious if it causes any of these to become false:

1. telemetry parsing never executes input;
2. reports do not intentionally expose unrelated local files;
3. suppression remains auditable;
4. alert/case evidence remains traceable to source input;
5. regression corpora remain reproducible;
6. detector output is not presented as an incident verdict.

## Review checklist

For parser/rule changes:

- What new input is trusted?
- Can one record affect unrelated records?
- Can source content escape its evidence context?
- Does the change alter rule/entity identity?
- Does the benign corpus remain quiet?
- Does the labeled corpus preserve expected alerts?
