# Changelog

## 0.4.0 - 2026-09-29

### Added
- Labeled detector regression evaluation with TP / FP / FN, Precision, Recall and F1.
- Benign regression corpus that fails CI on false-positive regressions.
- Case-report CLI support and configurable case-gap.
- Auditable rule/entity suppressions with suppression receipts.
- Detection tuning notes and suppression hygiene guidance.

### Changed
- CI now publishes detection and evaluation artifacts.
- README documents regression gates and evidence-first tuning.

### Safety
- Suppression is treated as versioned detection configuration rather than silent deletion.
