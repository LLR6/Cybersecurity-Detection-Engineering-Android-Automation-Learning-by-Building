# Releasing NightWatch

## Checklist

1. Default-branch CI green.
2. Positive regression corpus passes with no missed expected alerts.
3. Benign regression corpus remains free of unexpected alerts.
4. New detector behavior includes fixtures and tests.
5. Suppression behavior remains auditable.
6. Update `CHANGELOG.md`, `pyproject.toml` and `CITATION.cff`.
7. Review `docs/TUNING.md`, `docs/BENCHMARKS.md` and `docs/ROADMAP.md`.
8. Tag only after versioned metadata is committed.

Synthetic regression fixtures are release gates, not production accuracy claims.
