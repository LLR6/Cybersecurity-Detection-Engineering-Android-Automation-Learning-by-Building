# Release Checklist

Use this checklist before creating a tagged release.

## Code and behavior

- [ ] Main branch CI is green.
- [ ] Unit/integration tests pass from a clean checkout.
- [ ] Labeled benchmarks or regression fixtures pass.
- [ ] Generated example artifacts were inspected manually.
- [ ] CLI/UI behavior matches README examples.

## Reproducibility

- [ ] Version / commit is recorded.
- [ ] Example inputs are synthetic, de-identified, or authorized.
- [ ] Seeds/configuration are recorded for experiments.
- [ ] Important generated reports have stable schemas.
- [ ] Checksums are recorded where the project supports them.

## Documentation

- [ ] CHANGELOG reflects user-visible changes.
- [ ] README quick-start still works.
- [ ] ARCHITECTURE and limitation notes remain accurate.
- [ ] SECURITY / CONTRIBUTING guidance still matches actual behavior.

## Security and privacy

- [ ] No credentials, tokens, private keys, private telemetry, or personal backups are committed.
- [ ] New file/path/network behavior was reviewed against documented safety boundaries.
- [ ] Dependency / workflow changes were reviewed.

## Release artifact

- [ ] Artifact filename is unambiguous.
- [ ] Artifact can be recreated from the tagged commit.
- [ ] Release notes distinguish implemented behavior from experimental claims.
