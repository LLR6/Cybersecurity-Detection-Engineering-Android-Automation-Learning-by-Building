# Security Policy

NightWatch is a defensive detection-engineering project. Please report vulnerabilities privately rather than publishing working exploit details in an issue.

## In scope

- unsafe parsing of supplied local telemetry;
- path traversal or unintended file access;
- output that leaks secrets from provided inputs;
- dependency or CI configuration issues that materially affect repository security;
- a documented safety boundary that the code does not actually enforce.

## Out of scope

- requests to add offensive payloads, persistence, credential theft, exploitation, evasion, or unauthorized scanning;
- attacks against third-party systems;
- reports that only state that a heuristic detector can produce false positives or false negatives without a reproducible sample.

## Reporting

Open a private GitHub security advisory when available. Include the affected commit, minimal reproduction, impact, and suggested fix if known. Do not include real credentials, private telemetry, or data you are not authorized to share.

## Defensive data handling

Use synthetic or properly authorized, de-identified telemetry in examples and bug reports. Treat detector output as investigation evidence, not an automatic incident verdict.
