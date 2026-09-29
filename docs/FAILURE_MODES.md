# Known Failure Modes

| Failure | Detection | Recovery / interpretation |
|---|---|---|
| False positive from periodic legitimate traffic | benign corpus / analyst review | narrow threshold or auditable suppression |
| True activity split into multiple Cases | case review | increase or redesign correlation window |
| Unrelated alerts merged by shared infrastructure | correlation edges show weak/common entity | refine entity role / correlation policy |
| Missing parser fields reduce rule coverage | parser validation / sparse evidence | report degraded evidence; do not invent fields |
| Suppression too broad | suppression audit shows wildcard overreach | narrow rule/entity pattern |
| Detector regression | labeled CI corpora | block merge until explained or truth updated |

A successful parse is not equivalent to complete telemetry coverage.
