# NightWatch

> I like logs that refuse to look normal.

A small local-first detection engine I use to play with event correlation, network behavior and explainable alerts.

No giant SIEM stack. No dashboard for the sake of a dashboard. Feed it JSONL, let the detectors argue with the data, and keep the evidence.

```text
login failures ─┐
port fan-out ────┼─> correlation -> alert -> entity risk -> JSON / Markdown
periodic flow ───┤
high entropy DNS ┘
```

## What it catches now

| Rule | Idea | Signal |
|---|---|---|
| `AUTH-SEQ-001` | 连续失败后短时间成功登录 | sequence correlation |
| `NET-SCAN-001` | 单源对单目标端口高扇出 | sliding window |
| `NET-BEACON-001` | 低抖动周期外联 | interval CV |
| `DNS-TUNNEL-001` | 长高熵 DNS label | entropy heuristic |

Each alert carries its own window and evidence. Detection is not a verdict. I want enough context to explain *why* a rule fired instead of just printing `suspicious=true`.

## Quick run

```bash
git clone https://github.com/LLR6/Cybersecurity-Detection-Engineering-Android-Automation-Learning-by-Building.git
cd Cybersecurity-Detection-Engineering-Android-Automation-Learning-by-Building
python -m venv .venv
pip install -e ".[dev]"
pytest -q
nightwatch samples/demo.jsonl --format md --out report.md
```

Example alert:

```json
{
  "rule_id": "NET-BEACON-001",
  "score": 82,
  "entity": "10.10.7.12->203.0.113.42:443",
  "evidence": {
    "interval_mean": 30.0,
    "interval_cv": 0.0,
    "samples": 7
  }
}
```

## Stuff I care about

- **windows before regex** — time relationships usually tell a better story than single-line matching
- **evidence first** — every alert should be explainable without reopening the code
- **boring dependencies** — stdlib is enough for the core, so it runs almost anywhere
- **false positives are part of the design** — entropy and periodicity are signals, not proof
- **tests over screenshots** — if a detector cannot survive a tiny synthetic dataset, it should not exist yet

## Risk fusion

Multiple alerts on one entity are not added like arcade points.

```text
risk = 1 - product(1 - score_i)
```

Two medium signals can matter without instantly turning everything into 100/100.

## Repo map

```text
src/nightwatch/
├── models.py
├── detectors.py
├── engine.py
├── report.py
└── cli.py

tests/
samples/
docs/
.github/workflows/
```

## Next rabbit holes

- Zeek / Suricata adapter
- PCAP -> flow feature extraction
- Sigma-ish sequence rules
- baseline-aware beacon detection
- ATT&CK technique mapping
- precision / recall evaluation set
- graph view for multi-stage activity
- SARIF export and CI gate

If a rule gets smarter but becomes impossible to explain, I probably don't want it.

---

Built for defensive security research, lab data and authorized environments.
