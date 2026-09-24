# Architecture

NightWatch deliberately keeps the pipeline small:

```text
JSONL -> Event normalization -> Detector fan-out -> Alert set -> Entity risk fusion -> Report
```

The detectors do not mutate events and do not depend on each other. That makes each rule easy to test in isolation and keeps correlation behavior reproducible.

## Why not a giant rule DSL yet

A DSL is easy to demo and easy to over-engineer. I care more about getting event semantics, windows, evidence and false-positive behavior right first.

The next step is a thin rule layer that can express:

```text
sequence(auth.fail x N -> auth.success) within 120s
fanout(net.dst_port) >= N within 60s
periodicity(net.flow) cv <= threshold
feature(dns.label_entropy) >= threshold
```

## Risk fusion

Alerts on the same entity are combined as independent risk contributions:

```text
risk = 1 - product(1 - score_i)
```

This avoids naive score summation instantly overflowing 100 while still making multiple weak signals matter.
