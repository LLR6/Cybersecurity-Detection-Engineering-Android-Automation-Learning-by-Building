# Performance Policy

NightWatch CI publishes a non-gating smoke report from `samples/demo.jsonl`.

The report includes:

- event count;
- alert count;
- load time;
- repeated detector runtime;
- mean/min/max runtime;
- mean events per second.

## What the report is for

- spotting large regressions over time;
- checking that algorithmic changes do not obviously explode runtime;
- keeping a machine-readable artifact alongside functional evaluation.

## What the report is not for

- cross-machine benchmark claims;
- production capacity planning;
- comparing two commits that ran on materially different runner conditions;
- claiming network-wide throughput from a tiny synthetic sample.

If performance becomes a release criterion, use pinned hardware/runner conditions and a substantially larger corpus.
