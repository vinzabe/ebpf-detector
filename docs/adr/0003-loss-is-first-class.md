# 3. Dropped events are a first-class output; the tree is gap-safe

Date: 2026-08-24
Status: Accepted

## Context
Under load a BPF ring buffer overflows and events are lost. Two bad options:
pretend it didn't happen (silent false all-clear), or crash when a referenced
parent is missing.

## Decision
- `EventSource.dropped()` is part of the interface; `EngineReport` exposes
  `events_dropped` and `drop_rate`, and the CLI warns prominently above ~1%.
- The tree tolerates gaps: a missing parent becomes a synthetic node, ancestry
  walking is cycle- and depth-bounded, so a dropped event degrades a chain to a
  `?` ancestor rather than breaking reconstruction.

## Consequences
- Operators can trust a "0 detections" only when the drop rate is low, and the
  tool tells them the rate every run.
- Detection under heavy load degrades gracefully (some ancestry unknown) instead
  of failing; the `?` marker makes the degradation visible in the output.
- Tested directly: drop-rate math, synthetic-parent creation, and cycle-safe
  ancestry all have unit tests.
