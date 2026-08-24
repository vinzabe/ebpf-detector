# ebpf-detector

**Process-telemetry detection where the hard part isn't the probe — it's process ancestry and honest loss accounting.**

Attaching an eBPF probe is the easy part; every EDR demo does it. What makes process detection actually work is (1) reconstructing the process tree so a rule can say *"a shell whose ancestor is a web server"* — the signature of a web shell — and (2) accounting honestly for the events you drop under load, because **a detector that silently loses events is worse than none.**

This engine implements both, behind a pluggable event source. On Linux the source is a CO-RE eBPF collector; everywhere else a replay or in-memory source drives the *exact same engine*, so the detection logic is fully testable without a kernel.

```
$ ebpfdet run trace.jsonl
processed 3 events, dropped 0 (0.0%)
  ATT&CK coverage: T1033, T1059

  🔴 [critical] shell-from-webserver pid=200 sh
        ancestry: sh <- nginx <- ?  [T1059]
  🟠 [high] recon-under-webserver pid=300 whoami
        ancestry: whoami <- sh <- nginx  [T1033]
```

## Ancestry is the point

A flat, per-event rule cannot tell `bash` run by an admin from `bash` run by a compromised `nginx`. This engine reconstructs the tree incrementally and rules match on the chain:

| Rule | Fires on | ATT&CK |
|---|---|---|
| `shell-from-webserver` | interactive shell descended from nginx/httpd/node/… | T1059 |
| `recon-under-webserver` | `whoami`/`id`/`uname` in a shell under a server | T1033 |
| `curl-pipe-shell` | download piped straight into a shell | T1059.004 |
| `exec-from-tmp` | a binary executed from `/tmp` | T1036 |

The benign chain `sshd → bash → ls` does **not** fire `shell-from-webserver`, because its ancestor is sshd, not a server. That discrimination is what a tree buys you.

## Honest loss accounting

Under load a BPF ring buffer overflows. This engine treats dropped events as **first-class output**, not a silent gap:

```
processed 41,982 events, dropped 6,551 (13.5%)
  ⚠️  drop rate 13.5%: detections may have been MISSED under load
```

A tool that reported "0 detections" without that warning would be lying by omission. The tree is also **gap-safe**: a process whose parent's `exec` was dropped gets a synthetic `?` ancestor node instead of crashing the reconstruction.

## Runs without a kernel

The engine is driven by an `EventSource`:
- `EbpfSource` — the Linux binding point (attach `sched_process_{exec,fork,exit}` tracepoints, read the ring buffer, count overflows as `dropped()`). It **raises on non-Linux hosts** rather than returning an empty stream that would look like "no threats".
- `ReplaySource` — replay a JSONL event trace (with `{"__dropped__": N}` markers).
- `InMemorySource` — for tests.

So detection rules, ancestry, and loss accounting are 96%-covered by tests that never touch a kernel.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/ebpf-detector && cd ebpf-detector
python -m pip install -e ".[dev]"

ebpfdet run trace.jsonl          # replay a trace, report detections + drop rate
ebpfdet run trace.jsonl --json   # machine-readable, with ATT&CK coverage
```

Exit codes: `0` no detections, `2` detections found, `1` error.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=ebpfdet       # 23 tests, ~96% coverage
mypy --strict src/ebpfdet  # clean
ruff check src tests       # clean
```

## License

MIT © vinzabe
