# Threat model & scope

## What this is
A process-based detection engine (the analysis half of an eBPF EDR): process-tree
reconstruction, ancestry-aware rules, and loss accounting. It consumes an event
stream and emits detections mapped to ATT&CK.

## What this is not
- **Not a complete EDR.** No file/network/registry telemetry, no response
  actions, no kernel collector shipped (the collector is the documented Linux
  binding point). It is the detection core, deliberately scoped.
- **Not tamper-proof.** A root attacker can kill the collector or the engine.
  eBPF-based EDR raises the bar; it is not an integrity boundary against root.

## Trust boundaries
- **The event stream is trusted as kernel-sourced.** On Linux, eBPF tracepoints
  are the source; the engine assumes events reflect real kernel activity. A
  compromised collector yields compromised detection.
- **The engine executes nothing** from the events — it reads structured facts and
  matches rules. No pivot surface.

## Known limits (stated plainly)
- **Evasion.** An attacker who avoids the modeled patterns (renames the shell,
  uses a server not in the list, execs from a path other than /tmp) evades the
  current rules. Rules are a starting set, extensible; this is detection, not
  prevention.
- **Dropped events = missed detections.** Accounted for and surfaced, but a high
  drop rate genuinely means reduced coverage. Tune ring-buffer size on the
  collector side.
- **comm-based matching** can be spoofed (a process can set its own comm). Robust
  deployments should also match on the exec filename/hash; the engine records
  filename and rules can use it (`exec-from-tmp` does).
- **The shipped rules are illustrative**, covering common web-shell/recon/dropper
  patterns. Real coverage needs a tuned ruleset for your environment.

## Reporting
An evasion of a shipped rule, or a tree-reconstruction bug under drops, to
**gabejar@usa.com** with a replay trace.
