# 2. A pluggable EventSource, and refuse-not-fake on the wrong platform

Date: 2026-08-24
Status: Accepted

## Context
eBPF is Linux-only, but the valuable logic — process-tree reconstruction,
ancestry rules, loss accounting — is platform-independent. Coupling that logic to
a live kernel would make it untestable off-Linux and unverifiable in CI.

## Decision
Put an `EventSource` protocol between the platform and the engine.
`EbpfSource` is the Linux binding; `ReplaySource`/`InMemorySource` drive the same
engine from traces or memory. `EbpfSource` **raises** on non-Linux hosts instead
of yielding nothing.

## Consequences
- The engine is ~96% test-covered without a kernel, including the exact web-shell
  ancestry chain.
- A misconfigured deployment (running the non-Linux path expecting protection)
  fails loud rather than silently reporting a false all-clear — the same
  fail-closed principle used across these tools.
- The eBPF collector itself (tracepoint attach, ring-buffer read, CO-RE) is the
  documented next step, not shipped here. Stated as a scope boundary, not hidden.
