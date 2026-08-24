"""ebpfdet — kernel-informed process detection with honest loss accounting.

The valuable, hard-to-fake part of an eBPF EDR is not attaching a probe — it is
what you do with the event stream: reconstruct process ancestry so a rule can say
"a shell spawned by a web server", and account honestly for the events you drop
under load, because a detector that silently loses events is worse than none.

This package implements that core — process-tree reconstruction, ancestry-aware
rule matching, and ring-buffer/backpressure loss accounting — behind a pluggable
`EventSource`. On Linux the source is an eBPF collector (CO-RE); everywhere else a
replay or in-memory source drives the exact same engine, so the detection logic is
fully testable without a kernel.
"""
__version__ = "1.0.0"
