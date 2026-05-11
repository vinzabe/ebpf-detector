"""Parsers for bpftrace and our fixture JSONL.

``bpftrace -f json`` emits one JSON record per line.  Records of type
``"attached_probes"`` and ``"printf"`` show up; we ignore the metadata and
only consume the per-event ones.  Each printf record has a ``data`` field
that stores whatever the BPF program asked for.

We accept *two* fixture flavours:

1. The plain ``ebpfdet`` flavour: each line is a complete event with
   ``ts`` / ``pid`` / ``comm`` / ``syscall`` / optional ``args`` and ``retval``.
2. A ``bpftrace -f json`` flavour, which wraps the same payload inside
   ``{"type": "printf", "data": {...}}``.

The output of either parser is a ``Dict[(pid, comm), ProcessTrace]``.
"""

from __future__ import annotations

import json
from typing import Dict, Iterable, List, Tuple

from .events import ProcessTrace, SyscallEvent


def _coerce_event(record: dict) -> SyscallEvent:
    if not isinstance(record, dict):
        raise ValueError("event must be a dict")
    if "syscall" not in record or "pid" not in record:
        raise ValueError("event missing required pid/syscall")
    pid = int(record["pid"])
    comm = str(record.get("comm", f"pid_{pid}"))
    syscall = str(record["syscall"])
    ts_ns = int(record.get("ts", record.get("timestamp_ns", 0)))
    args = record.get("args") or {}
    if not isinstance(args, dict):
        args = {"raw": args}
    retval = record.get("retval")
    if retval is not None:
        retval = int(retval)
    return SyscallEvent(
        timestamp_ns=ts_ns,
        pid=pid,
        comm=comm,
        syscall=syscall,
        args=args,
        retval=retval,
    )


def parse_jsonl_lines(lines: Iterable[str]) -> List[ProcessTrace]:
    """Group lines into per-(pid,comm) ``ProcessTrace`` objects."""

    by_key: Dict[Tuple[int, str], ProcessTrace] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("type") == "printf":
            data = record.get("data")
            if not isinstance(data, dict):
                continue
            record = data
        if not isinstance(record, dict):
            continue
        if record.get("type") in {"attached_probes", "lost_events", "stats"}:
            continue
        try:
            ev = _coerce_event(record)
        except (ValueError, KeyError, TypeError):
            continue
        key = (ev.pid, ev.comm)
        if key not in by_key:
            by_key[key] = ProcessTrace(pid=ev.pid, comm=ev.comm)
        by_key[key].add(ev)
    return list(by_key.values())


def parse_bpftrace_jsonl(path: str) -> List[ProcessTrace]:
    """Convenience: parse a JSONL file from disk."""

    with open(path, "r", encoding="utf-8") as fh:
        return parse_jsonl_lines(fh)
