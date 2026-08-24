"""Concrete event sources.

`InMemorySource` and `ReplaySource` drive the engine in tests and from recorded
traces. `EbpfSource` is the Linux binding stub: it documents exactly where a CO-RE
eBPF collector plugs in, and refuses to pretend on non-Linux hosts rather than
silently returning nothing (which would look like "no threats").
"""
from __future__ import annotations

import json
import platform
from collections.abc import Iterator
from pathlib import Path

from .events import EventType, ProcessEvent


class InMemorySource:
    def __init__(self, events: list[ProcessEvent], dropped: int = 0) -> None:
        self._events = events
        self._dropped = dropped

    def events(self) -> Iterator[ProcessEvent]:
        yield from self._events

    def dropped(self) -> int:
        return self._dropped


class ReplaySource:
    """Replay events from a JSONL trace (one event per line)."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._dropped = 0

    def events(self) -> Iterator[ProcessEvent]:
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            if d.get("__dropped__"):
                self._dropped += int(d["__dropped__"])
                continue
            yield ProcessEvent(
                type=EventType(d["type"]), pid=d["pid"], ppid=d.get("ppid", 0),
                comm=d.get("comm", ""), filename=d.get("filename", ""),
                args=tuple(d.get("args", [])), uid=d.get("uid", 0),
                timestamp_ns=d.get("timestamp_ns", 0))

    def dropped(self) -> int:
        return self._dropped


class EbpfSource:
    """Linux CO-RE eBPF collector binding point.

    This is where a real deployment attaches tracepoints (sched_process_exec,
    sched_process_fork, sched_process_exit) and reads a BPF ring buffer, counting
    ring-buffer overflows as dropped(). It deliberately raises on non-Linux hosts
    instead of returning an empty stream, so a misconfigured deployment fails loud
    rather than reporting a false all-clear.
    """

    def __init__(self) -> None:
        if platform.system() != "Linux":
            raise RuntimeError(
                "EbpfSource requires Linux with a CO-RE-capable kernel; use "
                "ReplaySource/InMemorySource elsewhere. Refusing to return an "
                "empty stream that would look like 'no threats'.")

    def events(self) -> Iterator[ProcessEvent]:  # pragma: no cover - Linux only
        raise NotImplementedError(
            "attach BPF tracepoints and read the ring buffer here")

    def dropped(self) -> int:  # pragma: no cover - Linux only
        return 0
