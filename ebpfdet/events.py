"""Event datamodel.

We deliberately keep the schema small: ``bpftrace -f json`` emits a record
per probe firing, and we project it into a normalised ``SyscallEvent``.

A ``ProcessTrace`` is the per-PID timeseries; a ``TraceCorpus`` is the
labelled collection used for both training and forensic analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class SyscallEvent:
    """A single syscall observation.

    All fields are normalised to plain Python types so that a fixture replay
    and a live capture are indistinguishable downstream.
    """

    timestamp_ns: int
    pid: int
    comm: str
    syscall: str
    args: Dict[str, Any] = field(default_factory=dict)
    retval: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ts": self.timestamp_ns,
            "pid": self.pid,
            "comm": self.comm,
            "syscall": self.syscall,
            "args": dict(self.args),
        }
        if self.retval is not None:
            out["retval"] = self.retval
        return out


@dataclass
class ProcessTrace:
    """All observed syscalls for one (pid, comm) tuple.

    ``label`` is optional: it is populated for synthesised / fixture traces so
    that the detector can be trained, and absent for live capture.
    """

    pid: int
    comm: str
    events: List[SyscallEvent] = field(default_factory=list)
    label: Optional[str] = None

    def add(self, event: SyscallEvent) -> None:
        if event.pid != self.pid:
            raise ValueError(
                f"event pid {event.pid} != trace pid {self.pid}"
            )
        self.events.append(event)

    def syscall_sequence(self) -> List[str]:
        return [e.syscall for e in self.events]

    def duration_ns(self) -> int:
        if len(self.events) < 2:
            return 0
        return self.events[-1].timestamp_ns - self.events[0].timestamp_ns


@dataclass
class TraceCorpus:
    """A labelled collection of process traces."""

    traces: List[ProcessTrace] = field(default_factory=list)

    def add(self, trace: ProcessTrace) -> None:
        self.traces.append(trace)

    def extend(self, traces: Iterable[ProcessTrace]) -> None:
        for t in traces:
            self.add(t)

    def labels(self) -> List[str]:
        return [t.label or "unknown" for t in self.traces]

    def __len__(self) -> int:
        return len(self.traces)

    def __iter__(self):
        return iter(self.traces)
