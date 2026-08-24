"""Process events and the source abstraction.

Events are the minimal kernel facts a process-based detector needs. `EventSource`
is the seam between the platform (eBPF ring buffer on Linux, a replay file or an
in-memory queue in tests) and the engine.
"""
from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterator
from typing import Protocol


class EventType(enum.Enum):
    EXEC = "exec"      # a process called execve
    FORK = "fork"      # a process forked a child
    EXIT = "exit"      # a process exited


@dataclasses.dataclass(frozen=True, slots=True)
class ProcessEvent:
    type: EventType
    pid: int
    ppid: int
    comm: str                 # short command name (like kernel `comm`)
    filename: str = ""        # exec path for EXEC events
    args: tuple[str, ...] = ()
    uid: int = 0
    timestamp_ns: int = 0

    def __post_init__(self) -> None:
        if self.pid < 0 or self.ppid < 0:
            raise ValueError("pid/ppid must be non-negative")


class EventSource(Protocol):
    """Yields ProcessEvents and reports how many it had to drop.

    `dropped()` is first-class: under load a ring buffer overflows, and the engine
    must surface that, not hide it."""
    def events(self) -> Iterator[ProcessEvent]: ...
    def dropped(self) -> int: ...
