import pytest

from ebpfdet.events import EventType, ProcessEvent
from ebpfdet.sources import InMemorySource


def ev(t, pid, ppid, comm, **kw):
    return ProcessEvent(type=EventType(t), pid=pid, ppid=ppid, comm=comm, **kw)


@pytest.fixture
def webshell_trace():
    """nginx(100) -> sh(200) -> whoami(300): a classic web-shell chain."""
    return InMemorySource([
        ev("exec", 100, 1, "nginx", filename="/usr/sbin/nginx"),
        ev("fork", 200, 100, "nginx"),
        ev("exec", 200, 100, "sh", filename="/bin/sh"),
        ev("fork", 300, 200, "sh"),
        ev("exec", 300, 200, "whoami", filename="/usr/bin/whoami"),
    ])


@pytest.fixture
def benign_trace():
    """systemd -> sshd -> bash -> ls: normal, should NOT fire."""
    return InMemorySource([
        ev("exec", 1, 0, "systemd"),
        ev("fork", 50, 1, "systemd"),
        ev("exec", 50, 1, "sshd", filename="/usr/sbin/sshd"),
        ev("fork", 60, 50, "sshd"),
        ev("exec", 60, 50, "bash", filename="/bin/bash"),
        ev("fork", 70, 60, "bash"),
        ev("exec", 70, 60, "ls", filename="/bin/ls"),
    ])
