"""Process-tree reconstruction from an event stream.

Ancestry is what makes process detection powerful: "bash whose ancestor is nginx"
catches a web-shell that a flat per-event rule misses. The tree is built
incrementally as events arrive and tolerates gaps (a missing parent from a dropped
event becomes a synthetic 'unknown' node rather than crashing).
"""
from __future__ import annotations

import dataclasses

from .events import EventType, ProcessEvent


@dataclasses.dataclass(slots=True)
class Node:
    pid: int
    ppid: int
    comm: str
    filename: str = ""
    args: tuple[str, ...] = ()
    alive: bool = True
    synthetic: bool = False   # created to fill a gap from a dropped event


class ProcessTree:
    def __init__(self) -> None:
        self._nodes: dict[int, Node] = {}

    def apply(self, ev: ProcessEvent) -> None:
        if ev.type in (EventType.EXEC, EventType.FORK):
            # ensure the parent exists (synthetic if we never saw its exec)
            if ev.ppid and ev.ppid not in self._nodes:
                self._nodes[ev.ppid] = Node(
                    pid=ev.ppid, ppid=0, comm="?", synthetic=True)
            node = self._nodes.get(ev.pid)
            if node is None:
                self._nodes[ev.pid] = Node(
                    pid=ev.pid, ppid=ev.ppid, comm=ev.comm,
                    filename=ev.filename, args=ev.args)
            else:
                # exec-over: update image but keep identity/ancestry
                node.comm = ev.comm or node.comm
                node.filename = ev.filename or node.filename
                node.args = ev.args or node.args
                node.ppid = ev.ppid or node.ppid
                node.synthetic = False
                node.alive = True
        elif ev.type is EventType.EXIT:
            node = self._nodes.get(ev.pid)
            if node:
                node.alive = False

    def get(self, pid: int) -> Node | None:
        return self._nodes.get(pid)

    def ancestry(self, pid: int, max_depth: int = 64) -> list[Node]:
        """Chain from `pid` up to the root. Stops at cycles/limits (gap-safe)."""
        chain: list[Node] = []
        seen: set[int] = set()
        cur = self._nodes.get(pid)
        depth = 0
        while cur is not None and cur.pid not in seen and depth < max_depth:
            chain.append(cur)
            seen.add(cur.pid)
            if not cur.ppid or cur.ppid == cur.pid:
                break
            cur = self._nodes.get(cur.ppid)
            depth += 1
        return chain

    def has_ancestor(self, pid: int, comm: str) -> bool:
        return any(n.comm == comm for n in self.ancestry(pid)[1:])

    def live_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.alive)

    def reap_dead(self) -> int:
        """Drop exited leaf nodes to bound memory. Returns count reaped."""
        children: dict[int, int] = {}
        for n in self._nodes.values():
            children[n.ppid] = children.get(n.ppid, 0) + 1
        dead_leaves = [pid for pid, n in self._nodes.items()
                       if not n.alive and children.get(pid, 0) == 0]
        for pid in dead_leaves:
            del self._nodes[pid]
        return len(dead_leaves)
