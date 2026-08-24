"""The detection engine: drive an EventSource through the tree + rules, and make
lost-event accounting a first-class output.
"""
from __future__ import annotations

import dataclasses

from .events import EventSource
from .process_tree import ProcessTree
from .rules import DEFAULT_RULES, Detection, Rule, evaluate


@dataclasses.dataclass(frozen=True, slots=True)
class EngineReport:
    events_processed: int
    events_dropped: int
    detections: tuple[Detection, ...]
    reaped: int

    @property
    def drop_rate(self) -> float:
        total = self.events_processed + self.events_dropped
        return self.events_dropped / total if total else 0.0

    @property
    def coverage(self) -> set[str]:
        return {d.mitre for d in self.detections if d.mitre}


@dataclasses.dataclass(slots=True)
class Engine:
    rules: tuple[Rule, ...] = DEFAULT_RULES
    reap_interval: int = 10_000
    tree: ProcessTree = dataclasses.field(default_factory=ProcessTree)

    def run(self, source: EventSource) -> EngineReport:
        detections: list[Detection] = []
        processed = 0
        reaped = 0
        for ev in source.events():
            self.tree.apply(ev)
            detections.extend(evaluate(ev, self.tree, self.rules))
            processed += 1
            if self.reap_interval and processed % self.reap_interval == 0:
                reaped += self.tree.reap_dead()
        return EngineReport(
            events_processed=processed, events_dropped=source.dropped(),
            detections=tuple(detections), reaped=reaped)
