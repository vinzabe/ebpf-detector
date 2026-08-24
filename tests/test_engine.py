"""Loss accounting is a first-class feature — test it explicitly."""
from ebpfdet.engine import Engine
from ebpfdet.events import EventType, ProcessEvent
from ebpfdet.sources import InMemorySource


def test_drop_rate_accounting():
    src = InMemorySource(
        [ProcessEvent(EventType.EXEC, 10, 1, "bash")], dropped=9)
    report = Engine().run(src)
    assert report.events_dropped == 9
    assert report.events_processed == 1
    assert abs(report.drop_rate - 0.9) < 1e-9


def test_zero_drop_rate():
    src = InMemorySource([ProcessEvent(EventType.EXEC, 10, 1, "bash")])
    assert Engine().run(src).drop_rate == 0.0


def test_reaping_runs():
    events = []
    for pid in range(2, 25):
        events.append(ProcessEvent(EventType.FORK, pid, 1, "init"))
        events.append(ProcessEvent(EventType.EXIT, pid, 1, "init"))
    src = InMemorySource(events)
    report = Engine(reap_interval=10).run(src)
    assert report.reaped > 0


def test_empty_source():
    report = Engine().run(InMemorySource([]))
    assert report.events_processed == 0 and report.detections == ()
