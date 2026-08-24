import json
import platform

import pytest

from ebpfdet.sources import EbpfSource, ReplaySource


def test_replay_source_and_drop_marker(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join([
        json.dumps({"type": "exec", "pid": 10, "ppid": 1, "comm": "bash"}),
        json.dumps({"__dropped__": 5}),
        json.dumps({"type": "exec", "pid": 11, "ppid": 10, "comm": "sh",
                    "filename": "/bin/sh"}),
    ]))
    src = ReplaySource(trace)
    events = list(src.events())
    assert len(events) == 2
    assert src.dropped() == 5


def test_ebpf_source_refuses_non_linux():
    if platform.system() == "Linux":
        pytest.skip("on Linux EbpfSource construction is allowed")
    with pytest.raises(RuntimeError, match="requires Linux"):
        EbpfSource()
