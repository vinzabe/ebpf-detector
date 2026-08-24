import json

import pytest

from ebpfdet.cli import EXIT_DETECTIONS, EXIT_OK, main


def _trace(tmp_path):
    t = tmp_path / "t.jsonl"
    t.write_text("\n".join([
        json.dumps({"type": "exec", "pid": 100, "ppid": 1, "comm": "nginx",
                    "filename": "/usr/sbin/nginx"}),
        json.dumps({"type": "fork", "pid": 200, "ppid": 100, "comm": "nginx"}),
        json.dumps({"type": "exec", "pid": 200, "ppid": 100, "comm": "sh",
                    "filename": "/bin/sh"}),
    ]))
    return str(t)


def test_run_detects_webshell(tmp_path, capsys):
    rc = main(["run", _trace(tmp_path)])
    assert rc == EXIT_DETECTIONS
    assert "shell-from-webserver" in capsys.readouterr().out


def test_run_json(tmp_path, capsys):
    main(["run", _trace(tmp_path), "--json"])
    d = json.loads(capsys.readouterr().out)
    assert d["detections"] and "T1059" in d["coverage"]


def test_clean_trace_exits_ok(tmp_path, capsys):
    t = tmp_path / "c.jsonl"
    t.write_text(json.dumps({"type": "exec", "pid": 1, "ppid": 0,
                             "comm": "systemd"}))
    assert main(["run", str(t)]) == EXIT_OK


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
