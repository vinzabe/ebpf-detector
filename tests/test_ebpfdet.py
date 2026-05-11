"""ebpfdet test-suite.

Layout:
  - events / synth / parser / features    -- unit tests, no LLM
  - detector                               -- train + persist round-trip
  - forensics                              -- coerce + hallucination guards
  - pipeline                               -- end-to-end with FakeLLM
  - LLM_LIVE smoke                         -- full pipeline against real LLM
                                              (skipped unless LLM_LIVE=1)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from pathlib import Path
from typing import List

import numpy as np
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from ebpfdet import (
    BENIGN_PROFILES,
    DetectionPipeline,
    DetectorConfig,
    EBPFThreatDetector,
    FeatureExtractor,
    LLMForensicsAnalyst,
    MALICIOUS_PROFILES,
    ProcessTrace,
    SyntheticTraceGenerator,
    SyscallEvent,
    TraceCorpus,
    parse_bpftrace_jsonl,
    parse_jsonl_lines,
    extract_window_features,
)
from ebpfdet.features import feature_names
from ebpfdet.forensics import _coerce_report
from ebpfdet.synth import generate_trace


FIXTURE_DIR = Path(_HERE).parent / "fixtures"


# ---- events --------------------------------------------------------------


def test_syscall_event_to_dict_omits_none_retval():
    e = SyscallEvent(timestamp_ns=1, pid=2, comm="x", syscall="read")
    d = e.to_dict()
    assert "retval" not in d
    assert d["pid"] == 2 and d["syscall"] == "read"


def test_syscall_event_to_dict_includes_retval_when_set():
    e = SyscallEvent(timestamp_ns=1, pid=2, comm="x", syscall="read", retval=42)
    assert e.to_dict()["retval"] == 42


def test_process_trace_rejects_wrong_pid():
    t = ProcessTrace(pid=10, comm="x")
    with pytest.raises(ValueError):
        t.add(SyscallEvent(timestamp_ns=0, pid=11, comm="x", syscall="read"))


def test_process_trace_duration_zero_when_lt_two_events():
    t = ProcessTrace(pid=1, comm="x")
    assert t.duration_ns() == 0
    t.add(SyscallEvent(timestamp_ns=5, pid=1, comm="x", syscall="read"))
    assert t.duration_ns() == 0


def test_process_trace_duration_nonzero():
    t = ProcessTrace(pid=1, comm="x")
    t.add(SyscallEvent(timestamp_ns=5, pid=1, comm="x", syscall="read"))
    t.add(SyscallEvent(timestamp_ns=15, pid=1, comm="x", syscall="write"))
    assert t.duration_ns() == 10


def test_trace_corpus_labels_and_iter():
    c = TraceCorpus()
    c.add(ProcessTrace(pid=1, comm="x", label="benign"))
    c.add(ProcessTrace(pid=2, comm="y", label="malicious"))
    assert c.labels() == ["benign", "malicious"]
    assert len(c) == 2
    assert [t.pid for t in c] == [1, 2]


# ---- synth ---------------------------------------------------------------


def test_generate_trace_is_deterministic_given_seed():
    prof = BENIGN_PROFILES[0]
    a = generate_trace(prof, seed=99)
    b = generate_trace(prof, seed=99)
    assert a.syscall_sequence() == b.syscall_sequence()
    assert a.pid == b.pid
    assert a.comm == b.comm


def test_generate_trace_label_matches_profile():
    prof = MALICIOUS_PROFILES[0]
    t = generate_trace(prof, seed=7)
    assert t.label == "malicious"


def test_generator_corpus_has_both_labels():
    gen = SyntheticTraceGenerator(seed=1)
    corpus = gen.generate_corpus(n_per_profile=3)
    labels = {t.label for t in corpus}
    assert labels == {"benign", "malicious"}


def test_generator_one_unknown_profile_raises():
    gen = SyntheticTraceGenerator(seed=1)
    with pytest.raises(KeyError):
        gen.generate_one("does_not_exist")


def test_reverse_shell_profile_emits_dup2_and_connect():
    t = generate_trace(
        next(p for p in MALICIOUS_PROFILES if p.name == "reverse_shell"),
        seed=42,
    )
    seq = t.syscall_sequence()
    assert "dup2" in seq
    assert "connect" in seq or "execve" in seq


def test_cred_dumper_paths_include_known_secrets():
    t = generate_trace(
        next(p for p in MALICIOUS_PROFILES if p.name == "cred_dumper"),
        seed=42,
    )
    paths = [
        e.args.get("filename", "")
        for e in t.events
        if isinstance(e.args.get("filename"), str)
    ]
    blob = " ".join(paths)
    assert "shadow" in blob or "id_rsa" in blob or "credentials" in blob


# ---- parser --------------------------------------------------------------


def test_parser_skips_blank_and_comment_lines():
    lines = [
        "",
        "# a comment",
        '{"ts": 1, "pid": 5, "comm": "x", "syscall": "read"}',
    ]
    traces = parse_jsonl_lines(lines)
    assert len(traces) == 1
    assert traces[0].pid == 5


def test_parser_skips_invalid_json():
    lines = [
        "not json at all",
        '{"ts": 1, "pid": 5, "comm": "x", "syscall": "read"}',
    ]
    traces = parse_jsonl_lines(lines)
    assert len(traces) == 1


def test_parser_skips_attached_probes_and_lost_events():
    lines = [
        '{"type": "attached_probes", "data": {"probes": 7}}',
        '{"type": "lost_events", "data": {"count": 1}}',
        '{"ts": 1, "pid": 5, "comm": "x", "syscall": "read"}',
    ]
    assert len(parse_jsonl_lines(lines)) == 1


def test_parser_unwraps_bpftrace_printf_records():
    lines = [
        '{"type": "printf", "data": {"ts": 1, "pid": 9, "comm": "y", "syscall": "openat"}}',
    ]
    traces = parse_jsonl_lines(lines)
    assert len(traces) == 1 and traces[0].pid == 9


def test_parser_groups_events_by_pid_and_comm():
    lines = [
        '{"ts": 1, "pid": 1, "comm": "a", "syscall": "read"}',
        '{"ts": 2, "pid": 1, "comm": "a", "syscall": "write"}',
        '{"ts": 3, "pid": 2, "comm": "b", "syscall": "read"}',
    ]
    traces = parse_jsonl_lines(lines)
    by_pid = {t.pid: t for t in traces}
    assert by_pid[1].syscall_sequence() == ["read", "write"]
    assert by_pid[2].syscall_sequence() == ["read"]


def test_parser_skips_event_missing_required_fields():
    lines = [
        '{"ts": 1, "pid": 1}',  # no syscall
        '{"ts": 2, "pid": 1, "comm": "a", "syscall": "read"}',
    ]
    traces = parse_jsonl_lines(lines)
    assert len(traces) == 1
    assert len(traces[0].events) == 1


def test_parser_handles_real_fixture_reverse_shell():
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "reverse_shell.jsonl"))
    pids = {t.pid for t in traces}
    assert {4201, 999}.issubset(pids)


def test_parser_handles_real_fixture_cred_dump_with_printf_wrapper():
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "cred_dump.jsonl"))
    assert len(traces) == 1
    assert traces[0].comm == "harvest"


# ---- features ------------------------------------------------------------


def test_feature_names_are_unique_and_nonempty():
    names = feature_names()
    assert len(names) > 0
    assert len(set(names)) == len(names)


def test_extract_window_features_returns_correct_shape():
    t = ProcessTrace(pid=1, comm="x")
    for i in range(5):
        t.add(SyscallEvent(timestamp_ns=i * 1000, pid=1, comm="x", syscall="read"))
    vec = extract_window_features(t)
    assert vec.shape == (len(feature_names()),)
    assert vec.dtype == np.float64


def test_extract_window_features_normalises_freq_to_one():
    t = ProcessTrace(pid=1, comm="x")
    for i in range(10):
        t.add(SyscallEvent(timestamp_ns=i, pid=1, comm="x", syscall="read"))
    vec = extract_window_features(t)
    names = feature_names()
    freq_idxs = [i for i, n in enumerate(names) if n.startswith("sc_freq__")]
    assert abs(sum(vec[i] for i in freq_idxs) - 1.0) < 1e-9


def test_extract_window_features_picks_up_sensitive_paths():
    t = ProcessTrace(pid=1, comm="x")
    t.add(SyscallEvent(
        timestamp_ns=0, pid=1, comm="x", syscall="openat",
        args={"filename": "/etc/shadow"}, retval=5,
    ))
    t.add(SyscallEvent(
        timestamp_ns=1, pid=1, comm="x", syscall="read",
        args={"count": 100}, retval=100,
    ))
    vec = extract_window_features(t)
    names = feature_names()
    idx = names.index("susp_path__/etc/shadow")
    assert vec[idx] >= 1.0


def test_extract_window_features_picks_up_dup2_execve_bigram():
    t = ProcessTrace(pid=1, comm="x")
    t.add(SyscallEvent(timestamp_ns=0, pid=1, comm="x", syscall="dup2"))
    t.add(SyscallEvent(timestamp_ns=1, pid=1, comm="x", syscall="execve"))
    vec = extract_window_features(t)
    names = feature_names()
    idx = names.index("susp_bg__dup2_execve")
    assert vec[idx] == 1.0


def test_feature_extractor_transform_handles_empty():
    fx = FeatureExtractor()
    arr = fx.transform([])
    assert arr.shape == (0, len(feature_names()))


def test_feature_extractor_transform_stacks_rows():
    fx = FeatureExtractor()
    gen = SyntheticTraceGenerator(seed=3)
    traces = gen.generate_corpus(n_per_profile=2)
    arr = fx.transform(traces)
    assert arr.shape == (len(traces), len(feature_names()))


def test_extract_features_handles_negative_retval_as_error():
    t = ProcessTrace(pid=1, comm="x")
    t.add(SyscallEvent(timestamp_ns=0, pid=1, comm="x", syscall="openat", retval=-1))
    t.add(SyscallEvent(timestamp_ns=1, pid=1, comm="x", syscall="openat", retval=5))
    vec = extract_window_features(t)
    names = feature_names()
    idx = names.index("stat_error_rate")
    assert vec[idx] == 0.5


# ---- detector ------------------------------------------------------------


def _train_default_detector(seed: int = 1) -> EBPFThreatDetector:
    gen = SyntheticTraceGenerator(seed=seed)
    corpus = gen.generate_corpus(n_per_profile=8)
    return EBPFThreatDetector(DetectorConfig(random_state=seed)).fit(corpus)


def test_detector_fit_requires_nonempty_corpus():
    with pytest.raises(ValueError):
        EBPFThreatDetector().fit([])


def test_detector_fit_requires_labels():
    t = ProcessTrace(pid=1, comm="x")
    t.add(SyscallEvent(timestamp_ns=0, pid=1, comm="x", syscall="read"))
    with pytest.raises(ValueError):
        EBPFThreatDetector().fit([t])


def test_detector_fit_requires_both_classes():
    gen = SyntheticTraceGenerator(seed=1)
    benign_only = [t for t in gen.generate_corpus(8) if t.label == "benign"]
    with pytest.raises(ValueError):
        EBPFThreatDetector().fit(benign_only)


def test_detector_predict_before_fit_raises():
    with pytest.raises(RuntimeError):
        EBPFThreatDetector().predict([])


def test_detector_classifies_reverse_shell_as_malicious():
    det = _train_default_detector()
    gen = SyntheticTraceGenerator(seed=99)
    rs = gen.generate_one("reverse_shell", seed=99)
    [v] = det.predict([rs])
    assert v.label == "malicious"
    assert v.score > 0.5


def test_detector_classifies_webserver_as_benign():
    det = _train_default_detector()
    gen = SyntheticTraceGenerator(seed=99)
    ws = gen.generate_one("webserver", seed=99)
    [v] = det.predict([ws])
    assert v.label == "benign"
    assert v.score < 0.5


def test_detector_holdout_accuracy_is_high():
    det = _train_default_detector(seed=1)
    gen = SyntheticTraceGenerator(seed=2025)
    holdout = gen.generate_corpus(n_per_profile=5)
    verdicts = det.predict(holdout)
    correct = sum(1 for t, v in zip(holdout, verdicts) if v.label == t.label)
    assert correct / len(holdout) >= 0.85


def test_detector_save_and_load_roundtrip(tmp_path):
    det = _train_default_detector()
    p = tmp_path / "m.joblib"
    det.save(str(p))
    det2 = EBPFThreatDetector.load(str(p))
    gen = SyntheticTraceGenerator(seed=11)
    rs = gen.generate_one("reverse_shell", seed=11)
    [v1] = det.predict([rs])
    [v2] = det2.predict([rs])
    assert abs(v1.score - v2.score) < 1e-9


def test_detector_load_rejects_unknown_schema_version(tmp_path):
    det = _train_default_detector()
    p = tmp_path / "m.joblib"
    det.save(str(p))
    import joblib
    payload = joblib.load(p)
    payload["schema_version"] = 999
    joblib.dump(payload, p)
    with pytest.raises(ValueError):
        EBPFThreatDetector.load(str(p))


def test_detector_verdict_top_features_is_nonempty():
    det = _train_default_detector()
    gen = SyntheticTraceGenerator(seed=3)
    rs = gen.generate_one("reverse_shell", seed=3)
    [v] = det.predict([rs])
    assert len(v.top_features) > 0


def test_detector_threshold_overrides_suspicious_flag():
    det = EBPFThreatDetector(DetectorConfig(suspicious_threshold=0.99))
    gen = SyntheticTraceGenerator(seed=1)
    det.fit(gen.generate_corpus(n_per_profile=8))
    ws = gen.generate_one("webserver", seed=1)
    [v] = det.predict([ws])
    assert v.suspicious is False


# ---- forensics -----------------------------------------------------------


def _make_verdict(pid: int = 1, comm: str = "harvest", score: float = 0.9):
    return _coerce_report(
        json.dumps({
            "headline": "h", "severity": "high", "summary": "s",
            "techniques": [], "affected_processes": [], "recommended_actions": [],
            "confidence": 0.5,
        }),
        [],
    )  # used as a sentinel only


def test_coerce_report_clamps_confidence_low():
    raw = json.dumps({
        "headline": "x", "severity": "low", "summary": "s",
        "techniques": [], "affected_processes": [],
        "recommended_actions": [], "confidence": -3.0,
    })
    rep = _coerce_report(raw, [])
    assert rep.confidence == 0.0


def test_coerce_report_clamps_confidence_high():
    raw = json.dumps({
        "headline": "x", "severity": "low", "summary": "s",
        "techniques": [], "affected_processes": [],
        "recommended_actions": [], "confidence": 17.0,
    })
    rep = _coerce_report(raw, [])
    assert rep.confidence == 1.0


def test_coerce_report_drops_invalid_attack_id():
    raw = json.dumps({
        "headline": "x", "severity": "high", "summary": "s",
        "techniques": [
            {"id": "T1059.003", "name": "PowerShell", "evidence": "ev"},
            {"id": "ATT&CK::Bogus", "name": "fake", "evidence": "ev"},
        ],
        "affected_processes": [], "recommended_actions": [],
        "confidence": 0.5,
    })
    rep = _coerce_report(raw, [])
    assert len(rep.techniques) == 1
    assert rep.techniques[0]["id"] == "T1059.003"


def test_coerce_report_rejects_invented_processes():
    from ebpfdet.detector import Verdict as _V
    real = _V(pid=42, comm="real", label="malicious", score=0.9, suspicious=True)
    raw = json.dumps({
        "headline": "x", "severity": "high", "summary": "s",
        "techniques": [],
        "affected_processes": [
            {"pid": 42, "comm": "real", "rationale": "ok"},
            {"pid": 99, "comm": "ghost", "rationale": "should be dropped"},
        ],
        "recommended_actions": [],
        "confidence": 0.5,
    })
    rep = _coerce_report(raw, [real])
    assert len(rep.affected_processes) == 1
    assert rep.affected_processes[0]["pid"] == 42


def test_coerce_report_clamps_severity_to_known():
    raw = json.dumps({
        "headline": "x", "severity": "DOOM", "summary": "s",
        "techniques": [], "affected_processes": [],
        "recommended_actions": [], "confidence": 0.5,
    })
    rep = _coerce_report(raw, [])
    assert rep.severity == "medium"


def test_coerce_report_handles_garbled_response():
    rep = _coerce_report("absolutely not json", [])
    assert rep.fallback is True
    assert rep.severity in {"low", "medium", "high", "critical"}


def test_coerce_report_extracts_json_from_codefence():
    payload = {
        "headline": "x", "severity": "high", "summary": "s",
        "techniques": [], "affected_processes": [],
        "recommended_actions": ["a"], "confidence": 0.5,
    }
    raw = "Here you go:\n```json\n" + json.dumps(payload) + "\n```\n"
    rep = _coerce_report(raw, [])
    assert rep.fallback is False
    assert rep.recommended_actions == ["a"]


def test_analyst_with_no_client_returns_heuristic_report():
    analyst = LLMForensicsAnalyst(client=None)
    from ebpfdet.detector import Verdict as _V
    v = _V(pid=1, comm="x", label="malicious", score=0.9, suspicious=True)
    rep = analyst.analyse([v], [])
    assert rep.fallback is True
    assert any(p["pid"] == 1 for p in rep.affected_processes)


def test_analyst_with_no_verdicts_returns_clean_report():
    analyst = LLMForensicsAnalyst(client=None)
    rep = analyst.analyse([], [])
    assert rep.severity == "low"
    assert rep.fallback is False


# ---- pipeline ------------------------------------------------------------


class _FakeLLM:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        content = self._payload if isinstance(self._payload, str) else json.dumps(self._payload)
        return types.SimpleNamespace(content=content)


def test_pipeline_end_to_end_with_fake_llm():
    det = _train_default_detector()
    fake = _FakeLLM({
        "headline": "Reverse shell observed",
        "severity": "high",
        "summary": "dup2 then execve to /bin/bash with stdio redirection.",
        "techniques": [
            {"id": "T1059.004", "name": "Unix Shell", "evidence": "execve /bin/bash -i"},
        ],
        "affected_processes": [],  # filled at coerce; test passes verdicts only
        "recommended_actions": ["Isolate host", "Kill process tree"],
        "confidence": 0.9,
    })
    analyst = LLMForensicsAnalyst(client=fake)
    pipeline = DetectionPipeline(detector=det, analyst=analyst, enable_llm=True)
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "reverse_shell.jsonl"))
    result = pipeline.run(traces)
    assert any(v.suspicious for v in result.verdicts)
    assert result.report is not None
    assert fake.calls == 1
    assert result.report.severity == "high"
    assert any(t["id"] == "T1059.004" for t in result.report.techniques)


def test_pipeline_no_suspicious_skips_llm():
    det = _train_default_detector()
    fake = _FakeLLM("never called")
    analyst = LLMForensicsAnalyst(client=fake)
    pipeline = DetectionPipeline(detector=det, analyst=analyst, enable_llm=True)
    gen = SyntheticTraceGenerator(seed=4)
    benign = [gen.generate_one("webserver", seed=4)]
    result = pipeline.run(benign)
    assert fake.calls == 0
    assert result.report is not None
    assert result.report.severity == "low"


def test_pipeline_disabled_llm_returns_no_report():
    det = _train_default_detector()
    pipeline = DetectionPipeline(detector=det, analyst=None, enable_llm=False)
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "reverse_shell.jsonl"))
    result = pipeline.run(traces)
    assert result.report is None


def test_pipeline_to_dict_is_json_serialisable():
    det = _train_default_detector()
    pipeline = DetectionPipeline(detector=det, analyst=None, enable_llm=False)
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "reverse_shell.jsonl"))
    result = pipeline.run(traces)
    blob = json.dumps(result.to_dict(), default=str)
    assert "verdicts" in blob


# ---- LLM live smoke ------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("LLM_LIVE") != "1",
    reason="set LLM_LIVE=1 to run live LLM smoke",
)
def test_llm_live_full_pipeline_with_real_llm():
    det = _train_default_detector()
    analyst = LLMForensicsAnalyst()
    pipeline = DetectionPipeline(detector=det, analyst=analyst, enable_llm=True)
    traces = parse_bpftrace_jsonl(str(FIXTURE_DIR / "cred_dump.jsonl"))
    result = pipeline.run(traces)
    assert any(v.suspicious for v in result.verdicts)
    assert result.report is not None
    print(f"\nlive incident report:")
    print(f"  headline:   {result.report.headline}")
    print(f"  severity:   {result.report.severity}")
    print(f"  confidence: {result.report.confidence}")
    print(f"  techniques: {[t['id'] for t in result.report.techniques]}")
    print(f"  actions:    {len(result.report.recommended_actions)}")
    assert result.report.severity in {"low", "medium", "high", "critical"}
    assert 0.0 <= result.report.confidence <= 1.0
    # any reasonable response should mention credential-access in some form
    lowered = (result.report.headline + " " + result.report.summary).lower()
    assert any(t in lowered for t in ("cred", "secret", "shadow", "ssh", "exfil"))
