"""ebpfdet -- ML-driven threat detection over eBPF-style syscall traces.

The runtime layer consumes JSONL traces in the shape that ``bpftrace -f json``
produces.  The detector layer turns per-PID syscall windows into feature
vectors and scores them with a gradient-boosted classifier.  The forensics
layer hands the top-K suspicious processes to an LLM for an incident report
with MITRE ATT&CK mapping.

The package never elevates privileges.  Live capture is opt-in via
``EBPF_LIVE=1`` and requires ``bpftrace`` on PATH; everything else replays
fixtures or synthesised traces.
"""

from .events import SyscallEvent, ProcessTrace, TraceCorpus
from .synth import (
    BENIGN_PROFILES,
    MALICIOUS_PROFILES,
    SyntheticTraceGenerator,
)
from .parser import parse_bpftrace_jsonl, parse_jsonl_lines
from .features import (
    SYSCALL_VOCAB,
    FeatureExtractor,
    extract_window_features,
)
from .detector import (
    DetectorConfig,
    EBPFThreatDetector,
    Verdict,
)
from .forensics import (
    LLMForensicsAnalyst,
    IncidentReport,
)
from .pipeline import DetectionPipeline, PipelineResult

__all__ = [
    "SyscallEvent",
    "ProcessTrace",
    "TraceCorpus",
    "BENIGN_PROFILES",
    "MALICIOUS_PROFILES",
    "SyntheticTraceGenerator",
    "parse_bpftrace_jsonl",
    "parse_jsonl_lines",
    "SYSCALL_VOCAB",
    "FeatureExtractor",
    "extract_window_features",
    "DetectorConfig",
    "EBPFThreatDetector",
    "Verdict",
    "LLMForensicsAnalyst",
    "IncidentReport",
    "DetectionPipeline",
    "PipelineResult",
]
