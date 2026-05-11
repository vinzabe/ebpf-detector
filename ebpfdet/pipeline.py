"""End-to-end orchestration.

Glue layer that takes a raw trace source (file, stdin lines, or in-memory
``ProcessTrace`` list) and runs:

  parse  ->  detector.predict  ->  forensics.analyse

Returns a structured ``PipelineResult`` you can serialise to JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .detector import EBPFThreatDetector, Verdict
from .events import ProcessTrace
from .forensics import IncidentReport, LLMForensicsAnalyst
from .parser import parse_bpftrace_jsonl, parse_jsonl_lines


@dataclass
class PipelineResult:
    traces: List[ProcessTrace]
    verdicts: List[Verdict]
    report: Optional[IncidentReport] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_count": len(self.traces),
            "suspicious_count": sum(1 for v in self.verdicts if v.suspicious),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "report": self.report.to_dict() if self.report else None,
        }


@dataclass
class DetectionPipeline:
    detector: EBPFThreatDetector
    analyst: Optional[LLMForensicsAnalyst] = None
    enable_llm: bool = True

    def from_file(self, path: str) -> PipelineResult:
        traces = parse_bpftrace_jsonl(path)
        return self.run(traces)

    def from_lines(self, lines: Sequence[str]) -> PipelineResult:
        traces = parse_jsonl_lines(lines)
        return self.run(traces)

    def run(self, traces: Sequence[ProcessTrace]) -> PipelineResult:
        traces_l = list(traces)
        verdicts = self.detector.predict(traces_l)
        report: Optional[IncidentReport] = None
        if self.enable_llm and self.analyst is not None:
            suspicious = [v for v in verdicts if v.suspicious]
            if suspicious:
                report = self.analyst.analyse(suspicious, traces_l)
            else:
                report = IncidentReport(
                    headline="No suspicious processes",
                    severity="low",
                    summary="Detector flagged nothing above threshold.",
                    techniques=[],
                    affected_processes=[],
                    recommended_actions=[],
                    confidence=0.95,
                    fallback=False,
                )
        return PipelineResult(traces=traces_l, verdicts=verdicts, report=report)
