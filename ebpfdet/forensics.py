"""LLM-backed incident-report generator.

Given the top-K suspicious verdicts from the detector, build a compact
evidence summary, ask the LLM to map the behaviour to MITRE ATT&CK
techniques, and validate the JSON response.

Hallucination guards:

* ``techniques`` -- each item must carry an ATT&CK ID matching ``T\\d{4}``
  optionally with a sub-technique ``\\.\\d{3}``.  Items without that ID
  are dropped.
* ``affected_processes`` -- entries must reference a (pid, comm) actually
  present in the input verdicts.  Inventions are dropped.
* ``recommended_actions`` -- list of strings, capped to 8 items.
* ``confidence`` -- clamped to [0, 1].
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .detector import Verdict
from .events import ProcessTrace

try:
    from .llm_client import LLMClient
except Exception:  # pragma: no cover - optional dep at import time
    LLMClient = None  # type: ignore


_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass
class IncidentReport:
    headline: str
    severity: str  # "low" | "medium" | "high" | "critical"
    summary: str
    techniques: List[Dict[str, str]] = field(default_factory=list)
    affected_processes: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_response: Optional[str] = None
    fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline,
            "severity": self.severity,
            "summary": self.summary,
            "techniques": list(self.techniques),
            "affected_processes": list(self.affected_processes),
            "recommended_actions": list(self.recommended_actions),
            "confidence": self.confidence,
            "fallback": self.fallback,
        }


_ALLOWED_SEV = {"low", "medium", "high", "critical"}


def _build_evidence(
    verdicts: Sequence[Verdict],
    traces_by_key: Dict[tuple, ProcessTrace],
    top_k: int,
) -> List[Dict[str, Any]]:
    sorted_v = sorted(verdicts, key=lambda v: v.score, reverse=True)[:top_k]
    out: List[Dict[str, Any]] = []
    for v in sorted_v:
        trace = traces_by_key.get((v.pid, v.comm))
        sample_paths: List[str] = []
        sample_dests: List[str] = []
        sample_argv: List[List[str]] = []
        sample_seq: List[str] = []
        if trace is not None:
            sample_seq = trace.syscall_sequence()[:24]
            for e in trace.events:
                if "filename" in e.args and isinstance(e.args["filename"], str):
                    if e.args["filename"] not in sample_paths:
                        sample_paths.append(e.args["filename"])
                if "addr" in e.args and isinstance(e.args["addr"], str):
                    if e.args["addr"] not in sample_dests:
                        sample_dests.append(e.args["addr"])
                if "argv" in e.args and isinstance(e.args["argv"], list):
                    sample_argv.append([str(x) for x in e.args["argv"]])
        out.append({
            "pid": v.pid,
            "comm": v.comm,
            "score": round(v.score, 4),
            "label": v.label,
            "top_features": [(n, round(s, 4)) for n, s in v.top_features],
            "sample_syscalls": sample_seq,
            "sample_paths": sample_paths[:8],
            "sample_dests": sample_dests[:6],
            "sample_argv": sample_argv[:3],
        })
    return out


_SYSTEM_PROMPT = (
    "You are an enterprise SOC incident responder. You are given the top "
    "suspicious processes flagged by an ML classifier over eBPF syscall "
    "traces. Produce a short JSON incident report. Only emit JSON, no "
    "preamble. Schema:\n"
    "{\n"
    '  "headline": str,                        // one short line\n'
    '  "severity": "low"|"medium"|"high"|"critical",\n'
    '  "summary": str,                          // 2-4 sentences\n'
    '  "techniques": [{"id": "Txxxx[.yyy]", "name": str, "evidence": str}],\n'
    '  "affected_processes": [{"pid": int, "comm": str, "rationale": str}],\n'
    '  "recommended_actions": [str],            // <= 8 imperative actions\n'
    '  "confidence": float                      // 0..1\n'
    "}\n"
    "Rules: only include MITRE techniques that the evidence supports. "
    "Only reference (pid, comm) tuples that appear in the supplied "
    "evidence. Do not invent IPs, hashes, or filenames. Keep total "
    "response under 1500 characters."
)


def _coerce_report(
    raw: str, verdicts: Sequence[Verdict]
) -> IncidentReport:
    valid_keys = {(v.pid, v.comm) for v in verdicts}
    fallback = False
    try:
        if "```" in raw:
            blocks = re.findall(r"```(?:json)?\s*(.*?)```", raw, flags=re.DOTALL)
            if blocks:
                raw_json = blocks[0]
            else:
                raw_json = raw
        else:
            raw_json = raw
        data = json.loads(raw_json.strip())
    except Exception:
        return IncidentReport(
            headline="Suspicious activity detected",
            severity="medium",
            summary="LLM response could not be parsed; raw evidence retained.",
            techniques=[],
            affected_processes=[
                {"pid": v.pid, "comm": v.comm, "rationale": "ML score above threshold"}
                for v in verdicts
            ],
            recommended_actions=[
                "Quarantine affected hosts",
                "Capture full process tree and memory image",
            ],
            confidence=0.3,
            raw_response=raw,
            fallback=True,
        )

    headline = str(data.get("headline", "Suspicious activity detected"))[:180]
    severity = str(data.get("severity", "medium")).lower()
    if severity not in _ALLOWED_SEV:
        severity = "medium"
    summary = str(data.get("summary", ""))[:1200]
    confidence = data.get("confidence", 0.5)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    techs_raw = data.get("techniques", []) or []
    techniques: List[Dict[str, str]] = []
    for t in techs_raw[:12]:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id", "")).strip()
        if not _ATTACK_ID_RE.match(tid):
            continue
        techniques.append({
            "id": tid,
            "name": str(t.get("name", ""))[:80],
            "evidence": str(t.get("evidence", ""))[:240],
        })

    affected_raw = data.get("affected_processes", []) or []
    affected: List[Dict[str, Any]] = []
    for a in affected_raw[:16]:
        if not isinstance(a, dict):
            continue
        try:
            pid = int(a.get("pid"))
        except (TypeError, ValueError):
            continue
        comm = str(a.get("comm", ""))
        if (pid, comm) not in valid_keys:
            continue
        affected.append({
            "pid": pid,
            "comm": comm,
            "rationale": str(a.get("rationale", ""))[:240],
        })

    actions_raw = data.get("recommended_actions", []) or []
    actions = [str(a)[:240] for a in actions_raw if isinstance(a, (str, int, float))][:8]

    return IncidentReport(
        headline=headline,
        severity=severity,
        summary=summary,
        techniques=techniques,
        affected_processes=affected,
        recommended_actions=actions,
        confidence=confidence,
        raw_response=raw,
        fallback=fallback,
    )


# Sentinel so callers can distinguish "auto-construct" (default) from
# "explicitly disabled" (pass client=None).
_AUTO = object()


@dataclass
class LLMForensicsAnalyst:
    """Translate detector verdicts into a triage-ready incident report.

    Pass ``client=None`` to explicitly disable LLM use (the analyst will
    return a heuristic report).  Omit ``client`` to have one auto-constructed
    from ``llm_client.LLMClient`` if available.
    """

    client: Any = _AUTO
    model: str = os.environ.get("EBPFDET_LLM_MODEL", "glm-5.1")
    temperature: float = 0.1
    max_tokens: int = 900
    top_k: int = 5

    def __post_init__(self) -> None:
        if self.client is _AUTO:
            if LLMClient is None:
                self.client = None
            else:
                try:
                    self.client = LLMClient()
                except Exception:
                    self.client = None

    def analyse(
        self,
        verdicts: Sequence[Verdict],
        traces: Sequence[ProcessTrace],
    ) -> IncidentReport:
        if not verdicts:
            return IncidentReport(
                headline="No suspicious processes",
                severity="low",
                summary="Detector flagged nothing above threshold.",
                techniques=[],
                affected_processes=[],
                recommended_actions=[],
                confidence=0.95,
                fallback=False,
            )
        if self.client is None:
            return IncidentReport(
                headline="ML detector flagged suspicious processes (LLM offline)",
                severity="medium",
                summary="No LLM client available; report is heuristic only.",
                techniques=[],
                affected_processes=[
                    {"pid": v.pid, "comm": v.comm, "rationale": "ML score above threshold"}
                    for v in sorted(verdicts, key=lambda x: x.score, reverse=True)[: self.top_k]
                ],
                recommended_actions=[
                    "Quarantine affected hosts",
                    "Run forensic acquisition (memory + disk)",
                ],
                confidence=0.4,
                fallback=True,
            )

        traces_by_key = {(t.pid, t.comm): t for t in traces}
        evidence = _build_evidence(verdicts, traces_by_key, self.top_k)

        user = (
            "Evidence (JSON):\n" + json.dumps(evidence, indent=2)
            + "\n\nReturn the JSON report described in the system prompt only."
        )
        try:
            resp = self.client.chat(
                [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            return IncidentReport(
                headline="LLM unavailable",
                severity="medium",
                summary=f"LLM call failed: {exc!s}",
                techniques=[],
                affected_processes=[
                    {"pid": v.pid, "comm": v.comm, "rationale": "ML score above threshold"}
                    for v in sorted(verdicts, key=lambda x: x.score, reverse=True)[: self.top_k]
                ],
                recommended_actions=["Quarantine affected hosts"],
                confidence=0.3,
                fallback=True,
            )
        return _coerce_report(raw, verdicts)
