# ebpf-detector

ML-driven threat detection over Linux **eBPF syscall traces**, with an
LLM forensics layer that turns raw verdicts into a triage-ready
incident report mapped to MITRE ATT&CK.

```
JSONL syscall trace (bpftrace -f json | fixture | synth)
   -> parser            ProcessTrace per (pid, comm)
   -> features          59-dim vector: syscall mix + coarse stats + suspicion priors
   -> EBPFThreatDetector  GradientBoostingClassifier with persisted schema
   -> LLMForensicsAnalyst incident report (severity, ATT&CK, actions, confidence)
```

The package is intentionally split so each layer can be used
standalone:

* `ebpfdet.parser` -- bpftrace JSON or fixture JSONL -> `ProcessTrace`s
* `ebpfdet.features` -- stable 59-feature schema with a `feature_names()`
  contract the persisted model verifies on load
* `ebpfdet.detector` -- sklearn GBM + StandardScaler + joblib persistence
* `ebpfdet.forensics` -- LLM-backed report with hallucination guards
* `ebpfdet.pipeline` -- one-shot orchestration

## Why generative + ML?

Pure rules over syscalls (auditd, falco) are brittle: an attacker who
renames `bash` to `[kworker_evil]` defeats most string-matching rules.
A coarse classifier over syscall *mix* + *bigram* + *path-token* features
is harder to evade because the underlying behaviour (open many secret
files, dup stdio then exec, encrypt-then-unlink) shows up in syscall
shape regardless of cosmetic obfuscation.

The LLM is **only** invoked on the top-K already-suspicious processes,
and its output is validated:

* `techniques[*].id` must match `T\d{4}(\.\d{3})?` -- invented "ATT&CK
  IDs" are dropped
* `affected_processes[*]` must reference a `(pid, comm)` actually
  present in the input verdicts
* `severity` clamped to `low|medium|high|critical`
* `confidence` clamped to `[0, 1]`
* `recommended_actions` capped at 8 entries

## Quick start

```bash
pip install -r requirements.txt

# 1. Train a detector on the bundled synthetic profiles
python -m ebpfdet.cli train --out detector.joblib --n-per-profile 12

# 2. Score a captured / fixture trace
python -m ebpfdet.cli scan --model detector.joblib \
    --input fixtures/cred_dump.jsonl --llm

# 3. (opt-in) Live capture via bpftrace; refuses unless EBPFDET_LIVE=1
EBPFDET_LIVE=1 python -m ebpfdet.cli capture \
    --script 'tracepoint:syscalls:sys_enter_openat { ... }'
```

## Bundled profiles

| label     | profiles                                                              |
|-----------|-----------------------------------------------------------------------|
| benign    | `webserver`, `db_client`, `build_tool`, `systemd_idle`                |
| malicious | `reverse_shell`, `cred_dumper`, `ransomware_encrypt`, `crypto_miner`, `data_exfil` |

Sample LLM live output on `fixtures/cred_dump.jsonl`:

```
headline:   Credential harvesting process accessing multiple secret files
severity:   critical
confidence: 0.99
techniques: ['T1003', 'T1552.001']
actions:    8
```

## Embedding into a stream

```python
import sys
from ebpfdet import EBPFThreatDetector, LLMForensicsAnalyst, DetectionPipeline

det = EBPFThreatDetector.load("detector.joblib")
analyst = LLMForensicsAnalyst()  # auto-constructs LLM client
pipeline = DetectionPipeline(detector=det, analyst=analyst)

# stream JSONL from bpftrace stdout
result = pipeline.from_lines(sys.stdin)
print(result.to_dict())
```

## Tests

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v   # +1 live LLM smoke
```

52 unit tests cover parser robustness, feature stability, detector
training/persistence/threshold, and forensics hallucination guards;
1 LLM_LIVE smoke runs the full pipeline against the configured LLM.

## Layout

```
ebpfdet/
  events.py       SyscallEvent, ProcessTrace, TraceCorpus
  synth.py        TraceProfile + 4 benign + 5 malicious bundled profiles
  parser.py       bpftrace JSON / fixture JSONL parser
  features.py     SYSCALL_VOCAB + 59-feature schema
  detector.py     EBPFThreatDetector + DetectorConfig + Verdict
  forensics.py    LLMForensicsAnalyst + IncidentReport (validated)
  pipeline.py     DetectionPipeline + PipelineResult
  cli.py          ebpfdet {train, scan, capture}
fixtures/
  reverse_shell.jsonl     plain JSONL flavour
  cred_dump.jsonl         bpftrace printf-wrapped flavour
tests/
  test_ebpfdet.py         52 unit + 1 live smoke
```

## License

MIT
