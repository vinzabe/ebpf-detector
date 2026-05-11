# Security Policy

## Threat model

`ebpf-detector` is a **defensive** tool: it consumes already-captured
syscall traces and produces verdicts.  It does not load BPF programs into
the kernel itself.  The package therefore inherits two distinct risk
surfaces:

1. **Untrusted trace input.** A malicious actor may supply crafted JSONL
   designed to (a) crash the parser, (b) blow up the feature extractor's
   memory, or (c) coerce the LLM into producing actionable but false
   reports.
2. **LLM as analyst.** A language model is invoked on detector output.
   It must not be permitted to invent indicators, quote private data, or
   emit content the operator would mistake for ground truth.

## In-package controls

### Parser

* `parse_jsonl_lines` skips blank lines, comments, malformed JSON, and
  bpftrace metadata records (`attached_probes`, `lost_events`, `stats`)
  rather than aborting the whole stream.
* Records missing required fields (`pid`, `syscall`) are dropped silently
  rather than poisoning the trace.
* Type coercion is done with `int()` / `str()`; non-conforming records
  raise once and are skipped.

### Feature extractor

* The schema is fixed (`feature_names()`); the persisted detector
  refuses to load against a mismatched schema.  This prevents an
  attacker who can swap a `.joblib` from also subtly changing what
  features get evaluated.
* No code in the feature path executes data: arguments are read as
  strings, never `eval`d, never used as filesystem paths.

### Detector

* `joblib` payloads carry a `schema_version`.  Loading a payload with an
  unknown version raises `ValueError`.
* `EBPFThreatDetector.fit` requires both `benign` and `malicious`
  classes; degenerate single-class corpora are rejected.

### LLM forensics

* The analyst sends only **top-K verdicts and bounded evidence
  windows** (`top_k=5`, syscall sequences capped at 24, paths at 8,
  destinations at 6, argv at 3).  Full traces never leave the host.
* `_coerce_report` validates the LLM JSON:
  * `severity` clamped to `{low, medium, high, critical}`
  * `confidence` clamped to `[0, 1]`
  * `techniques[*].id` must match `^T\d{4}(\.\d{3})?$` -- fabricated
    technique IDs are silently dropped
  * `affected_processes[*]` must reference a `(pid, comm)` present in
    the verdicts -- invented processes are dropped
  * `recommended_actions` capped at 8 strings
* On JSON parse failure or LLM transport error the analyst falls back
  to a deterministic heuristic report and sets `fallback=True`.

### CLI

* `ebpfdet capture` (the one path that would run `bpftrace`) refuses to
  execute unless `EBPFDET_LIVE=1` is explicitly set.  In any other
  configuration the CLI is read-only.

## Operator responsibilities

1. **Never train on attacker-controlled traces.** The bundled synthetic
   profiles are safe.  If you train on captured traces you must label
   them yourself; do not accept third-party labelled corpora without
   review.
2. **Treat the LLM report as a triage hint, not ground truth.** Confirm
   `affected_processes` and `techniques` against the underlying trace
   before quarantining hosts.
3. **Run capture as an unprivileged user with CAP_BPF where possible.**
   Do not run the whole CLI as root; use a privileged sidecar that pipes
   JSONL into `ebpfdet scan -i -`.
4. **Outbound LLM calls.** The forensics analyst sends evidence summaries
   to whatever endpoint `LLMClient` is configured for.  Confirm your
   contract with the LLM provider permits this and does not include
   training-on-data clauses.  Prefer a self-hosted endpoint.

## Threats NOT mitigated

* **Mimicry.** A sophisticated attacker who shapes their behaviour to
  look statistically benign will reduce the classifier's recall.  The
  detector is one signal in a defence-in-depth stack, not a perimeter.
* **Adversarial perturbation of ML features.** A targeted attacker who
  knows the feature schema can attempt to inject benign-looking syscalls
  to dilute frequencies.  Mitigation requires retraining on adversarial
  examples (out of scope here).
* **LLM jailbreak.** The validators reject *structurally* invalid LLM
  output, but cannot detect a *plausible-looking* but false claim ("PID
  4201 is your DBA running a backup").  Always corroborate with the
  trace.
* **Side channels in capture.** `bpftrace` itself can be detected by an
  attacker on the host (`/sys/kernel/debug/tracing` activity).  This
  package does not attempt to hide capture.

## Reporting a vulnerability

Email vinzabe@users.noreply.github.com with:

* Affected file/line
* Reproduction steps
* Suggested mitigation (if any)

Do not file public issues for vulnerabilities.

## Contact

Responsible disclosure: **g@abejar.net**
