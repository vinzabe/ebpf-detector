"""Feature extraction for syscall windows.

The detector consumes a fixed-width vector per process trace.  Three groups:

1. *Syscall mix* -- normalised frequency of each syscall in ``SYSCALL_VOCAB``,
   plus a single ``other`` bucket.  This captures "what kind of process is
   this" (epoll-heavy server vs. open-heavy file scanner vs. send-heavy
   exfil tool).

2. *Coarse statistics* -- event count, duration, mean inter-arrival, syscall
   diversity (Shannon entropy), error rate (negative retval frequency), and
   the unique-destination / unique-path counts pulled out of args.

3. *Suspicion priors* -- counts of syscalls into known-sensitive paths
   (``/etc/shadow``, ``/root/.ssh``, ``credentials``, ``id_rsa``) and
   sequence-bigram hits for classic patterns (``dup2 -> execve``,
   ``connect -> dup2``, bulk ``rename -> unlink``).  These are *not* the
   classifier on their own; they are signal the GBM can latch onto.

The feature schema is stable: ``feature_names()`` returns the column order
which the persisted detector verifies on load.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np

from .events import ProcessTrace

# A compact vocabulary chosen so that all bundled profiles plus typical
# real captures land in-distribution.
SYSCALL_VOCAB: Tuple[str, ...] = (
    "openat", "open", "read", "write", "close", "fstat", "stat",
    "execve", "execveat", "fork", "clone", "dup2",
    "connect", "accept4", "sendto", "recvfrom",
    "epoll_wait", "futex", "mmap", "munmap",
    "rename", "unlink", "sched_yield",
)

_SENSITIVE_TOKENS: Tuple[str, ...] = (
    "/etc/shadow", "/etc/passwd", "/root/.ssh", "id_rsa", "id_ed25519",
    ".aws/credentials", ".docker/config", "credentials.db", ".kube/config",
)

_SUSPICIOUS_BIGRAMS: Tuple[Tuple[str, str], ...] = (
    ("dup2", "execve"),
    ("connect", "dup2"),
    ("rename", "unlink"),
    ("openat", "rename"),
    ("read", "sendto"),
)


def _shannon_entropy(counts: Iterable[int]) -> float:
    counts = [c for c in counts if c > 0]
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts)


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def feature_names() -> List[str]:
    names: List[str] = [f"sc_freq__{sc}" for sc in SYSCALL_VOCAB]
    names.append("sc_freq__other")
    names.extend([
        "stat_event_count",
        "stat_duration_us",
        "stat_mean_iat_us",
        "stat_syscall_entropy",
        "stat_error_rate",
        "stat_unique_dests",
        "stat_unique_paths",
        "stat_max_send_bytes",
        "stat_max_recv_bytes",
        "stat_total_send_bytes",
    ])
    names.extend([f"susp_path__{tok}" for tok in _SENSITIVE_TOKENS])
    names.extend([f"susp_bg__{a}_{b}" for a, b in _SUSPICIOUS_BIGRAMS])
    return names


def extract_window_features(trace: ProcessTrace) -> np.ndarray:
    """Return a 1D float vector of length ``len(feature_names())``."""

    n = len(trace.events)
    counts = Counter(e.syscall for e in trace.events)
    other = sum(c for sc, c in counts.items() if sc not in SYSCALL_VOCAB)
    freq_vec = []
    denom = max(1, n)
    for sc in SYSCALL_VOCAB:
        freq_vec.append(counts.get(sc, 0) / denom)
    freq_vec.append(other / denom)

    # coarse stats
    duration_ns = trace.duration_ns()
    duration_us = duration_ns / 1000.0
    if n > 1:
        mean_iat_us = duration_us / (n - 1)
    else:
        mean_iat_us = 0.0
    entropy = _shannon_entropy(counts.values())
    err = sum(1 for e in trace.events if e.retval is not None and e.retval < 0)
    err_rate = _safe_div(err, n)

    dests = set()
    paths = set()
    send_bytes = []
    recv_bytes = []
    for e in trace.events:
        addr = e.args.get("addr")
        if isinstance(addr, str):
            dests.add(addr)
        path = e.args.get("filename")
        if isinstance(path, str):
            paths.add(path)
        cnt = e.args.get("count")
        if isinstance(cnt, int) and cnt >= 0:
            if e.syscall in {"sendto", "write"}:
                send_bytes.append(cnt)
            elif e.syscall in {"recvfrom", "read"}:
                recv_bytes.append(cnt)

    coarse = [
        float(n),
        float(duration_us),
        float(mean_iat_us),
        float(entropy),
        float(err_rate),
        float(len(dests)),
        float(len(paths)),
        float(max(send_bytes) if send_bytes else 0),
        float(max(recv_bytes) if recv_bytes else 0),
        float(sum(send_bytes) if send_bytes else 0),
    ]

    # suspicion priors -- token-in-path
    susp_path = []
    flat_paths = " ".join(p for p in paths if isinstance(p, str)).lower()
    for tok in _SENSITIVE_TOKENS:
        susp_path.append(float(flat_paths.count(tok.lower())))

    # suspicion priors -- bigrams
    seq = trace.syscall_sequence()
    bigram_counts: Counter = Counter(zip(seq, seq[1:]))
    susp_bg = [float(bigram_counts.get((a, b), 0)) for a, b in _SUSPICIOUS_BIGRAMS]

    vec = freq_vec + coarse + susp_path + susp_bg
    return np.asarray(vec, dtype=np.float64)


class FeatureExtractor:
    """Vectorised feature extraction over a list of traces."""

    def __init__(self) -> None:
        self.names: List[str] = feature_names()

    def transform(self, traces: Sequence[ProcessTrace]) -> np.ndarray:
        if not traces:
            return np.zeros((0, len(self.names)), dtype=np.float64)
        rows = [extract_window_features(t) for t in traces]
        return np.vstack(rows)

    def feature_names(self) -> List[str]:
        return list(self.names)
