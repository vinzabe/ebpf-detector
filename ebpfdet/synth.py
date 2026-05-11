"""Synthetic syscall trace generator.

Real eBPF capture requires CAP_BPF and an unblocked tracefs.  In CI / cloud
sandboxes that often is not available, so we ship a profile-driven
generator that mimics the *statistical shape* of common process behaviours
on Linux: short-bursty exec, long-tail file scanning, network-heavy beacons,
and so on.  The detector trained on these profiles transfers reasonably to
real bpftrace JSONL captures of similar behaviour because the feature
extractor only consumes coarse syscall mix + sequence statistics.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .events import ProcessTrace, SyscallEvent


@dataclass
class TraceProfile:
    """Profile parameters for a synthetic process behaviour.

    ``syscall_weights`` is sampled with replacement.  ``burst_args`` lets
    a profile bias arguments toward a particular file path / dest IP / etc,
    which the feature extractor later picks up as e.g. "talks to one host".
    """

    name: str
    label: str  # "benign" | "malicious"
    comm_pool: Sequence[str]
    syscall_weights: Dict[str, float]
    mean_events: int
    event_jitter: float = 0.3
    interarrival_us: float = 200.0
    burst_args: Dict[str, Sequence[str]] = field(default_factory=dict)
    notes: str = ""


def _sample_syscall(weights: Dict[str, float], rng: random.Random) -> str:
    items = list(weights.items())
    total = sum(w for _, w in items)
    if total <= 0:
        raise ValueError("syscall weights must be positive")
    pick = rng.uniform(0.0, total)
    acc = 0.0
    for name, w in items:
        acc += w
        if pick <= acc:
            return name
    return items[-1][0]


def _sample_args(
    syscall: str, profile: TraceProfile, rng: random.Random
) -> Dict[str, object]:
    args: Dict[str, object] = {}
    if syscall in {"openat", "open", "stat", "execve", "execveat"}:
        if "paths" in profile.burst_args:
            args["filename"] = rng.choice(list(profile.burst_args["paths"]))
        else:
            args["filename"] = rng.choice(
                ["/etc/hosts", "/usr/bin/ls", "/var/log/syslog", "/tmp/x"]
            )
    if syscall in {"connect", "sendto", "recvfrom"}:
        if "dests" in profile.burst_args:
            args["addr"] = rng.choice(list(profile.burst_args["dests"]))
        else:
            args["addr"] = f"10.0.0.{rng.randint(2, 250)}:{rng.randint(80, 8443)}"
    if syscall in {"write", "read", "sendto", "recvfrom"}:
        args["count"] = int(rng.lognormvariate(5.5, 1.0))
    if syscall == "execve" and "argv" in profile.burst_args:
        args["argv"] = list(profile.burst_args["argv"])
    return args


def _sample_retval(syscall: str, rng: random.Random) -> int:
    if syscall in {"openat", "open", "connect"}:
        return -1 if rng.random() < 0.05 else rng.randint(3, 64)
    if syscall in {"read", "recvfrom"}:
        return int(rng.lognormvariate(5.5, 1.0))
    if syscall in {"write", "sendto"}:
        return int(rng.lognormvariate(5.0, 0.8))
    return 0


def generate_trace(
    profile: TraceProfile,
    pid: Optional[int] = None,
    seed: Optional[int] = None,
    start_ts_ns: int = 0,
) -> ProcessTrace:
    rng = random.Random(seed)
    pid = pid if pid is not None else rng.randint(1000, 65535)
    comm = rng.choice(list(profile.comm_pool))
    n_target = max(
        4,
        int(profile.mean_events * (1.0 + rng.uniform(-profile.event_jitter, profile.event_jitter))),
    )
    trace = ProcessTrace(pid=pid, comm=comm, label=profile.label)
    ts = start_ts_ns
    for _ in range(n_target):
        sc = _sample_syscall(profile.syscall_weights, rng)
        ev = SyscallEvent(
            timestamp_ns=ts,
            pid=pid,
            comm=comm,
            syscall=sc,
            args=_sample_args(sc, profile, rng),
            retval=_sample_retval(sc, rng),
        )
        trace.add(ev)
        ia_us = max(1.0, rng.expovariate(1.0 / profile.interarrival_us))
        ts += int(ia_us * 1000)
    return trace


# ----- bundled profiles -----

BENIGN_PROFILES: List[TraceProfile] = [
    TraceProfile(
        name="webserver",
        label="benign",
        comm_pool=("nginx", "gunicorn", "uvicorn"),
        syscall_weights={
            "accept4": 4.0, "read": 12.0, "write": 10.0, "epoll_wait": 8.0,
            "openat": 1.5, "close": 4.0, "fstat": 2.0,
        },
        mean_events=80,
        interarrival_us=150.0,
        notes="HTTP server: accept-loop dominated by epoll/read/write.",
    ),
    TraceProfile(
        name="db_client",
        label="benign",
        comm_pool=("psql", "mysql", "redis-cli"),
        syscall_weights={
            "connect": 1.0, "sendto": 6.0, "recvfrom": 6.0,
            "read": 2.0, "write": 2.0, "close": 1.0,
        },
        mean_events=40,
        interarrival_us=400.0,
        burst_args={"dests": ["10.0.5.20:5432", "10.0.5.20:6379"]},
        notes="Single-host DB chatter.",
    ),
    TraceProfile(
        name="build_tool",
        label="benign",
        comm_pool=("gcc", "make", "ld", "python3"),
        syscall_weights={
            "openat": 8.0, "read": 14.0, "fstat": 6.0, "close": 8.0,
            "write": 4.0, "execve": 0.5, "mmap": 5.0,
        },
        mean_events=120,
        interarrival_us=80.0,
        notes="Compiler reads many headers, writes one object.",
    ),
    TraceProfile(
        name="systemd_idle",
        label="benign",
        comm_pool=("systemd", "systemd-journald"),
        syscall_weights={
            "epoll_wait": 18.0, "read": 4.0, "write": 2.0,
            "openat": 1.0, "fstat": 1.0,
        },
        mean_events=40,
        interarrival_us=2000.0,
        notes="Mostly idle event loop.",
    ),
]

MALICIOUS_PROFILES: List[TraceProfile] = [
    TraceProfile(
        name="reverse_shell",
        label="malicious",
        comm_pool=("bash", "sh", "python3"),
        syscall_weights={
            "connect": 1.0, "dup2": 3.0, "execve": 1.0,
            "read": 6.0, "write": 6.0, "fork": 0.5, "clone": 0.5,
        },
        mean_events=30,
        interarrival_us=600.0,
        burst_args={
            "dests": ["198.51.100.7:4444"],
            "argv": ["/bin/bash", "-i"],
            "paths": ["/dev/tcp/198.51.100.7/4444", "/bin/bash"],
        },
        notes="Classic dup2-stdio-then-exec /bin/bash reverse shell.",
    ),
    TraceProfile(
        name="cred_dumper",
        label="malicious",
        comm_pool=("dump", "harvest", "python3"),
        syscall_weights={
            "openat": 14.0, "read": 18.0, "fstat": 4.0, "close": 8.0,
            "write": 1.0,
        },
        mean_events=80,
        interarrival_us=120.0,
        burst_args={
            "paths": [
                "/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa",
                "/home/alice/.aws/credentials",
                "/home/alice/.config/gcloud/credentials.db",
                "/var/lib/docker/.docker/config.json",
            ]
        },
        notes="Sweeps well-known credential paths read-only.",
    ),
    TraceProfile(
        name="ransomware_encrypt",
        label="malicious",
        comm_pool=("locker", "enc", "kworker_evil"),
        syscall_weights={
            "openat": 10.0, "read": 12.0, "write": 12.0,
            "rename": 6.0, "unlink": 3.0, "fstat": 4.0, "close": 8.0,
        },
        mean_events=200,
        interarrival_us=40.0,
        burst_args={
            "paths": [
                "/home/alice/docs/q1.docx", "/home/alice/docs/q2.docx",
                "/home/alice/photos/img_001.jpg", "/srv/share/budget.xlsx",
            ]
        },
        notes="Bulk rename/encrypt/unlink across user dirs.",
    ),
    TraceProfile(
        name="crypto_miner",
        label="malicious",
        comm_pool=("xmrig", "kdevtmpfsi", "python3"),
        syscall_weights={
            "futex": 30.0, "sched_yield": 6.0, "mmap": 3.0,
            "read": 1.0, "write": 1.0, "connect": 0.2, "sendto": 1.5,
            "recvfrom": 1.5,
        },
        mean_events=200,
        interarrival_us=30.0,
        burst_args={"dests": ["203.0.113.42:3333"]},
        notes="Stratum pool socket + futex-heavy worker threads.",
    ),
    TraceProfile(
        name="data_exfil",
        label="malicious",
        comm_pool=("curl", "wget", "python3"),
        syscall_weights={
            "openat": 4.0, "read": 8.0, "connect": 0.5,
            "sendto": 14.0, "recvfrom": 1.0, "close": 2.0,
        },
        mean_events=120,
        interarrival_us=80.0,
        burst_args={
            "dests": ["192.0.2.55:443"],
            "paths": ["/var/lib/postgresql/dump.sql", "/srv/share/customers.csv"],
        },
        notes="Read-once, send-many to a single external destination.",
    ),
]


@dataclass
class SyntheticTraceGenerator:
    """Produce labelled corpora for training and evaluation.

    Determinism: pass ``seed`` for reproducible draws.  The generator threads
    sub-seeds into each per-trace generator so adding traces does not
    perturb earlier ones.
    """

    benign_profiles: Sequence[TraceProfile] = field(default_factory=lambda: list(BENIGN_PROFILES))
    malicious_profiles: Sequence[TraceProfile] = field(default_factory=lambda: list(MALICIOUS_PROFILES))
    seed: Optional[int] = None

    def _rng(self) -> random.Random:
        return random.Random(self.seed)

    def generate_corpus(
        self,
        n_per_profile: int = 8,
    ) -> List[ProcessTrace]:
        rng = self._rng()
        out: List[ProcessTrace] = []
        for prof in list(self.benign_profiles) + list(self.malicious_profiles):
            for i in range(n_per_profile):
                sub_seed = rng.randint(0, 2**31 - 1)
                ts = rng.randint(0, 10_000_000)
                out.append(generate_trace(prof, seed=sub_seed, start_ts_ns=ts))
        rng.shuffle(out)
        return out

    def generate_one(self, profile_name: str, seed: Optional[int] = None) -> ProcessTrace:
        for prof in list(self.benign_profiles) + list(self.malicious_profiles):
            if prof.name == profile_name:
                return generate_trace(prof, seed=seed if seed is not None else self.seed)
        raise KeyError(f"unknown profile {profile_name!r}")
