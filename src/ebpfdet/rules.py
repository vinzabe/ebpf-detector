"""Ancestry-aware detection rules.

A rule matches on the triggering event AND the process ancestry, which is what
distinguishes real EDR logic from grep-over-a-log. Rules are declarative
predicates; the engine supplies the tree so a rule can ask "was this spawned by
nginx?".
"""
from __future__ import annotations

import dataclasses
import fnmatch
from collections.abc import Callable

from .events import ProcessEvent
from .process_tree import ProcessTree

# A matcher gets the event and the tree; returns True if the rule fires.
Matcher = Callable[[ProcessEvent, ProcessTree], bool]


@dataclasses.dataclass(frozen=True, slots=True)
class Rule:
    id: str
    description: str
    severity: str            # "critical" | "high" | "medium"
    matcher: Matcher
    mitre: str = ""          # ATT&CK technique id, for coverage tracking


@dataclasses.dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    severity: str
    pid: int
    comm: str
    ancestry: tuple[str, ...]
    mitre: str


_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "csh"})
_SERVERS = frozenset({"nginx", "httpd", "apache2", "node", "java", "gunicorn",
                      "php-fpm", "python", "uwsgi"})


def _shell_from_server(ev: ProcessEvent, tree: ProcessTree) -> bool:
    if ev.comm not in _SHELLS:
        return False
    return any(a.comm in _SERVERS for a in tree.ancestry(ev.pid)[1:])


def _download_and_exec(ev: ProcessEvent, _tree: ProcessTree) -> bool:
    if ev.comm not in ("curl", "wget"):
        return False
    joined = " ".join(ev.args).lower()
    return "| sh" in joined or "|sh" in joined or "| bash" in joined


def _suspicious_recon_chain(ev: ProcessEvent, tree: ProcessTree) -> bool:
    recon = {"whoami", "id", "uname", "hostname", "ifconfig", "ip"}
    if ev.comm not in recon:
        return False
    return any(a.comm in _SHELLS for a in tree.ancestry(ev.pid)[1:]) and \
        any(a.comm in _SERVERS for a in tree.ancestry(ev.pid)[1:])


def _exec_from_tmp(ev: ProcessEvent, _tree: ProcessTree) -> bool:
    return bool(ev.filename) and fnmatch.fnmatch(ev.filename, "/tmp/*")


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("shell-from-webserver",
         "Interactive shell spawned by a web/app server (web shell)",
         "critical", _shell_from_server, "T1059"),
    Rule("curl-pipe-shell",
         "Download piped directly to a shell", "high",
         _download_and_exec, "T1059.004"),
    Rule("recon-under-webserver",
         "Recon command in a shell descended from a server", "high",
         _suspicious_recon_chain, "T1033"),
    Rule("exec-from-tmp",
         "Execution of a binary from /tmp", "medium",
         _exec_from_tmp, "T1036"),
)


def evaluate(ev: ProcessEvent, tree: ProcessTree,
             rules: tuple[Rule, ...] = DEFAULT_RULES) -> list[Detection]:
    out: list[Detection] = []
    for rule in rules:
        if rule.matcher(ev, tree):
            out.append(Detection(
                rule_id=rule.id, severity=rule.severity, pid=ev.pid,
                comm=ev.comm,
                ancestry=tuple(n.comm for n in tree.ancestry(ev.pid)),
                mitre=rule.mitre))
    return out
