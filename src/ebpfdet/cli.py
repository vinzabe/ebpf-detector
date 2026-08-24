"""CLI: replay a trace through the engine and report detections + drop rate.

Exit codes: 0 no detections, 2 detections found, 1 error. A high drop rate is
surfaced prominently because it means detections may have been MISSED.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .engine import Engine
from .sources import ReplaySource

EXIT_OK, EXIT_ERROR, EXIT_DETECTIONS = 0, 1, 2

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡"}


def cmd_run(a: argparse.Namespace) -> int:
    report = Engine().run(ReplaySource(a.trace))
    if a.json:
        print(json.dumps({
            "events_processed": report.events_processed,
            "events_dropped": report.events_dropped,
            "drop_rate": report.drop_rate,
            "coverage": sorted(report.coverage),
            "detections": [{"rule": d.rule_id, "severity": d.severity,
                            "pid": d.pid, "comm": d.comm,
                            "ancestry": list(d.ancestry), "mitre": d.mitre}
                           for d in report.detections]}, indent=2))
    else:
        print(f"processed {report.events_processed} events, "
              f"dropped {report.events_dropped} ({report.drop_rate:.1%})")
        if report.drop_rate > 0.01:
            print(f"  ⚠️  drop rate {report.drop_rate:.1%}: detections may have "
                  "been MISSED under load")
        print(f"  ATT&CK coverage: {', '.join(sorted(report.coverage)) or 'none'}\n")
        for d in report.detections:
            print(f"  {_ICON.get(d.severity,'')} [{d.severity}] {d.rule_id} "
                  f"pid={d.pid} {d.comm}")
            print(f"        ancestry: {' <- '.join(d.ancestry)}  [{d.mitre}]")
        if not report.detections:
            print("  no detections")
    return EXIT_DETECTIONS if report.detections else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ebpfdet", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="replay a JSONL event trace through the engine")
    r.add_argument("trace")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
