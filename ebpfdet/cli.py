"""Command-line entry point.

Subcommands:
  train     -- generate synthetic corpus, fit detector, persist .joblib
  scan      -- load .joblib, score a JSONL trace, print verdicts (+ report)
  capture   -- *opt-in* live bpftrace capture; requires EBPFDET_LIVE=1 and
               privileges. Otherwise refuses.

The capture path runs ``bpftrace`` as a subprocess and emits JSONL to
stdout; we never load any kernel module from this Python.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import List

from .detector import DetectorConfig, EBPFThreatDetector
from .forensics import LLMForensicsAnalyst
from .pipeline import DetectionPipeline
from .synth import SyntheticTraceGenerator


def _cmd_train(args: argparse.Namespace) -> int:
    gen = SyntheticTraceGenerator(seed=args.seed)
    corpus = gen.generate_corpus(n_per_profile=args.n_per_profile)
    cfg = DetectorConfig(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.lr,
        random_state=args.seed,
        suspicious_threshold=args.threshold,
    )
    det = EBPFThreatDetector(cfg).fit(corpus)
    det.save(args.out)
    print(f"trained on {len(corpus)} traces -> {args.out}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    det = EBPFThreatDetector.load(args.model)
    analyst = None
    if args.llm:
        analyst = LLMForensicsAnalyst()
    pipeline = DetectionPipeline(detector=det, analyst=analyst, enable_llm=args.llm)
    if args.input == "-":
        lines = sys.stdin.readlines()
        result = pipeline.from_lines(lines)
    else:
        result = pipeline.from_file(args.input)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    if os.environ.get("EBPFDET_LIVE") != "1":
        print("refusing to run bpftrace; set EBPFDET_LIVE=1 to opt in", file=sys.stderr)
        return 2
    cmd = ["bpftrace", "-f", "json", "-e", args.script]
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ebpfdet")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="train detector on synthetic corpus")
    p_train.add_argument("--out", default="ebpfdet.joblib")
    p_train.add_argument("--seed", type=int, default=1337)
    p_train.add_argument("--n-per-profile", type=int, default=12)
    p_train.add_argument("--n-estimators", type=int, default=200)
    p_train.add_argument("--max-depth", type=int, default=3)
    p_train.add_argument("--lr", type=float, default=0.1)
    p_train.add_argument("--threshold", type=float, default=0.5)
    p_train.set_defaults(func=_cmd_train)

    p_scan = sub.add_parser("scan", help="score a JSONL trace against a detector")
    p_scan.add_argument("--model", required=True)
    p_scan.add_argument("--input", required=True, help="JSONL file or '-' for stdin")
    p_scan.add_argument("--llm", action="store_true", help="ask LLM for incident report")
    p_scan.set_defaults(func=_cmd_scan)

    p_cap = sub.add_parser("capture", help="(opt-in) run bpftrace -f json")
    p_cap.add_argument("--script", required=True, help="bpftrace one-liner")
    p_cap.set_defaults(func=_cmd_capture)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
