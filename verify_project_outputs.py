#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> int:
    print(f"[cmd] {' '.join(cmd)}")
    proc = subprocess.run(cmd, check=False)
    print(f"[done] rc={proc.returncode}")
    return proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify project outputs: presence/completeness + real shared library quality."
    )
    ap.add_argument("--csv", default="all_in_one.csv", help="CSV used for build matrix")
    ap.add_argument("--output", required=True, help="Output root, e.g. /home/user/tools/all_in_one_pie")
    ap.add_argument("--project", default="freetype", help="Project name (default: freetype)")
    ap.add_argument("--scope", choices=["all", "commits", "releases"], default="all")
    ap.add_argument("--min-size-kb", type=int, default=50)
    ap.add_argument("--show", type=int, default=20)
    args = ap.parse_args()

    root = Path(__file__).resolve().parent
    verify_all = root / "verify_all_in_one_outputs.py"
    verify_shared = root / "verify_shared_artifacts.py"

    if not verify_all.exists() or not verify_shared.exists():
        print("[result] FAIL: required verifier scripts are missing")
        return 2

    rc_all = run(
        [
            sys.executable,
            str(verify_all),
            "--csv",
            args.csv,
            "--output",
            args.output,
            "--only-project",
            args.project,
            "--scope",
            args.scope,
        ]
    )

    rc_shared = run(
        [
            sys.executable,
            str(verify_shared),
            "--output",
            args.output,
            "--project",
            args.project,
            "--min-size-kb",
            str(args.min_size_kb),
            "--show",
            str(args.show),
        ]
    )

    if rc_all == 0 and rc_shared == 0:
        print("[result] PASS: project outputs look complete and real")
        return 0
    print("[result] FAIL: project outputs need attention")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

