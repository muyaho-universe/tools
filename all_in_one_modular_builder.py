from __future__ import annotations

import argparse
from pathlib import Path

from modular_builder import run_pipeline


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build commit and release binaries from all_in_one.csv with project-specific modular profiles."
    )
    p.add_argument("--csv", default="all_in_one.csv", help="Input CSV path")
    p.add_argument("--output", default="/home/user/all_in_one", help="Output directory")
    p.add_argument("--only-project", default="", help="Process only one project name")
    p.add_argument(
        "--mode",
        choices=["all", "commits", "releases"],
        default="all",
        help="Build mode",
    )
    p.add_argument("--no-clone", action="store_true", help="Do not git clone missing project repositories")
    p.add_argument("--fail-log", default="all_in_one_failed_steps.txt", help="Failure log path")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    failures = run_pipeline(
        csv_path=args.csv,
        output_root=args.output,
        only_project=args.only_project,
        mode=args.mode,
        clone_missing=not args.no_clone,
    )

    fail_log = Path(args.fail_log)
    fail_log.write_text("\n".join(failures) + ("\n" if failures else "No failures\n"), encoding="utf-8")
    print(f"[done] failure log: {fail_log.resolve()}")
    print(f"[done] total failures: {len(failures)}")


if __name__ == "__main__":
    main()
