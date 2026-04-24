#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SHARED_LIBRARY_PROJECTS = {
    "openssl",
    "libxml2",
    "freetype",
    "expat",
    "libtiff",
}

FALLBACK_TOKENS = (
    "dwg2dxf fallback binary",
    "openvpn fallback binary",
    "freetype_dummy_symbol",
    "expat_dummy_symbol",
)


def run(cmd: list[str]) -> int:
    print(f"[cmd] {' '.join(cmd)}")
    proc = subprocess.run(cmd, check=False)
    print(f"[done] rc={proc.returncode}")
    return proc.returncode


def run_capture(cmd: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return False, ""
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    return proc.returncode == 0, out if out else err


def verify_non_shared_project(output_root: str, project: str, min_size_kb: int, show: int) -> int:
    proj_dir = Path(output_root).expanduser().resolve() / project
    if not proj_dir.exists():
        print(f"[result] FAIL: project output directory missing: {proj_dir}")
        return 2

    files = [p for p in proj_dir.rglob("*") if p.is_file()]
    if not files:
        print(f"[result] FAIL: no files found under {proj_dir}")
        return 2

    elf_execs: list[Path] = []
    too_small: list[Path] = []
    has_fallback: list[Path] = []
    for p in files:
        ok, desc = run_capture(["file", "-b", str(p)])
        if not ok:
            continue
        low = desc.lower()
        if "elf" in low and "executable" in low:
            elf_execs.append(p)
            if p.stat().st_size < max(1, min_size_kb) * 1024:
                too_small.append(p)
            ok2, text = run_capture(["strings", "-a", str(p)])
            if ok2:
                t = text.lower()
                if any(tok in t for tok in FALLBACK_TOKENS):
                    has_fallback.append(p)

    if not elf_execs:
        print(f"[result] FAIL: no ELF executables found under {proj_dir}")
        return 2

    print(f"[summary] project={project} elf_executables={len(elf_execs)}")
    for p in elf_execs[: max(0, show)]:
        print(f"  - {p} ({p.stat().st_size} bytes)")
    if len(elf_execs) > show:
        print(f"  ... and {len(elf_execs) - show} more")

    failed = False
    if too_small:
        failed = True
        print(f"[warn] too-small executables: {len(too_small)}")
        for p in too_small[:10]:
            print(f"  - {p}")
    if has_fallback:
        failed = True
        print(f"[warn] fallback/dummy markers found: {len(has_fallback)}")
        for p in has_fallback[:10]:
            print(f"  - {p}")

    if failed:
        print("[result] FAIL: suspicious executable artifacts detected")
        return 1
    print("[result] PASS: executable artifacts look real")
    return 0


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

    if args.project in SHARED_LIBRARY_PROJECTS:
        rc_kind = run(
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
    else:
        rc_kind = verify_non_shared_project(
            output_root=args.output,
            project=args.project,
            min_size_kb=args.min_size_kb,
            show=args.show,
        )

    if rc_all == 0 and rc_kind == 0:
        print("[result] PASS: project outputs look complete and real")
        return 0
    print("[result] FAIL: project outputs need attention")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
