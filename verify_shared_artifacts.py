#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Iterable


FALLBACK_SYMBOL_TOKENS = (
    "freetype_dummy_symbol",
    "expat_dummy_symbol",
    "__binforge_liblouis_brlcheck_dummy",
)


def run_capture(cmd: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return False, ""
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    return proc.returncode == 0, out if out else err


def iter_files(root: Path, project: str) -> Iterable[Path]:
    target = root / project if project else root
    if not target.exists():
        return []
    return [p for p in target.rglob("*") if p.is_file()]


def is_elf_shared(path: Path) -> bool:
    ok, desc = run_capture(["file", "-b", str(path)])
    if not ok:
        return False
    low = desc.lower()
    return ("elf" in low) and ("shared object" in low)


def has_dummy_marker(path: Path) -> bool:
    # Symbol-level scan only: avoids false positives from generic words
    # like "dummy" or "fallback" appearing in legitimate binaries.
    ok, syms = run_capture(["nm", "-D", "--defined-only", str(path)])
    if ok:
        low = syms.lower()
        if any(tok in low for tok in FALLBACK_SYMBOL_TOKENS):
            return True
    # Fallback for stripped binaries where dynamic symbols may be absent.
    ok, text = run_capture(["strings", "-a", str(path)])
    if ok:
        low = text.lower()
        if any(tok in low for tok in FALLBACK_SYMBOL_TOKENS):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify produced shared libraries are real ELF .so artifacts (not fallback/dummy)."
    )
    ap.add_argument("--output", required=True, help="Output root, e.g. /home/user/tools/all_in_one_pie")
    ap.add_argument("--project", default="openssl", help="Project folder under output (default: openssl)")
    ap.add_argument("--min-size-kb", type=int, default=50, help="Minimum size to consider non-trivial shared object")
    ap.add_argument("--show", type=int, default=30, help="How many artifacts to print")
    args = ap.parse_args()

    root = Path(args.output).expanduser().resolve()
    files = list(iter_files(root, args.project))
    if not files:
        print(f"[result] FAIL: no files found under {root / args.project}")
        return 2

    shared = [p for p in files if is_elf_shared(p)]
    if not shared:
        print(f"[result] FAIL: no ELF shared objects found under {root / args.project}")
        return 2

    bad_dummy: list[Path] = []
    bad_size: list[Path] = []
    for so in shared:
        if so.stat().st_size < max(1, args.min_size_kb) * 1024:
            bad_size.append(so)
        if has_dummy_marker(so):
            bad_dummy.append(so)

    print(f"[summary] project={args.project} shared_objects={len(shared)}")
    for p in shared[: max(0, args.show)]:
        print(f"  - {p} ({p.stat().st_size} bytes)")
    if len(shared) > args.show:
        print(f"  ... and {len(shared) - args.show} more")

    failed = False
    if bad_size:
        failed = True
        print(f"[warn] too-small shared objects: {len(bad_size)}")
        for p in bad_size[:10]:
            print(f"  - {p}")
    if bad_dummy:
        failed = True
        print(f"[warn] fallback/dummy markers found: {len(bad_dummy)}")
        for p in bad_dummy[:10]:
            print(f"  - {p}")

    if failed:
        print("[result] FAIL: suspicious shared library artifacts detected")
        return 1
    print("[result] PASS: shared libraries look real")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
