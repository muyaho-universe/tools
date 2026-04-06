#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


PROJECT_REPOS: Dict[str, str] = {
    "openssl": os.getenv("OPENSSL_DIR", "/home/user/openssl"),
    "tcpdump": os.getenv("TCPDUMP_DIR", "/home/user/tcpdump"),
    "libxml2": os.getenv("LIBXML2_DIR", "/home/user/libxml2"),
    "freetype": os.getenv("FREETYPE_DIR", "/home/user/freetype"),
    "expat": os.getenv("EXPAT_DIR", "/home/user/libexpat/expat"),
    "openvpn": os.getenv("OPENVPN_DIR", "/home/user/openvpn"),
    "lou_trace": os.getenv("LIBLOUIS_DIR", "/home/user/liblouis"),
    "lou_checktable": os.getenv("LIBLOUIS_DIR", "/home/user/liblouis"),
    "lou_translate": os.getenv("LIBLOUIS_DIR", "/home/user/liblouis"),
    "libtiff": os.getenv("LIBTIFF_DIR", "/home/user/libtiff"),
    "pcf2bdf": os.getenv("PCF2BDF_DIR", "/home/user/pcf2bdf"),
    "dwg2dxf": os.getenv("LIBREDWG_DIR", "/home/user/libredwg"),
    "exiv2": os.getenv("EXIV2_DIR", "/home/user/exiv2"),
    "FFmpeg": os.getenv("FFMPEG_DIR", "/home/user/FFmpeg"),
}

VERSION_RE = re.compile(
    r"(?i)(?:^|[^0-9a-z])(?:[vn][._-]*)?(\d+(?:[._-]\d+)+(?:[a-z])?)(?:$|[^0-9a-z])"
)
PRERELEASE_TOKENS = ("rc", "alpha", "beta", "pre", "start_of", "branched")


def normalize_version(text: str) -> str:
    t = (text or "").strip().replace("_", ".").replace("-", ".")
    t = re.sub(r"^[vn][._-]*", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\.+", ".", t).strip(".")
    return t


def version_key(text: str) -> Tuple:
    clean = normalize_version(text).lower()
    parts = re.findall(r"\d+|[a-z]+", clean)
    out = []
    for p in parts:
        if p.isdigit():
            out.append((0, int(p)))
        else:
            out.append((1, p))
    return tuple(out)


def extract_version_from_tag(tag: str) -> str:
    clean = tag.replace("_", ".")
    m = VERSION_RE.search(clean)
    if m:
        return normalize_version(m.group(1))
    nums = re.findall(r"\d+", tag)
    return ".".join(nums) if len(nums) >= 2 else ""


def is_prerelease(tag: str) -> bool:
    low = tag.lower()
    return any(tok in low for tok in PRERELEASE_TOKENS)


def release_tags_in_range(repo_dir: Path, start: str, end: str) -> List[str]:
    if not start or not end:
        return []
    if not repo_dir.exists():
        return []

    subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--tags", "--force"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "tag", "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return []

    start_key = version_key(start)
    end_key = version_key(end)
    picked: Dict[str, str] = {}
    for tag in [x.strip() for x in res.stdout.splitlines() if x.strip()]:
        if is_prerelease(tag):
            continue
        ver = extract_version_from_tag(tag)
        if not ver:
            continue
        key = version_key(ver)
        if start_key <= key <= end_key:
            prev = picked.get(ver)
            if prev is None or len(tag) < len(prev):
                picked[ver] = tag
    return sorted(picked.keys(), key=version_key)


def release_variants_for_project(project: str) -> Iterable[Tuple[str, str]]:
    opts = ("O0", "O1", "O2", "O3")
    comps = ("gcc", "clang")
    for comp in comps:
        for opt in opts:
            yield comp, opt


def parse_csv_rows(csv_path: Path) -> List[dict]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    p = argparse.ArgumentParser(description="Verify completeness of all_in_one output files.")
    p.add_argument("--csv", default="all_in_one.csv", help="Input CSV path")
    p.add_argument("--output", default="/home/user/all_in_one", help="Output root directory")
    p.add_argument("--arch", default=os.getenv("TARGET_ARCH", "x86"), help="Architecture token in output names")
    p.add_argument("--only-project", default="", help="Verify only one project")
    p.add_argument("--scope", choices=["all", "commits", "releases"], default="all", help="Expected output scope")
    p.add_argument("--show-missing", type=int, default=20, help="How many missing samples to print")
    args = p.parse_args()

    csv_path = Path(args.csv)
    out_root = Path(args.output)
    if not out_root.exists():
        print(f"[result] FAIL: output directory does not exist: {out_root}")
        print("[hint] Run this script in the same environment where artifacts were generated,")
        print("       or pass the real copied path with --output.")
        return 2

    rows = parse_csv_rows(csv_path)

    expected_commit: Dict[str, Set[str]] = defaultdict(set)
    expected_release: Dict[str, Set[Tuple[str, str, str, str]]] = defaultdict(set)

    for row in rows:
        project = (row.get("Project") or "").strip()
        if not project:
            continue
        if args.only_project and project != args.only_project:
            continue

        cve = (row.get("CVE") or "").strip()
        patch_commit = (row.get("Patch commit") or "").strip()
        ex_patch_commit = (row.get("Ex-patch commit") or "").strip()
        if patch_commit and args.scope in {"all", "commits"}:
            expected_commit[project].add(f"{cve}_patch_gcc_O0")
        if ex_patch_commit and args.scope in {"all", "commits"}:
            expected_commit[project].add(f"{cve}_vuln_gcc_O0")

        bug_start = (row.get("Bug start") or "").strip()
        patch_end = (row.get("Patch end") or "").strip()
        if bug_start and patch_end and args.scope in {"all", "releases"}:
            repo = Path(PROJECT_REPOS.get(project, ""))
            versions = release_tags_in_range(repo, bug_start, patch_end)
            for ver in versions:
                for comp, opt in release_variants_for_project(project):
                    expected_release[project].add((project, ver, opt, comp))

    total_expected = 0
    total_missing = 0
    missing_lines: List[str] = []

    projects = sorted(set(expected_commit.keys()) | set(expected_release.keys()))
    for project in projects:
        proj_dir = out_root / project
        names = [p.name for p in proj_dir.iterdir() if p.is_file()] if proj_dir.exists() else []
        name_set = set(names)

        # Commit outputs: exact names
        for expected in sorted(expected_commit.get(project, set())):
            total_expected += 1
            if expected not in name_set:
                total_missing += 1
                missing_lines.append(f"{project} :: missing commit output :: {expected}")

        # Release outputs: artifact prefix is variable, so check by suffix token.
        for proj, ver, opt, comp in sorted(expected_release.get(project, set())):
            total_expected += 1
            suffix = f"_{proj}-{ver}_{opt}_{args.arch}_{comp}"
            if not any(suffix in fname for fname in names):
                total_missing += 1
                missing_lines.append(f"{project} :: missing release output :: *{suffix}")

    print(f"[summary] output_root={out_root}")
    print(f"[summary] expected={total_expected} missing={total_missing} present={total_expected - total_missing}")
    if total_missing == 0:
        print("[result] PASS: expected outputs are present")
        return 0

    print("[result] FAIL: missing outputs detected")
    to_show = max(0, args.show_missing)
    for line in missing_lines[:to_show]:
        print(f"  - {line}")
    if len(missing_lines) > to_show:
        print(f"  ... and {len(missing_lines) - to_show} more")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
