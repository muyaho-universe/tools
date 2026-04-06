#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import subprocess
from pathlib import Path


PROJECT_REPOS: dict[str, str] = {
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


def parse_commit_hash(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "/commit/" in text:
        text = text.split("/commit/", 1)[1]
    text = text.rstrip("/")
    text = text.split("/")[-1]
    text = text.split("?")[0]
    text = text.split("#")[0]
    return text.strip()


def git_show(repo_dir: Path, commit_hash: str) -> tuple[bool, str]:
    res = subprocess.run(
        ["git", "show", "--no-color", "--format=", commit_hash],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return False, (res.stderr or res.stdout or "").strip()
    return True, res.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Patch commit diffs into diff/{CVE}.diff")
    parser.add_argument("--csv", default="all_in_one.csv", help="CSV path")
    parser.add_argument("--out-dir", default="diff", help="Output directory")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing diff files")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not csv_path.exists():
        print(f"[error] csv not found: {csv_path}")
        return 2

    rows: list[dict[str, str]]
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    written = 0
    skipped = 0
    failed = 0
    seen_cve: set[str] = set()

    for row in rows:
        project = (row.get("Project") or "").strip()
        cve = (row.get("CVE") or "").strip()
        patch_ref = (row.get("Patch commit") or "").strip()

        if not project or not cve or not patch_ref:
            skipped += 1
            continue
        if cve in seen_cve:
            skipped += 1
            continue
        seen_cve.add(cve)

        repo_raw = PROJECT_REPOS.get(project, "")
        repo_dir = Path(repo_raw) if repo_raw else Path("")
        if not repo_raw or not repo_dir.exists():
            failed += 1
            print(f"[fail] {cve}: repo not found for project={project} ({repo_dir})")
            continue

        commit_hash = parse_commit_hash(patch_ref)
        if not commit_hash:
            failed += 1
            print(f"[fail] {cve}: invalid Patch commit ({patch_ref})")
            continue

        ok, out = git_show(repo_dir, commit_hash)
        if not ok:
            failed += 1
            print(f"[fail] {cve}: git show failed in {repo_dir} ({commit_hash})")
            print(f"       {out}")
            continue

        dst = out_dir / f"{cve}.diff"
        if dst.exists() and not args.overwrite:
            skipped += 1
            print(f"[skip] exists: {dst}")
            continue

        dst.write_text(out, encoding="utf-8")
        written += 1
        print(f"[ok] {cve} -> {dst}")

    print(f"[done] written={written} skipped={skipped} failed={failed} out_dir={out_dir.resolve()}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
