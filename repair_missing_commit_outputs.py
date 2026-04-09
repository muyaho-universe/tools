#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import tempfile
from pathlib import Path


def _read_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _expected_commit_names(row: dict[str, str]) -> list[str]:
    cve = (row.get("CVE") or "").strip()
    expected: list[str] = []
    if (row.get("Patch commit") or "").strip():
        expected.append(f"{cve}_patch_gcc_O0")
    if (row.get("Ex-patch commit") or "").strip():
        expected.append(f"{cve}_vuln_gcc_O0")
    return expected


def _is_row_missing(row: dict[str, str], out_dir: Path) -> bool:
    expected = _expected_commit_names(row)
    if not expected:
        return False
    for name in expected:
        if not (out_dir / name).exists():
            return True
    return False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Repair missing commit outputs (CVE_patch/vuln_gcc_O0) by rebuilding only missing rows."
    )
    p.add_argument("--csv", default="all_in_one.csv", help="Input CSV path")
    p.add_argument("--output", default="all_in_one_old", help="Output root")
    p.add_argument("--project", default="tcpdump", help="Target project name")
    p.add_argument("--no-clone", action="store_true", help="Do not clone missing repositories")
    p.add_argument("--dry-run", action="store_true", help="Only scan and print missing rows")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    csv_path = Path(args.csv)
    out_root = Path(args.output)
    project_dir = out_root / args.project
    project_dir.mkdir(parents=True, exist_ok=True)

    rows = _read_rows(csv_path)
    selected = [r for r in rows if (r.get("Project") or "").strip() == args.project]
    missing_rows = [r for r in selected if _is_row_missing(r, project_dir)]

    print(f"[scan] project={args.project} rows={len(selected)} missing_rows={len(missing_rows)}")
    if not missing_rows:
        print("[result] no missing commit outputs")
        return 0

    fieldnames = list(rows[0].keys()) if rows else []
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", suffix=".csv", delete=False) as tf:
        temp_csv = Path(tf.name)
        writer = csv.DictWriter(tf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(missing_rows)

    print(f"[repair] temporary csv: {temp_csv}")
    if args.dry_run:
        print("[result] dry-run only (no rebuild executed)")
        return 0

    try:
        from modular_builder import run_pipeline
    except Exception as exc:  # pragma: no cover
        print("[error] failed to import modular_builder.run_pipeline")
        print(f"[hint] run this script in the same Python environment used for all_in_one_modular_builder.py ({exc})")
        return 2

    failures = run_pipeline(
        csv_path=str(temp_csv),
        output_root=str(out_root),
        only_project=args.project,
        mode="commits",
        clone_missing=not args.no_clone,
        parallel_workers=1,
    )

    if failures:
        print(f"[result] completed with failures={len(failures)}")
        for line in failures:
            print(f"  - {line}")
        return 1

    print("[result] missing commit outputs repaired successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
