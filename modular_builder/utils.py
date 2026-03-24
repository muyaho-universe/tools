from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def run_cmd(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    quiet_stdout: bool = True,
) -> tuple[bool, str]:
    cmd_text = " ".join(cmd)
    print(f"[cmd] cwd={cwd} :: {cmd_text}")
    stderr_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as stderr_file:
            stderr_path = stderr_file.name
            try:
                proc = subprocess.Popen(
                    cmd,  # noqa: S603
                    cwd=str(cwd),
                    env=env,
                    text=True,
                    stdout=subprocess.DEVNULL if quiet_stdout else None,
                    stderr=stderr_file,
                )
            except OSError as exc:
                return False, str(exc)

            start = time.time()
            last_log = -1
            while True:
                try:
                    proc.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    elapsed = int(time.time() - start)
                    if elapsed // 10 != last_log:
                        print(f"[running] {elapsed}s :: {cmd_text}")
                        last_log = elapsed // 10

            result_code = proc.returncode or 0
            elapsed = int(time.time() - start)
            print(f"[done] rc={result_code} elapsed={elapsed}s :: {cmd_text}")

        stderr_text = ""
        if stderr_path and os.path.exists(stderr_path):
            try:
                with open(stderr_path, "r", encoding="utf-8", errors="ignore") as f:
                    stderr_text = f.read() or ""
            except OSError:
                stderr_text = ""
    finally:
        if stderr_path and os.path.exists(stderr_path):
            try:
                os.remove(stderr_path)
            except OSError:
                pass

    if result_code != 0:
        err = stderr_text.strip()
        if err:
            print("[stderr]")
            print(err)
        else:
            print("[stderr] <empty>")
        return False, err
    return True, ""


def parse_commit_hash(ref_or_url: str) -> str:
    text = (ref_or_url or "").strip()
    if not text:
        return ""
    found = re.findall(r"[0-9a-fA-F]{7,40}", text)
    if found:
        return found[-1]
    return text.split("/")[-1]


def is_real_binary_or_library(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_symlink():
        try:
            target = path.resolve(strict=True)
        except OSError:
            return False
        return is_real_binary_or_library(target)
    if not path.is_file():
        return False

    bad_suffixes = {
        ".1",
        ".3",
        ".5",
        ".7",
        ".8",
        ".txt",
        ".md",
        ".in",
        ".pc",
        ".la",
    }
    if path.suffix.lower() in bad_suffixes:
        return False

    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        desc = (result.stdout or "").lower()
    except OSError:
        return path.suffix in {".a", ".so"} or os.access(path, os.X_OK)

    if "elf" in desc:
        return True
    if "current ar archive" in desc:
        return True
    if "mach-o" in desc:
        return True
    if "pe32" in desc:
        return True
    return False


def copy_artifacts(artifacts: list[Path], out_dir: Path, name_prefix: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for idx, src in enumerate(artifacts, start=1):
        base = src.name
        out_name = f"{name_prefix}_{idx}_{base}" if len(artifacts) > 1 else f"{name_prefix}_{base}"
        dst = out_dir / out_name
        if dst.exists():
            continue
        shutil.copy2(src, dst)
        copied.append(dst)
    return copied
