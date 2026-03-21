from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .utils import run_cmd


@dataclass(frozen=True)
class TagVersion:
    tag: str
    version_text: str
    key: tuple


_VERSION_RE = re.compile(
    r"(?i)(?:^|[^0-9a-z])(?:[vn][._-]*)?(\d+(?:[._-]\d+)+(?:[a-z])?)(?:$|[^0-9a-z])"
)


def _normalize_text(text: str) -> str:
    t = (text or "").strip()
    t = t.replace("_", ".").replace("-", ".")
    t = re.sub(r"^[vn][._-]*", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\.+", ".", t).strip(".")
    return t


def version_key(text: str) -> tuple:
    clean = _normalize_text(text).lower()
    parts = re.findall(r"\d+|[a-z]+", clean)
    key: list[tuple[int, int | str]] = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return tuple(key)


def extract_version_from_tag(tag: str) -> str:
    clean = tag.replace("_", ".")
    m = _VERSION_RE.search(clean)
    if not m:
        nums = re.findall(r"\d+", tag)
        if len(nums) >= 2:
            return ".".join(nums)
        return ""
    return _normalize_text(m.group(1))


def _is_prerelease(tag: str) -> bool:
    lower = tag.lower()
    bad = ("rc", "alpha", "beta", "pre", "start_of", "branched")
    return any(token in lower for token in bad)


def release_tags_in_range(repo_dir: Path, start: str, end: str) -> list[TagVersion]:
    if not start or not end:
        return []

    ok, err = run_cmd(["git", "fetch", "--tags", "--force"], cwd=repo_dir)
    if not ok:
        _ = err

    tags_result = subprocess.run(
        ["git", "tag", "--list"],
        cwd=str(repo_dir),
        text=True,
        capture_output=True,
        check=False,
    )
    if tags_result.returncode != 0:
        raise RuntimeError((tags_result.stderr or "failed to list tags").strip())
    tags_text = tags_result.stdout

    start_key = version_key(start)
    end_key = version_key(end)
    candidates: dict[str, TagVersion] = {}

    for tag in [line.strip() for line in tags_text.splitlines() if line.strip()]:
        if _is_prerelease(tag):
            continue
        ver = extract_version_from_tag(tag)
        if not ver:
            continue
        key = version_key(ver)
        if start_key <= key <= end_key:
            existing = candidates.get(ver)
            current = TagVersion(tag=tag, version_text=ver, key=key)
            if not existing:
                candidates[ver] = current
                continue
            if len(tag) < len(existing.tag):
                candidates[ver] = current

    return sorted(candidates.values(), key=lambda x: x.key)
