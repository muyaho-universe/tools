#!/usr/bin/env python3
import csv
import math
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple, Dict

CSV_PATH = Path("/home/user/tools/tcpdump_version.csv")
REPO_PATH = Path("/home/user/tcpdump")
OUTPUT_PATH = Path("/home/user/tools/tcpdump_version_filled.csv")

GITHUB_COMMIT_PREFIX = "https://github.com/the-tcpdump-group/tcpdump/commit/"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
RELEASE_TAG_RE = re.compile(r"^tcpdump-(\d+)\.(\d+)(?:\.(\d+))?([.-].*)?$")


def run_git(args: List[str], check: bool = True) -> str:
    cmd = ["git", "-C", str(REPO_PATH)] + args
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout.strip()


def git_lines(args: List[str], check: bool = True) -> List[str]:
    out = run_git(args, check=check)
    return out.splitlines() if out else []


def normalize_cve(value: str) -> Optional[str]:
    if not value:
        return None
    m = CVE_RE.search(str(value))
    return m.group(0) if m else None


def is_empty(value) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    s = str(value).strip()
    return s == "" or s.lower() == "nan"


def to_commit_url(sha: str) -> str:
    return GITHUB_COMMIT_PREFIX + sha


def extract_sha(value: str) -> Optional[str]:
    if not value:
        return None
    m = SHA_RE.search(str(value))
    return m.group(0) if m else None


def list_release_tags() -> List[str]:
    tags = git_lines(["tag", "--list", "tcpdump-*"], check=False)
    return [t.strip() for t in tags if t.strip()]


def parse_release_tag(tag: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Returns (major, minor, patch, suffix)
    Example:
      tcpdump-4.99.6 -> (4, 99, 6, "")
      tcpdump-4.99-bp -> (4, 99, 0, "-bp")
      tcpdump-4.9.1 -> (4, 9, 1, "")
    """
    m = RELEASE_TAG_RE.match(tag)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3) or 0)
    suffix = m.group(4) or ""
    return (major, minor, patch, suffix)


def sort_release_tags(tags: List[str]) -> List[str]:
    def key(tag: str):
        parsed = parse_release_tag(tag)
        if parsed is None:
            return (9999, 9999, 9999, "zzz", tag)
        return (*parsed, tag)
    return sorted(tags, key=key)


ALL_RELEASE_TAGS = sort_release_tags(list_release_tags())


def tags_containing(commit: str) -> List[str]:
    return sort_release_tags(git_lines(["tag", "--contains", commit], check=False))


def parent_commit(commit: str) -> Optional[str]:
    parents = git_lines(["rev-list", "--parents", "-n", "1", commit], check=False)
    if not parents:
        return None
    parts = parents[0].split()
    if len(parts) < 2:
        return None
    # first parent
    return parts[1]


def commit_subject(commit: str) -> str:
    return run_git(["show", "-s", "--format=%s", commit], check=False)


def commit_touches_file(commit: str, file_name: str) -> bool:
    if is_empty(file_name):
        return False
    files = git_lines(["show", "--name-only", "--format=", commit], check=False)
    target = str(file_name).strip()
    for f in files:
        if f.strip() == target:
            return True
    return False


def score_candidate(commit: str, row_file: str, row_func: str, cve: str) -> Tuple[int, int, int]:
    """
    Higher is better.
    Priority:
      1) touches target file
      2) contains 4.99-related release tags
      3) exact CVE appears in subject
    """
    tags = tags_containing(commit)
    touches = 1 if commit_touches_file(commit, row_file) else 0
    has_499 = 1 if any(t.startswith("tcpdump-4.99") for t in tags) else 0
    subj = commit_subject(commit)
    exact_cve = 1 if cve in subj else 0
    return (touches, has_499, exact_cve)


def find_patch_commit(cve: str, row_file: str, row_func: str) -> Optional[str]:
    """
    Main strategy:
      - search all commits whose subject matches the CVE
      - prefer commits touching the row's file
      - prefer commits contained in 4.99 tags
    """
    lines = git_lines(
        ["log", "--all", "--format=%H\t%s", f"--grep={cve}"],
        check=False,
    )

    candidates = []
    for line in lines:
        if "\t" not in line:
            continue
        sha, subj = line.split("\t", 1)
        candidates.append((sha, subj))

    if not candidates:
        return None

    ranked = sorted(
        candidates,
        key=lambda x: score_candidate(x[0], row_file, row_func, cve),
        reverse=True,
    )

    return ranked[0][0]


def release_tags_for_affected(ex_patch: str, patch: str) -> List[str]:
    """
    Affected tags = tags that contain ex_patch but do not contain patch.
    """
    ex_tags = set(tags_containing(ex_patch))
    patch_tags = set(tags_containing(patch))
    affected = sorted(ex_tags - patch_tags)
    affected = [t for t in affected if parse_release_tag(t) is not None]
    return sort_release_tags(affected)


def compress_tags(tags: List[str]) -> str:
    """
    Conservative formatter:
      - if nothing, return ""
      - if one, return version only
      - if multiple, return comma-separated versions
    """
    if not tags:
        return ""
    versions = [t.replace("tcpdump-", "") for t in tags]
    return ", ".join(versions)


def infer_bic_from_file(file_path: str) -> Optional[str]:
    """
    Very rough heuristic:
      - find oldest commit in file history
      - map that commit to the earliest release tag containing it
    """
    if is_empty(file_path):
        return None

    file_path = str(file_path).strip()
    commits = git_lines(["log", "--follow", "--format=%H", "--", file_path], check=False)
    if not commits:
        return None

    oldest = commits[-1]
    tags = tags_containing(oldest)
    tags = [t for t in tags if parse_release_tag(t) is not None]
    tags = sort_release_tags(tags)
    if not tags:
        return None
    return tags[0].replace("tcpdump-", "")


def process_csv():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found: {CSV_PATH}")
    if not REPO_PATH.exists():
        raise FileNotFoundError(f"Repo not found: {REPO_PATH}")

    with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    extra_cols = ["Auto note"]
    for col in extra_cols:
        if col not in fieldnames:
            fieldnames.append(col)

    for row in rows:
        cve = normalize_cve(row.get("CVE", ""))
        row_file = row.get("File", "")
        row_func = row.get("Function", "")

        if not cve:
            row["Auto note"] = "skip: invalid CVE"
            continue

        notes = [cve]

        # 1) patch commit 찾기
        patch = find_patch_commit(cve, row_file, row_func)
        if not patch:
            row["Auto note"] = f"{cve}: patch commit not found"
            continue

        # 2) ex-patch = patch의 부모
        ex_patch = parent_commit(patch)
        if not ex_patch:
            row["Auto note"] = f"{cve}: patch commit found but parent commit not found"
            continue

        # 3) CSV 갱신
        row["Patch commit"] = to_commit_url(patch)
        row["Ex-patch commit"] = to_commit_url(ex_patch)

        # 4) affected 계산
        affected_tags = release_tags_for_affected(ex_patch, patch)
        row["Affected"] = compress_tags(affected_tags)

        # 5) BIC는 비어 있을 때만 heuristic
        if is_empty(row.get("BIC", "")):
            bic = infer_bic_from_file(row_file)
            if bic:
                row["BIC"] = bic
                notes.append(f"BIC heuristic={bic}")

        notes.append(f"patch={patch}")
        notes.append(f"ex_patch={ex_patch}")

        patch_tags = tags_containing(patch)
        ex_tags = tags_containing(ex_patch)

        patch_tags_short = [t.replace("tcpdump-", "") for t in patch_tags[:8]]
        ex_tags_short = [t.replace("tcpdump-", "") for t in ex_tags[:8]]

        if patch_tags_short:
            notes.append("patch_tags=" + ",".join(patch_tags_short))
        if ex_tags_short:
            notes.append("ex_patch_tags=" + ",".join(ex_tags_short))

        if affected_tags:
            notes.append("affected_tags=" + ",".join(t.replace("tcpdump-", "") for t in affected_tags))
        else:
            notes.append("affected_tags=<none>")

        row["Auto note"] = " | ".join(notes)

    with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    process_csv()