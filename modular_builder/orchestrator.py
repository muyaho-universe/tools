from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from pathlib import Path

from .models import BuildRow
from .profiles import BuildProfile, build_profiles, resolve_artifacts
from .utils import copy_artifacts, parse_commit_hash, run_cmd
from .versioning import release_tags_in_range


@dataclass
class BuildContext:
    output_root: Path
    failures: list[str]
    built_cache: set[tuple[str, str]]


def _log_failure(ctx: BuildContext, row: BuildRow, ref_kind: str, step: str, err: str) -> None:
    one_line = " ".join((err or "").split())
    msg = f"{row.project},{row.cve},{ref_kind},{step} fail"
    if one_line:
        msg = f"{msg} | {one_line}"
    ctx.failures.append(msg)


def _checkout_ref(profile: BuildProfile, ref: str) -> tuple[bool, str]:
    return run_cmd(["git", "checkout", "-f", ref], cwd=profile.repo_dir)


def _ensure_repo(profile: BuildProfile) -> tuple[bool, str]:
    if profile.repo_dir.exists():
        return True, ""
    if not profile.repo_url:
        return False, f"repo path not found and no clone URL: {profile.repo_dir}"
    parent = profile.repo_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    return run_cmd(
        ["git", "clone", "--recursive", profile.repo_url, str(profile.repo_dir)],
        cwd=parent,
        quiet_stdout=False,
    )


def _prepare_build(profile: BuildProfile, env: dict[str, str]) -> tuple[bool, str]:
    configure_path = profile.repo_dir / "configure"
    for step in profile.pre_steps:
        if step and step[0].endswith("autogen.sh") and configure_path.exists():
            continue
        ok, err = run_cmd(step, cwd=profile.repo_dir, env=env)
        if not ok:
            return False, err
    return True, ""


def _build_once(profile: BuildProfile, row: BuildRow, ref: str, ref_kind: str, ctx: BuildContext) -> list[Path]:
    cache_key = (profile.name, ref)
    cache_dir = ctx.output_root / "_cache" / profile.name / ref
    if cache_key in ctx.built_cache and cache_dir.exists():
        return [p for p in cache_dir.iterdir() if p.is_file()]

    env = os.environ.copy()
    env.update(profile.env_overrides)

    ok, err = _checkout_ref(profile, ref)
    if not ok:
        _log_failure(ctx, row, ref_kind, "checkout", err)
        return []

    ok, err = _prepare_build(profile, env)
    if not ok:
        _log_failure(ctx, row, ref_kind, "pre_step", err)
        return []

    if profile.configure_cmd:
        ok, err = run_cmd(profile.configure_cmd, cwd=profile.repo_dir, env=env)
        if not ok:
            _log_failure(ctx, row, ref_kind, "configure", err)
            return []

    build_cmd = list(profile.build_cmd)
    if build_cmd == ["make"]:
        jobs = max(1, os.cpu_count() or 1)
        build_cmd.append(f"-j{jobs}")
    ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=env)
    if not ok:
        _log_failure(ctx, row, ref_kind, "build", err)
        return []

    artifacts = resolve_artifacts(profile, row)
    if not artifacts:
        _log_failure(ctx, row, ref_kind, "artifact", "artifact not found")
        return []

    copied = copy_artifacts(artifacts, cache_dir, f"{profile.name}_{ref_kind}_{ref}")
    if not copied and cache_dir.exists():
        copied = [p for p in cache_dir.iterdir() if p.is_file()]
    ctx.built_cache.add(cache_key)
    run_cmd(profile.clean_cmd, cwd=profile.repo_dir, env=env)
    return copied


def _emit_row_outputs(ctx: BuildContext, row: BuildRow, ref_kind: str, ref: str, cache_files: list[Path]) -> None:
    out_dir = ctx.output_root / row.project / row.cve / ref_kind
    short_ref = ref[:12]
    prefix = f"{row.cve}_{ref_kind}_{short_ref}"
    copy_artifacts(cache_files, out_dir, prefix)


def _process_commits(profile: BuildProfile, row: BuildRow, ctx: BuildContext) -> None:
    for kind, raw_ref in row.commit_refs():
        ref = parse_commit_hash(raw_ref)
        if not ref:
            _log_failure(ctx, row, kind, "parse_ref", "empty ref")
            continue
        cache_files = _build_once(profile, row, ref, kind, ctx)
        if cache_files:
            _emit_row_outputs(ctx, row, kind, ref, cache_files)


def _process_releases(profile: BuildProfile, row: BuildRow, ctx: BuildContext) -> None:
    window = row.release_window()
    if not window:
        return
    start, end = window
    try:
        tags = release_tags_in_range(profile.repo_dir, start, end)
    except Exception as exc:
        _log_failure(ctx, row, "release_range", "tag_scan", str(exc))
        return

    for tag in tags:
        ref = tag.tag
        kind = f"release_{tag.version_text}"
        cache_files = _build_once(profile, row, ref, kind, ctx)
        if cache_files:
            _emit_row_outputs(ctx, row, kind, ref, cache_files)


def run_pipeline(
    csv_path: str,
    output_root: str,
    only_project: str = "",
    mode: str = "all",
    clone_missing: bool = True,
) -> list[str]:
    profiles = build_profiles()
    ctx = BuildContext(output_root=Path(output_root), failures=[], built_cache=set())
    ctx.output_root.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            row = BuildRow.from_csv_row(raw)
            if not row.project:
                continue
            if only_project and row.project != only_project:
                continue

            profile = profiles.get(row.project)
            if not profile:
                _log_failure(ctx, row, "profile", "resolve", "unsupported project profile")
                continue
            if not profile.repo_dir.exists():
                if not clone_missing:
                    _log_failure(ctx, row, "profile", "repo_dir", f"repo path not found: {profile.repo_dir}")
                    continue
                ok, err = _ensure_repo(profile)
                if not ok:
                    _log_failure(ctx, row, "profile", "clone", err)
                    continue

            if mode in {"all", "commits"}:
                _process_commits(profile, row, ctx)
            if mode in {"all", "releases"}:
                _process_releases(profile, row, ctx)

    return ctx.failures
