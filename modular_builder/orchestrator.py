from __future__ import annotations

import csv
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .models import BuildRow
from .profiles import BuildProfile, build_profiles, resolve_artifacts
from .utils import is_real_binary_or_library, parse_commit_hash, run_cmd
from .versioning import release_tags_in_range


@dataclass
class BuildContext:
    output_root: Path
    failures: list[str]
    built_cache: set[tuple[str, str, str]]


@dataclass(frozen=True)
class BuildVariant:
    compiler: str
    opt: str
    env_overrides: dict[str, str]

    @property
    def key(self) -> str:
        return f"{self.compiler}_{self.opt}"


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


def _render_tokens(tokens: list[str], variant: BuildVariant) -> list[str]:
    rendered: list[str] = []
    for token in tokens:
        rendered.append(
            token.format(
                compiler=variant.compiler,
                opt=variant.opt,
            )
        )
    return rendered


def _resolve_artifacts_for_variant(profile: BuildProfile, row: BuildRow, ref_kind: str, variant: BuildVariant) -> list[Path]:
    artifacts = resolve_artifacts(profile, row, ref_kind)
    if artifacts:
        return artifacts

    # fallback: apply variant token replacement for glob-based resolution
    found: list[Path] = []
    for pattern in _render_tokens(profile.artifact_globs, variant):
        for p in sorted(profile.repo_dir.glob(pattern)):
            if p.is_file() and is_real_binary_or_library(p):
                found.append(p)
                break
    return found


def _build_once(
    profile: BuildProfile,
    row: BuildRow,
    ref: str,
    ref_kind: str,
    variant: BuildVariant,
    ctx: BuildContext,
) -> list[Path]:
    print(
        f"[build-start] project={profile.name} cve={row.cve} ref_kind={ref_kind} "
        f"ref={ref} variant={variant.key}"
    )
    cache_key = (profile.name, ref, variant.key)
    cache_dir = ctx.output_root / "_cache" / profile.name / ref / variant.key
    if cache_key in ctx.built_cache and cache_dir.exists():
        print(f"[cache-hit] project={profile.name} ref={ref} variant={variant.key}")
        return [p for p in cache_dir.iterdir() if p.is_file()]

    env = os.environ.copy()
    env.update(profile.env_overrides)
    env.update(variant.env_overrides)

    ok, err = _checkout_ref(profile, ref)
    if not ok:
        _log_failure(ctx, row, ref_kind, "checkout", err)
        return []

    ok, err = _prepare_build(profile, env)
    if not ok:
        _log_failure(ctx, row, ref_kind, "pre_step", err)
        return []

    if profile.configure_cmd:
        configure_cmd = _render_tokens(profile.configure_cmd, variant)
        ok, err = run_cmd(configure_cmd, cwd=profile.repo_dir, env=env)
        if not ok:
            _log_failure(ctx, row, ref_kind, "configure", err)
            return []

    build_cmd = _render_tokens(profile.build_cmd, variant)
    if build_cmd == ["make"]:
        jobs = max(1, os.cpu_count() or 1)
        build_cmd.append(f"-j{jobs}")
    ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=env)
    if not ok:
        _log_failure(ctx, row, ref_kind, "build", err)
        return []

    artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
    if not artifacts:
        _log_failure(ctx, row, ref_kind, "artifact", "artifact not found")
        return []

    cache_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for artifact in artifacts:
        dst = cache_dir / artifact.name
        if dst.exists():
            copied.append(dst)
            continue
        shutil.copy2(artifact, dst)
        copied.append(dst)
    if not copied and cache_dir.exists():
        copied = [p for p in cache_dir.iterdir() if p.is_file()]
    ctx.built_cache.add(cache_key)
    run_cmd(_render_tokens(profile.clean_cmd, variant), cwd=profile.repo_dir, env=env)
    print(
        f"[build-done] project={profile.name} cve={row.cve} ref_kind={ref_kind} "
        f"ref={ref} variant={variant.key} artifacts={len(copied)}"
    )
    return copied


def _default_variant(profile: BuildProfile) -> BuildVariant:
    flags = " ".join([profile.env_overrides.get("CFLAGS", ""), profile.env_overrides.get("CXXFLAGS", "")])
    m = re.search(r"-O([0-3sz])", flags)
    opt = f"O{m.group(1)}" if m else "O0"
    cc = (profile.env_overrides.get("CC") or "").lower()
    compiler = "clang" if "clang" in cc else "gcc"
    return BuildVariant(compiler=compiler, opt=opt, env_overrides={})


def _release_variants() -> list[BuildVariant]:
    gcc = os.getenv("GCC_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc")
    gpp = os.getenv("GPP_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++")
    clang = os.getenv("CLANG_BIN", "/home/user/BinForge/tools/clang/clang-14.0.6/bin/clang")
    clangpp = os.getenv("CLANGPP_BIN", clang + "++" if clang.endswith("clang") else "clang++")

    variants: list[BuildVariant] = []
    for compiler, cc, cxx in [("gcc", gcc, gpp), ("clang", clang, clangpp)]:
        for opt in ["O0", "O1", "O2", "O3"]:
            variants.append(
                BuildVariant(
                    compiler=compiler,
                    opt=opt,
                    env_overrides={
                        "CC": cc,
                        "CXX": cxx,
                        "CFLAGS": f"-{opt}",
                        "CXXFLAGS": f"-{opt}",
                    },
                )
            )
    return variants


def _version_token(ref_kind: str) -> str:
    if ref_kind.startswith("release_"):
        return ref_kind[len("release_") :]
    return ref_kind


def _emit_row_outputs(
    ctx: BuildContext,
    profile: BuildProfile,
    row: BuildRow,
    ref_kind: str,
    variant: BuildVariant,
    cache_files: list[Path],
) -> None:
    out_dir = ctx.output_root / row.project / row.cve / ref_kind
    out_dir.mkdir(parents=True, exist_ok=True)
    opt = variant.opt
    compiler = variant.compiler
    arch = os.getenv("TARGET_ARCH", "x86")
    version = _version_token(ref_kind)
    copied_count = 0

    for idx, src in enumerate(cache_files, start=1):
        artifact_name = src.name
        base_name = f"{artifact_name}_{row.project}-{version}_{opt}_{arch}_{compiler}"
        dst_name = base_name if len(cache_files) == 1 else f"{base_name}_{idx}"
        dst = out_dir / dst_name
        if dst.exists():
            continue
        shutil.copy2(src, dst)
        copied_count += 1

    if copied_count > 0:
        print(f"[out] project={row.project} cve={row.cve} ref_kind={ref_kind} copied={copied_count} -> {out_dir}")
    else:
        print(f"[out-skip] project={row.project} cve={row.cve} ref_kind={ref_kind} (already exists)")


def _process_commits(profile: BuildProfile, row: BuildRow, ctx: BuildContext) -> None:
    variant = _default_variant(profile)
    for kind, raw_ref in row.commit_refs():
        ref = parse_commit_hash(raw_ref)
        if not ref:
            _log_failure(ctx, row, kind, "parse_ref", "empty ref")
            continue
        cache_files = _build_once(profile, row, ref, kind, variant, ctx)
        if cache_files:
            _emit_row_outputs(ctx, profile, row, kind, variant, cache_files)


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
    print(
        f"[release-range] project={row.project} cve={row.cve} "
        f"start={start} end={end} tags={len(tags)}"
    )

    variants = _release_variants()
    print(f"[release-variants] count={len(variants)} (gcc/clang x O0..O3, no -g)")
    for tag in tags:
        ref = tag.tag
        kind = f"release_{tag.version_text}"
        for variant in variants:
            cache_files = _build_once(profile, row, ref, kind, variant, ctx)
            if cache_files:
                _emit_row_outputs(ctx, profile, row, kind, variant, cache_files)


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
            print(f"\n[row] project={row.project} cve={row.cve} file={row.file}")

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
