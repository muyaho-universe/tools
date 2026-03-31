from __future__ import annotations

import csv
import os
import re
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock

from .models import BuildRow
from .profiles import BuildProfile, build_profiles, resolve_artifacts
from .utils import is_real_binary_or_library, parse_commit_hash, run_cmd
from .versioning import release_tags_in_range

MAX_FAILURE_LOG_LINES = int(os.getenv("MAX_FAILURE_LOG_LINES", "40"))


@dataclass
class BuildContext:
    output_root: Path
    failures: list[str]
    built_cache: set[tuple[str, str, str]]
    parallel_workers: int
    lock: Lock


@dataclass(frozen=True)
class BuildVariant:
    compiler: str
    opt: str
    env_overrides: dict[str, str]

    @property
    def key(self) -> str:
        return f"{self.compiler}_{self.opt}"


def _log_failure(ctx: BuildContext, row: BuildRow, ref_kind: str, step: str, err: str) -> None:
    err_text = (err or "").strip()
    if err_text:
        lines = [ln for ln in err_text.splitlines() if ln.strip()]
        tail = lines[-MAX_FAILURE_LOG_LINES:] if len(lines) > MAX_FAILURE_LOG_LINES else lines
        one_line = " \\n ".join(tail)
    else:
        one_line = ""
    msg = f"{row.project},{row.cve},{ref_kind},{step} fail"
    if one_line:
        msg = f"{msg} | {one_line}"
    ctx.failures.append(msg)


def _checkout_ref(profile: BuildProfile, ref: str) -> tuple[bool, str]:
    return run_cmd(["git", "checkout", "-f", ref], cwd=profile.repo_dir)


def _hard_clean_repo(profile: BuildProfile) -> None:
    # Different refs in old projects (especially OpenSSL) often leave stale artifacts.
    # Enforce a pristine tree before/after each build attempt.
    run_cmd(["git", "reset", "--hard", "HEAD"], cwd=profile.repo_dir)
    run_cmd(["git", "clean", "-xfd"], cwd=profile.repo_dir)


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
    if profile.name == "openssl":
        ok, err = _patch_openssl_fileglob_issue(profile.repo_dir)
        if not ok:
            return False, err

    configure_path = profile.repo_dir / "configure"
    for step in profile.pre_steps:
        if not step:
            continue
        cmd = list(step)
        first = cmd[0]
        first_path = profile.repo_dir / first

        if first.endswith("autogen.sh") and configure_path.exists():
            continue

        if first.startswith("./") and first.endswith(".sh"):
            if not first_path.exists():
                print(f"[pre-step-skip] missing script: {first} (project={profile.name})")
                continue
            if not os.access(first_path, os.X_OK):
                cmd = ["sh", first]

        ok, err = run_cmd(cmd, cwd=profile.repo_dir, env=env)
        if not ok:
            return False, err
    return True, ""


def _patch_openssl_fileglob_issue(repo_dir: Path) -> tuple[bool, str]:
    targets = [repo_dir / "Configure", repo_dir / "test" / "build.info"]
    pattern = re.compile(r"qw\s*[\(/]\s*:?\s*glob\s*[\)/]")
    changed_any = False

    for path in targets:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)

        if "File::Glob" not in text:
            continue

        new_text = pattern.sub("qw/:glob/", text)
        if new_text != text:
            try:
                path.write_text(new_text, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)

    if changed_any:
        print("[openssl-fix] applied File::Glob compatibility patch")
    return True, ""


def _patch_liblouis_tool_dependency(repo_dir: Path) -> tuple[bool, str]:
    targets = [repo_dir / "tools" / "Makefile", repo_dir / "tools" / "Makefile.in"]
    changed_any = False

    for path in targets:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)

        # Clean up any previously injected stubs to keep this idempotent.
        new_text = text.replace("\n../tools/libbrlcheck.la:\n\t@true\n", "\n")
        new_text = new_text.replace("\n../tools/libbrlcheck.la:\n    @true\n", "\n")
        new_text = new_text.replace("\n\\:\n\t@true\n", "\n")
        new_text = new_text.replace("\n\\:\n    @true\n", "\n")

        needs_libb_stub = "libbrlcheck.la" in new_text
        if not needs_libb_stub and new_text == text:
            continue

        if needs_libb_stub:
            stub = "../tools/libbrlcheck.la:\n\t@true\n\n"
            # Prepend stub so it cannot be captured by a trailing '\' line continuation at EOF.
            new_text = stub + new_text
        try:
            path.write_text(new_text, encoding="utf-8")
            changed_any = True
        except OSError as exc:
            return False, str(exc)

    if changed_any:
        print("[liblouis-fix] patched tools makefile for legacy lou_trace dependency")
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


def _debug_artifact_candidates(profile: BuildProfile, variant: BuildVariant) -> None:
    print(f"[artifact-debug] project={profile.name} variant={variant.key}")
    sample_patterns = ["**/*.so*", "**/*.a", "**/openssl", "**/tcpdump", "**/openvpn", "**/exiv2"]
    shown = 0
    for pattern in sample_patterns:
        for p in sorted(profile.repo_dir.glob(pattern)):
            if not p.is_file():
                continue
            rel = p.relative_to(profile.repo_dir)
            print(f"[artifact-candidate] {rel}")
            shown += 1
            if shown >= 30:
                return


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
    cached_files = [p for p in cache_dir.iterdir() if p.is_file()] if cache_dir.exists() else []
    if cached_files:
        print(f"[cache-hit] project={profile.name} ref={ref} variant={variant.key}")
        return cached_files
    with ctx.lock:
        if cache_key in ctx.built_cache and cache_dir.exists():
            print(f"[cache-hit] project={profile.name} ref={ref} variant={variant.key}")
            return [p for p in cache_dir.iterdir() if p.is_file()]

    env = os.environ.copy()
    env.update(profile.env_overrides)
    env.update(variant.env_overrides)
    openssl_release_mode = profile.name == "openssl" and ref_kind.startswith("release_")

    try:
        _hard_clean_repo(profile)

        ok, err = _checkout_ref(profile, ref)
        if not ok:
            _log_failure(ctx, row, ref_kind, "checkout", err)
            return []

        ok, err = _prepare_build(profile, env)
        if not ok:
            _log_failure(ctx, row, ref_kind, "pre_step", err)
            return []

        if profile.configure_cmd:
            if openssl_release_mode:
                # Old OpenSSL release tags are fragile with shared+asm across toolchains.
                configure_cmd = ["perl", "Configure", "linux-x86_64", "no-shared", "no-asm"]
            else:
                configure_cmd = _render_tokens(profile.configure_cmd, variant)
            ok, err = run_cmd(configure_cmd, cwd=profile.repo_dir, env=env)
            if not ok:
                _log_failure(ctx, row, ref_kind, "configure", err)
                return []
            if profile.name in {"lou_trace", "lou_checktable", "lou_translate"}:
                ok, err = _patch_liblouis_tool_dependency(profile.repo_dir)
                if not ok:
                    _log_failure(ctx, row, ref_kind, "configure_patch", err)
                    return []

        build_cmd = _render_tokens(profile.build_cmd, variant)
        if openssl_release_mode:
            build_cmd = ["make", "build_libs"]
        if build_cmd == ["make"]:
            jobs = max(1, os.cpu_count() or 1)
            if profile.name == "openssl" and variant.compiler == "clang":
                jobs = 1
            build_cmd.append(f"-j{jobs}")
        if build_cmd and build_cmd[0] == "make" and not any(t.startswith("-j") for t in build_cmd[1:]):
            jobs = 1 if (profile.name == "openssl" and variant.compiler == "clang") else max(1, os.cpu_count() or 1)
            build_cmd.append(f"-j{jobs}")
        ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and openssl_release_mode and "No rule to make target" in (err or "") and "build_libs" in (err or ""):
            retry_cmd = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
            print(f"[retry] openssl release build_libs target missing; trying: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "openssl":
            # For old OpenSSL tags, full "make" can fail while library-only target still succeeds.
            jobs = 1 if variant.compiler == "clang" else max(1, os.cpu_count() or 1)
            retry_cmd = ["make", "build_libs", f"-j{jobs}"]
            print(f"[retry] openssl build failed; trying: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name in {"lou_trace", "lou_checktable", "lou_translate"}:
            target_path = f"tools/{profile.name}"
            retry_plan = [
                ["make", target_path],
                ["make", "-C", "tools", profile.name],
            ]
            for retry_cmd in retry_plan:
                print(f"[retry] {profile.name} build failed; trying focused target: {' '.join(retry_cmd)}")
                ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                if ok:
                    break
        if (not ok) and profile.name in {"lou_trace", "lou_checktable", "lou_translate"}:
            err_text = err or ""
            # Some liblouis tags fail a late optional dependency, but the requested tool binary
            # may already be produced; in that case keep going and collect artifacts.
            if "libbrlcheck.la" in err_text and "No rule to make target" in err_text:
                prebuilt = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
                if prebuilt:
                    print(
                        f"[warn] {profile.name} build reported missing libbrlcheck, "
                        f"but artifacts already exist ({len(prebuilt)}); continuing"
                    )
                    ok = True
        if not ok:
            _log_failure(ctx, row, ref_kind, "build", err)
            return []

        artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
        if not artifacts:
            _debug_artifact_candidates(profile, variant)
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
        with ctx.lock:
            ctx.built_cache.add(cache_key)
        print(
            f"[build-done] project={profile.name} cve={row.cve} ref_kind={ref_kind} "
            f"ref={ref} variant={variant.key} artifacts={len(copied)}"
        )
        return copied
    finally:
        run_cmd(_render_tokens(profile.clean_cmd, variant), cwd=profile.repo_dir, env=env)
        _hard_clean_repo(profile)


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
    clang = os.getenv("CLANG_BIN", "/home/user/BinForge/tools/clang/clang-13.0.1/bin/clang")
    clangpp = os.getenv("CLANGPP_BIN", "/home/user/BinForge/tools/clang/clang-13.0.1/bin/clang++")
    llvm_ar = os.getenv("LLVM_AR_BIN", "/usr/bin/llvm-ar")
    llvm_ranlib = os.getenv("LLVM_RANLIB_BIN", "/usr/bin/llvm-ranlib")
    llvm_nm = os.getenv("LLVM_NM_BIN", "/usr/bin/llvm-nm")

    variants: list[BuildVariant] = []
    for compiler, cc, cxx in [("gcc", gcc, gpp), ("clang", clang, clangpp)]:
        for opt in ["O0", "O1", "O2", "O3"]:
            extra: dict[str, str] = {}
            if compiler == "clang":
                # Keep binutils consistent with clang, but only pin tools that actually exist.
                if os.path.isfile(llvm_ar):
                    extra["AR"] = llvm_ar
                elif shutil.which("llvm-ar"):
                    extra["AR"] = "llvm-ar"
                elif shutil.which("ar"):
                    extra["AR"] = "ar"

                if os.path.isfile(llvm_ranlib):
                    extra["RANLIB"] = llvm_ranlib
                elif shutil.which("llvm-ranlib"):
                    extra["RANLIB"] = "llvm-ranlib"
                elif shutil.which("ranlib"):
                    extra["RANLIB"] = "ranlib"

                if os.path.isfile(llvm_nm):
                    extra["NM"] = llvm_nm
                elif shutil.which("llvm-nm"):
                    extra["NM"] = "llvm-nm"
                elif shutil.which("nm"):
                    extra["NM"] = "nm"
            variants.append(
                BuildVariant(
                    compiler=compiler,
                    opt=opt,
                    env_overrides={
                        "CC": cc,
                        "CXX": cxx,
                        "CFLAGS": f"-{opt}",
                        "CXXFLAGS": f"-{opt}",
                        **extra,
                    },
                )
            )
    return variants


def _version_token(ref_kind: str) -> str:
    if ref_kind.startswith("release_"):
        return ref_kind[len("release_") :]
    return ref_kind


def _outputs_already_exist(ctx: BuildContext, row: BuildRow, ref_kind: str, variant: BuildVariant) -> bool:
    out_dir = ctx.output_root / row.project
    if not out_dir.exists():
        return False

    if ref_kind in {"patch", "vuln"}:
        target = f"{row.cve}_{ref_kind}_{variant.compiler}_{variant.opt}"
        return (out_dir / target).exists()

    arch = os.getenv("TARGET_ARCH", "x86")
    version = _version_token(ref_kind)
    suffix = f"_{row.project}-{version}_{variant.opt}_{arch}_{variant.compiler}"
    for p in out_dir.iterdir():
        if p.is_file() and suffix in p.name:
            return True
    return False


def _emit_row_outputs(
    ctx: BuildContext,
    profile: BuildProfile,
    row: BuildRow,
    ref_kind: str,
    variant: BuildVariant,
    cache_files: list[Path],
) -> None:
    out_dir = ctx.output_root / row.project
    out_dir.mkdir(parents=True, exist_ok=True)
    opt = variant.opt
    compiler = variant.compiler
    arch = os.getenv("TARGET_ARCH", "x86")
    version = _version_token(ref_kind)
    copied_count = 0

    files_to_emit = cache_files
    if ref_kind in {"patch", "vuln"} and cache_files:
        # OpenSSL commit output must be chosen by target file domain: crypto vs ssl.
        if profile.name == "openssl":
            preferred = None
            if row.file.startswith("crypto/"):
                preferred = next((p for p in cache_files if ("libcrypto.so" in p.name or p.name == "libcrypto.a")), None)
            elif row.file.startswith("ssl/"):
                preferred = next((p for p in cache_files if ("libssl.so" in p.name or p.name == "libssl.a")), None)

            if preferred is None:
                print(
                    f"[out-skip] project={row.project} cve={row.cve} ref_kind={ref_kind} "
                    f"reason=no matching openssl shared library for file={row.file}"
                )
                return
            files_to_emit = [preferred]
        else:
            files_to_emit = [cache_files[0]]

    for idx, src in enumerate(files_to_emit, start=1):
        if ref_kind in {"patch", "vuln"}:
            base_name = f"{row.cve}_{ref_kind}_{compiler}_{opt}"
        else:
            artifact_name = src.name
            base_name = f"{artifact_name}_{row.project}-{version}_{opt}_{arch}_{compiler}"

        dst_name = base_name if len(files_to_emit) == 1 else f"{base_name}_{idx}"
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
        if _outputs_already_exist(ctx, row, kind, variant):
            print(f"[skip] existing outputs found: project={row.project} cve={row.cve} ref_kind={kind} variant={variant.key}")
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
    if profile.name == "openssl":
        variants = [v for v in variants if v.compiler == "gcc"]
        print("[release-variants] openssl: using gcc-only variants to avoid clang assembler incompatibilities")
    if profile.name == "openssl":
        print(f"[release-variants] count={len(variants)} (gcc x O0..O3, no -g)")
    else:
        print(f"[release-variants] count={len(variants)} (gcc/clang x O0..O3, no -g)")
    tasks: list[tuple[str, str, BuildVariant]] = []
    for tag in tags:
        ref = tag.tag
        kind = f"release_{tag.version_text}"
        for variant in variants:
            if _outputs_already_exist(ctx, row, kind, variant):
                print(
                    f"[skip] existing outputs found: project={row.project} cve={row.cve} "
                    f"ref_kind={kind} variant={variant.key}"
                )
                continue
            tasks.append((ref, kind, variant))

    if ctx.parallel_workers <= 1:
        for ref, kind, variant in tasks:
            cache_files = _build_once(profile, row, ref, kind, variant, ctx)
            if cache_files:
                _emit_row_outputs(ctx, profile, row, kind, variant, cache_files)
        return

    worktree_root = ctx.output_root / "_worktrees"
    with ThreadPoolExecutor(max_workers=ctx.parallel_workers) as ex:
        futures = [
            ex.submit(_build_once_isolated_worktree, profile, row, ref, kind, variant, ctx, worktree_root)
            for ref, kind, variant in tasks
        ]
        for fut in as_completed(futures):
            result = fut.result()
            if not result:
                continue
            kind, variant, cache_files = result
            if cache_files:
                _emit_row_outputs(ctx, profile, row, kind, variant, cache_files)


def _build_once_isolated_worktree(
    profile: BuildProfile,
    row: BuildRow,
    ref: str,
    kind: str,
    variant: BuildVariant,
    ctx: BuildContext,
    worktree_root: Path,
) -> tuple[str, BuildVariant, list[Path]] | None:
    wt_name = f"{profile.name}_{kind}_{variant.key}_{uuid.uuid4().hex[:8]}"
    wt_dir = worktree_root / wt_name
    wt_dir.parent.mkdir(parents=True, exist_ok=True)

    ok, err = run_cmd(
        ["git", "worktree", "add", "--detach", "--force", str(wt_dir), ref],
        cwd=profile.repo_dir,
        quiet_stdout=False,
    )
    if not ok:
        _log_failure(ctx, row, kind, "worktree_add", err)
        return None

    try:
        local_profile = replace(profile, repo_dir=wt_dir)
        cache_files = _build_once(local_profile, row, ref, kind, variant, ctx)
        return kind, variant, cache_files
    finally:
        run_cmd(["git", "worktree", "remove", "--force", str(wt_dir)], cwd=profile.repo_dir, quiet_stdout=False)
        if wt_dir.exists():
            shutil.rmtree(wt_dir, ignore_errors=True)


def run_pipeline(
    csv_path: str,
    output_root: str,
    only_project: str = "",
    mode: str = "all",
    clone_missing: bool = True,
    parallel_workers: int = 1,
) -> list[str]:
    profiles = build_profiles()
    ctx = BuildContext(
        output_root=Path(output_root),
        failures=[],
        built_cache=set(),
        parallel_workers=max(1, int(parallel_workers)),
        lock=Lock(),
    )
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
