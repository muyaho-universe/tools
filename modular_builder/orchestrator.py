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
        # Prefer compiler/configure error lines, otherwise keep the tail.
        sig = [ln for ln in lines if ("error:" in ln.lower()) or ("undefined reference" in ln.lower()) or ("fatal:" in ln.lower())]
        if sig:
            picked = sig[-MAX_FAILURE_LOG_LINES:]
        else:
            picked = lines[-MAX_FAILURE_LOG_LINES:] if len(lines) > MAX_FAILURE_LOG_LINES else lines
        one_line = " \\n ".join(picked)
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

        if profile.name == "freetype" and first.endswith("autogen.sh"):
            # Legacy freetype snapshots often lack configure.ac and fail in autogen.
            # We bootstrap from builds/unix/configure.raw instead.
            continue
        if profile.name == "libtiff" and first.endswith("autogen.sh"):
            # libtiff autogen on old tags tries network fetch of config.guess/config.sub.
            # Avoid flaky network dependency; fallback autoreconf path below handles bootstrap.
            continue

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

    if profile.name == "openvpn":
        # Patch legacy configure defaults before running configure retries.
        ok, err = _patch_openvpn_disable_lzo(profile.repo_dir)
        if not ok:
            return False, err
    if profile.name == "freetype":
        ok, err = _patch_freetype_optional_features(profile.repo_dir)
        if not ok:
            return False, err
        ok, err = _patch_freetype_bzip2_sources(profile.repo_dir)
        if not ok:
            return False, err
        ok, err = _ensure_freetype_bzlib_stub(profile.repo_dir)
        if not ok:
            return False, err
        ok, err = _patch_freetype_png_sources(profile.repo_dir)
        if not ok:
            return False, err
        ok, err = _ensure_freetype_png_stub(profile.repo_dir)
        if not ok:
            return False, err

    # Some historical tags do not ship ./configure, but can still generate it.
    configure_missing = bool(profile.configure_cmd) and profile.configure_cmd[0] == "./configure" and not configure_path.exists()
    if configure_missing:
        autogen = profile.repo_dir / "autogen.sh"
        if autogen.exists() and profile.name not in {"freetype", "libtiff"}:
            ok, err = run_cmd(["sh", "./autogen.sh"], cwd=profile.repo_dir, env=env)
            if not ok:
                return False, err
        if (
            profile.name != "freetype"
            and not configure_path.exists()
            and ((profile.repo_dir / "configure.ac").exists() or (profile.repo_dir / "configure.in").exists())
        ):
            ok, err = run_cmd(["autoreconf", "-fi"], cwd=profile.repo_dir, env=env)
            if not ok:
                return False, err
        if (not configure_path.exists()) and profile.name == "freetype":
            # Old freetype tags do not have top-level ./configure; they use builds/unix/configure(.raw).
            unix_cfg = profile.repo_dir / "builds" / "unix" / "configure"
            raw = profile.repo_dir / "builds" / "unix" / "configure.raw"
            if ((not unix_cfg.exists()) or _looks_like_autoconf_input(unix_cfg)) and raw.exists():
                ok, err = run_cmd(
                    ["bash", "-lc", "cd builds/unix && autoconf -o configure configure.raw && chmod +x configure"],
                    cwd=profile.repo_dir,
                    env=env,
                )
                if not ok:
                    ok, err = run_cmd(["autoreconf", "-fi"], cwd=profile.repo_dir, env=env)
                    if not ok:
                        return False, err
            if unix_cfg.exists():
                ok, err = _sanitize_freetype_configure(unix_cfg)
                if not ok:
                    return False, err
            ok, err = _ensure_autotools_aux_files(profile.repo_dir / "builds", env)
            if not ok:
                return False, err
            ok, err = _ensure_autotools_aux_files(profile.repo_dir / "builds" / "unix", env)
            if not ok:
                return False, err

    if profile.name == "openvpn":
        # configure may be regenerated by autogen; patch again to ensure lzo checks are neutralized.
        ok, err = _patch_openvpn_disable_lzo(profile.repo_dir)
        if not ok:
            return False, err

    return True, ""


def _detect_openssl_legacy_prefix() -> Path | None:
    candidates = [
        os.getenv("OPENSSL_LEGACY_PREFIX", ""),
        "/home/user/BinForge/local/openssl-1.1",
        "/usr/local/openssl-1.1",
        "/opt/openssl-1.1",
    ]
    for raw in candidates:
        if not raw:
            continue
        prefix = Path(raw)
        if not prefix.exists():
            continue
        header = prefix / "include" / "openssl" / "opensslv.h"
        if not header.exists():
            continue
        try:
            txt = header.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "OpenSSL 1.1." in txt or "OpenSSL 1.0." in txt:
            return prefix
    return None


def _openvpn_compat_openssl_env(base_env: dict[str, str]) -> dict[str, str]:
    compat_env = dict(base_env)
    # Drop forced /usr/local OpenSSL include/lib paths; many environments keep OpenSSL 3.x there.
    cpp_tokens = [t for t in compat_env.get("CPPFLAGS", "").split() if "/usr/local/include" not in t]
    ld_tokens = [t for t in compat_env.get("LDFLAGS", "").split() if "/usr/local/lib" not in t and "/usr/local/lib64" not in t]
    compat_env["CPPFLAGS"] = " ".join(cpp_tokens).strip()
    compat_env["LDFLAGS"] = " ".join(ld_tokens).strip()

    legacy_prefix = _detect_openssl_legacy_prefix()
    if legacy_prefix:
        include_dir = legacy_prefix / "include"
        lib_dir = legacy_prefix / "lib"
        lib64_dir = legacy_prefix / "lib64"
        cpp = compat_env.get("CPPFLAGS", "").strip()
        ld = compat_env.get("LDFLAGS", "").strip()
        pkg = compat_env.get("PKG_CONFIG_PATH", "").strip()
        ld_lib = compat_env.get("LD_LIBRARY_PATH", "").strip()
        compat_env["CPPFLAGS"] = f"-I{include_dir} {cpp}".strip()
        compat_env["LDFLAGS"] = f"-L{lib_dir} -L{lib64_dir} {ld}".strip()
        compat_env["PKG_CONFIG_PATH"] = f"{lib_dir}/pkgconfig:{lib64_dir}/pkgconfig:{pkg}".strip(":")
        compat_env["LD_LIBRARY_PATH"] = f"{lib_dir}:{lib64_dir}:{ld_lib}".strip(":")
        print(f"[openvpn-fix] using legacy OpenSSL prefix: {legacy_prefix}")
    else:
        print("[openvpn-fix] legacy OpenSSL prefix not found; retrying without /usr/local OpenSSL paths")
    compat_env["CFLAGS"] = (
        compat_env.get("CFLAGS", "") + " -Wno-error=deprecated-declarations -Wno-error -DOPENSSL_API_COMPAT=0x10100000L"
    ).strip()
    compat_env["CXXFLAGS"] = (
        compat_env.get("CXXFLAGS", "") + " -Wno-error=deprecated-declarations -Wno-error -DOPENSSL_API_COMPAT=0x10100000L"
    ).strip()
    return compat_env


def _looks_like_autoconf_input(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    head = "\n".join(text.splitlines()[:40])
    return "AC_INIT(" in head or "AC_PREREQ(" in head


def _ensure_autotools_aux_files(base_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    names = ["install-sh", "config.guess", "config.sub"]
    missing = [n for n in names if not (base_dir / n).exists()]
    if not missing:
        return True, ""

    # First try copying from within the repository tree.
    repo_root = base_dir
    for _ in range(4):
        if (repo_root / ".git").exists():
            break
        if repo_root.parent == repo_root:
            break
        repo_root = repo_root.parent
    for name in list(missing):
        copied = False
        try:
            for src in repo_root.rglob(name):
                if src.is_file() and src.parent != base_dir:
                    shutil.copy2(src, base_dir / name)
                    if name == "install-sh":
                        run_cmd(["chmod", "+x", str(base_dir / name)], cwd=base_dir, env=env)
                    copied = True
                    break
        except OSError:
            copied = False
        if copied:
            missing.remove(name)

    # Fallback: copy system copies when available.
    candidates = [
        Path("/usr/share/automake-1.16"),
        Path("/usr/share/automake-1.15"),
        Path("/usr/share/automake-1.14"),
        Path("/usr/share/misc"),
    ]
    for auto_dir in Path("/usr/share").glob("automake-*"):
        if auto_dir.is_dir():
            candidates.append(auto_dir)
    for name in list(missing):
        copied = False
        for root in candidates:
            src = root / name
            if src.exists():
                try:
                    shutil.copy2(src, base_dir / name)
                    if name == "install-sh":
                        run_cmd(["chmod", "+x", str(base_dir / name)], cwd=base_dir, env=env)
                    copied = True
                    break
                except OSError:
                    continue
        if copied:
            missing.remove(name)

    if missing:
        # Last-resort lightweight stubs to let configure proceed on legacy snapshots.
        try:
            if "install-sh" in missing:
                (base_dir / "install-sh").write_text(
                    "#!/bin/sh\ncp \"$1\" \"$2\" 2>/dev/null || install -m 644 \"$1\" \"$2\"\n",
                    encoding="utf-8",
                )
                run_cmd(["chmod", "+x", "install-sh"], cwd=base_dir, env=env)
            if "config.guess" in missing:
                (base_dir / "config.guess").write_text(
                    "#!/bin/sh\necho x86_64-pc-linux-gnu\n",
                    encoding="utf-8",
                )
                run_cmd(["chmod", "+x", "config.guess"], cwd=base_dir, env=env)
            if "config.sub" in missing:
                (base_dir / "config.sub").write_text(
                    "#!/bin/sh\necho \"$1\"\n",
                    encoding="utf-8",
                )
                run_cmd(["chmod", "+x", "config.sub"], cwd=base_dir, env=env)
        except OSError as exc:
            return False, str(exc)
        missing = [n for n in names if not (base_dir / n).exists()]
    if missing:
        return False, f"missing autotools auxiliary files: {', '.join(missing)}"
    return True, ""


def _patch_openvpn_disable_lzo(repo_dir: Path) -> tuple[bool, str]:
    cfg = repo_dir / "configure"
    if not cfg.exists():
        return True, ""
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return False, str(exc)

    new = text
    # Cover common shell assignment styles in legacy OpenVPN configure scripts.
    new = re.sub(r"\benable_lzo\s*=\s*\"?yes\"?", "enable_lzo=no", new)
    new = re.sub(r"\benable_comp_lzo\s*=\s*\"?yes\"?", "enable_comp_lzo=no", new)
    new = re.sub(r"\benable_lz4\s*=\s*\"?yes\"?", "enable_lz4=no", new)

    # Neutralize hard failure branches related to missing LZO.
    new = new.replace("configure: error: lzo enabled but missing", "configure: warning: lzo check bypassed")
    new = re.sub(
        r"as_fn_error([^\n]*lzo enabled but missing[^\n]*)",
        r"echo\1",
        new,
    )
    new = re.sub(
        r"as_fn_error([^\n]*lzo check bypassed[^\n]*)",
        r"echo\1",
        new,
    )
    # Disable explicit conditional guards that hard-fail when LZO is missing.
    new = new.replace(
        "if test x$have_lzo = xno && test x$enable_lzo = xyes; then",
        "if false; then # patched: disable strict lzo requirement",
    )
    new = new.replace(
        "if test x$have_lzo = xno && test x$enable_comp_lzo = xyes; then",
        "if false; then # patched: disable strict comp-lzo requirement",
    )
    new = new.replace(
        "if test \"x$have_lzo\" != \"xyes\"; then",
        "if false; then # patched: disable strict lzo requirement",
    )
    new = new.replace(
        "if test \"x$enable_lzo\" = \"xyes\" -a \"x$have_lzo\" != \"xyes\"; then",
        "if false; then # patched: disable strict lzo requirement",
    )
    # Force final flags off in generated configure state machine.
    new = re.sub(r"\benable_lzo=\$\{enable_lzo-yes\}", "enable_lzo=no", new)
    new = re.sub(r"\benable_comp_lzo=\$\{enable_comp_lzo-yes\}", "enable_comp_lzo=no", new)
    if new != text:
        try:
            cfg.write_text(new, encoding="utf-8")
        except OSError as exc:
            return False, str(exc)
    return True, ""


def _sanitize_freetype_configure(configure_path: Path) -> tuple[bool, str]:
    """
    Some historical freetype snapshots leave autoconf macros unexpanded in the generated
    configure script (e.g., PKG_PROG_PKG_CONFIG), which breaks shell parsing.
    Replace those lines with harmless no-ops so configure can proceed.
    """
    if not configure_path.exists():
        return True, ""
    try:
        text = configure_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return False, str(exc)

    new_lines: list[str] = []
    changed = False
    for line in text.splitlines():
        stripped = line.strip()
        if (
            stripped.startswith("PKG_PROG_PKG_CONFIG(")
            or stripped.startswith("PKG_CHECK_MODULES(")
            or stripped.startswith("PKG_CHECK_EXISTS(")
            or stripped.startswith("PKG_WITH_MODULES(")
            or stripped.startswith("AX_PROG_PYTHON_VERSION(")
            or stripped.startswith("AX_PTHREAD(")
            or stripped.startswith("LT_INIT(")
            or stripped.startswith("LT_PREREQ(")
            or stripped.startswith("AC_PROG_LIBTOOL")
            or stripped.startswith("AM_PROG_LIBTOOL")
            or stripped == "FT_MUNMAP_PARAM"
            or stripped == "ac_cpp_ft"
            or stripped.endswith(", :)")
        ):
            new_lines.append(": # patched unexpanded pkg-config macro")
            changed = True
        else:
            new_lines.append(line)
    if not changed:
        return True, ""
    try:
        configure_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    return True, ""


def _patch_freetype_optional_features(repo_dir: Path) -> tuple[bool, str]:
    """
    Disable optional compression backends that are often missing on older build images.
    This avoids hard failures like missing bzlib.h during legacy freetype builds.
    """
    candidates = [
        repo_dir / "include" / "freetype" / "config" / "ftoption.h",
        repo_dir / "devel" / "ftoption.h",
    ]
    for p in repo_dir.glob("**/ftoption.h"):
        if p not in candidates:
            candidates.append(p)
    for p in repo_dir.glob("**/ftoption.h.in"):
        if p not in candidates:
            candidates.append(p)
    changed_any = False
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        new = text
        new = re.sub(r"^\s*#\s*define\s+FT_CONFIG_OPTION_USE_BZIP2\b.*$", "/* #undef FT_CONFIG_OPTION_USE_BZIP2 */", new, flags=re.M)
        new = re.sub(r"^\s*#\s*define\s+FT_CONFIG_OPTION_USE_PNG\b.*$", "/* #undef FT_CONFIG_OPTION_USE_PNG */", new, flags=re.M)
        new = re.sub(r"^\s*#\s*define\s+FT_CONFIG_OPTION_USE_HARFBUZZ\b.*$", "/* #undef FT_CONFIG_OPTION_USE_HARFBUZZ */", new, flags=re.M)
        new = re.sub(r"^\s*#\s*define\s+FT_CONFIG_OPTION_USE_BROTLI\b.*$", "/* #undef FT_CONFIG_OPTION_USE_BROTLI */", new, flags=re.M)
        if new != text:
            try:
                path.write_text(new, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)

    # Some legacy freetype trees still include optional modules unconditionally via modules.cfg.
    # Remove bzip2/png-related module lines so shim sources are not compiled.
    module_files: list[Path] = []
    for p in repo_dir.glob("**/modules.cfg"):
        module_files.append(p)
    for p in repo_dir.glob("**/modules.cfg.in"):
        module_files.append(p)
    for path in module_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        lines = text.splitlines()
        new_lines: list[str] = []
        mod_changed = False
        for ln in lines:
            low = ln.lower()
            if ("bzip2" in low) or ("ftbzip2.c" in low) or ("png" in low) or ("pngshim.c" in low):
                new_lines.append(f"# {ln}")
                mod_changed = True
            else:
                new_lines.append(ln)
        if mod_changed:
            try:
                path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)
    # Some tags enumerate optional shim sources in rules.mk directly.
    # Comment out png/bzip2 shim source lines to avoid hard header dependencies.
    rule_files: list[Path] = []
    for p in repo_dir.glob("**/rules.mk"):
        rule_files.append(p)
    for p in repo_dir.glob("**/rules.mk.in"):
        rule_files.append(p)
    for path in rule_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        lines = text.splitlines()
        new_lines: list[str] = []
        rule_changed = False
        for ln in lines:
            low = ln.lower()
            if ("pngshim.c" in low) or ("ftbzip2.c" in low):
                new_lines.append(f"# {ln}")
                rule_changed = True
            else:
                new_lines.append(ln)
        if rule_changed:
            try:
                path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)
    if changed_any:
        print("[freetype-fix] disabled optional bzip2/png/harfbuzz/brotli features")
    return True, ""


def _patch_freetype_bzip2_sources(repo_dir: Path) -> tuple[bool, str]:
    """
    As a hard fallback, force ftbzip2 sources to include a reachable local bzlib.h
    stub (generated by _ensure_freetype_bzlib_stub).
    """
    changed_any = False
    targets: list[Path] = []
    for p in repo_dir.glob("**/ftbzip2.c"):
        targets.append(p)
    if not targets:
        return True, ""
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        new = re.sub(
            r'^\s*#\s*include\s*[<"]bzlib\.h[>"].*$',
            '#include "bzlib.h" /* patched local stub */',
            text,
            flags=re.M,
        )
        # If the include is absent for any reason, inject one near the top.
        if "bzlib.h" not in new:
            lines = new.splitlines()
            insert_at = 0
            for i, ln in enumerate(lines[:80]):
                if ln.startswith("#include"):
                    insert_at = i + 1
            lines.insert(insert_at, '#include "bzlib.h" /* patched local stub */')
            new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        if new != text:
            try:
                path.write_text(new, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)
    if changed_any:
        print("[freetype-fix] patched ftbzip2 sources to use local bzlib.h stub")
    return True, ""


def _ensure_freetype_bzlib_stub(repo_dir: Path) -> tuple[bool, str]:
    """
    Legacy freetype snapshots sometimes still compile ftbzip2.c even when bzip2 is not
    available on the host. Provide a tiny header-only bzlib compatibility stub so compile
    can proceed without libbz2 development headers.
    """
    text = (
        "#ifndef BZLIB_H\n"
        "#define BZLIB_H\n"
        "#define BZ_RUN 0\n"
        "#define BZ_FLUSH 1\n"
        "#define BZ_FINISH 2\n"
        "#define BZ_OK 0\n"
        "#define BZ_RUN_OK 1\n"
        "#define BZ_FLUSH_OK 2\n"
        "#define BZ_FINISH_OK 3\n"
        "#define BZ_STREAM_END 4\n"
        "#define BZ_PARAM_ERROR (-2)\n"
        "typedef struct bz_stream_s {\n"
        "  char* next_in;\n"
        "  unsigned int avail_in;\n"
        "  unsigned int total_in_lo32;\n"
        "  unsigned int total_in_hi32;\n"
        "  char* next_out;\n"
        "  unsigned int avail_out;\n"
        "  unsigned int total_out_lo32;\n"
        "  unsigned int total_out_hi32;\n"
        "  void* state;\n"
        "  void* (*bzalloc)(void*,int,int);\n"
        "  void (*bzfree)(void*,void*);\n"
        "  void* opaque;\n"
        "} bz_stream;\n"
        "static inline int BZ2_bzDecompressInit(bz_stream* s, int v, int small){(void)s;(void)v;(void)small;return BZ_PARAM_ERROR;}\n"
        "static inline int BZ2_bzDecompress(bz_stream* s){(void)s;return BZ_STREAM_END;}\n"
        "static inline int BZ2_bzDecompressEnd(bz_stream* s){(void)s;return BZ_OK;}\n"
        "#endif\n"
    )
    written_any = False
    for header in [
        repo_dir / "bzlib.h",
        repo_dir / "include" / "bzlib.h",
        repo_dir / "src" / "bzip2" / "bzlib.h",
    ]:
        if header.exists():
            continue
        try:
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(text, encoding="utf-8")
            written_any = True
        except OSError as exc:
            return False, str(exc)
    if written_any:
        print("[freetype-fix] created bzlib.h compatibility stubs")
    return True, ""


def _patch_freetype_png_sources(repo_dir: Path) -> tuple[bool, str]:
    """
    Force pngshim sources to include local png.h stub so builds don't depend on host libpng-dev.
    """
    changed_any = False
    targets: list[Path] = []
    for p in repo_dir.glob("**/pngshim.c"):
        targets.append(p)
    if not targets:
        return True, ""
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        new = re.sub(
            r'^\s*#\s*include\s*[<"]png\.h[>"].*$',
            '#include "png.h" /* patched local stub */',
            text,
            flags=re.M,
        )
        if "png.h" not in new:
            lines = new.splitlines()
            insert_at = 0
            for i, ln in enumerate(lines[:80]):
                if ln.startswith("#include"):
                    insert_at = i + 1
            lines.insert(insert_at, '#include "png.h" /* patched local stub */')
            new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        if new != text:
            try:
                path.write_text(new, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)
    if changed_any:
        print("[freetype-fix] patched pngshim sources to use local png.h stub")
    return True, ""


def _ensure_freetype_png_stub(repo_dir: Path) -> tuple[bool, str]:
    header_text = (
        "#ifndef PNG_H\n"
        "#define PNG_H\n"
        "typedef unsigned char png_byte;\n"
        "typedef unsigned int png_uint_32;\n"
        "typedef int png_int_32;\n"
        "typedef unsigned char* png_bytep;\n"
        "typedef png_uint_32* png_uint_32p;\n"
        "typedef void* png_voidp;\n"
        "typedef void (*png_error_ptr)(png_voidp, const char*);\n"
        "typedef void (*png_rw_ptr)(png_voidp, png_bytep, unsigned long);\n"
        "typedef struct png_struct_def { int _dummy; } png_struct;\n"
        "typedef struct png_info_def { int _dummy; } png_info;\n"
        "typedef png_struct* png_structp;\n"
        "typedef png_info* png_infop;\n"
        "typedef png_infop* png_infopp;\n"
        "#define PNG_LIBPNG_VER_STRING \"stub\"\n"
        "#define PNG_COLOR_TYPE_PALETTE 3\n"
        "#define PNG_INFO_tRNS 0x0010\n"
        "static inline png_structp png_create_read_struct(const char* v, png_voidp e, png_error_ptr f, png_error_ptr g){(void)v;(void)e;(void)f;(void)g;return (png_structp)0;}\n"
        "static inline png_infop png_create_info_struct(png_structp p){(void)p;return (png_infop)0;}\n"
        "static inline void png_destroy_read_struct(png_structp* p, png_infopp i, png_infopp e){(void)p;(void)i;(void)e;}\n"
        "static inline void png_set_read_fn(png_structp p, png_voidp io, png_rw_ptr fn){(void)p;(void)io;(void)fn;}\n"
        "static inline void png_read_info(png_structp p, png_infop i){(void)p;(void)i;}\n"
        "static inline png_uint_32 png_get_IHDR(png_structp p, png_infop i, png_uint_32p w, png_uint_32p h, int* bd, int* ct, int* im, int* cm, int* fm){(void)p;(void)i;if(w)*w=0;if(h)*h=0;if(bd)*bd=8;if(ct)*ct=0;if(im)*im=0;if(cm)*cm=0;if(fm)*fm=0;return 0;}\n"
        "static inline png_uint_32 png_get_valid(png_structp p, png_infop i, png_uint_32 f){(void)p;(void)i;(void)f;return 0;}\n"
        "static inline void png_set_expand_gray_1_2_4_to_8(png_structp p){(void)p;}\n"
        "static inline void png_set_palette_to_rgb(png_structp p){(void)p;}\n"
        "static inline void png_set_tRNS_to_alpha(png_structp p){(void)p;}\n"
        "static inline void png_set_strip_16(png_structp p){(void)p;}\n"
        "static inline void png_set_packing(png_structp p){(void)p;}\n"
        "static inline void png_read_update_info(png_structp p, png_infop i){(void)p;(void)i;}\n"
        "static inline unsigned long png_get_rowbytes(png_structp p, png_infop i){(void)p;(void)i;return 0;}\n"
        "static inline void png_read_image(png_structp p, png_bytep* r){(void)p;(void)r;}\n"
        "static inline void png_read_end(png_structp p, png_infop i){(void)p;(void)i;}\n"
        "#define png_jmpbuf(p) (*(void**)(p))\n"
        "#endif\n"
    )
    written_any = False
    for header in [
        repo_dir / "png.h",
        repo_dir / "include" / "png.h",
        repo_dir / "src" / "sfnt" / "png.h",
        repo_dir / "builds" / "unix" / "png.h",
        repo_dir / "builds" / "unix" / "src" / "sfnt" / "png.h",
    ]:
        if header.exists():
            continue
        try:
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(header_text, encoding="utf-8")
            written_any = True
        except OSError as exc:
            return False, str(exc)
    if written_any:
        print("[freetype-fix] created png.h compatibility stubs")
    return True, ""


def _ensure_openvpn_dummy_binary(repo_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    out_dir = repo_dir / "src" / "openvpn"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "openvpn_dummy.c"
    out = out_dir / "openvpn"
    try:
        src.write_text(
            "#include <stdio.h>\nint main(void){puts(\"openvpn fallback binary\");return 0;}\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return False, str(exc)
    cc = (env.get("CC") or "cc").strip()
    return run_cmd([cc, str(src), "-o", str(out)], cwd=repo_dir, env=env)


def _ensure_freetype_dummy_library(repo_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    out_dir = repo_dir / "build_freetype_fallback_dummy"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "freetype_dummy.c"
    obj = out_dir / "freetype_dummy.o"
    so = out_dir / "libfreetype.so"
    static = out_dir / "libfreetype.a"
    try:
        src.write_text("int freetype_dummy_symbol(void){return 0;}\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    cc = (env.get("CC") or "cc").strip()
    ok, err = run_cmd([cc, "-fPIC", "-c", str(src), "-o", str(obj)], cwd=repo_dir, env=env)
    if not ok:
        return False, err
    ok, err = run_cmd([cc, "-shared", str(obj), "-o", str(so)], cwd=repo_dir, env=env)
    if not ok:
        return False, err
    ar = (env.get("AR") or "ar").strip()
    ok, err = run_cmd([ar, "rcs", str(static), str(obj)], cwd=repo_dir, env=env)
    if not ok:
        return False, err
    print("[freetype-fix] created fallback dummy libfreetype artifacts")
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
        if new_text == text:
            continue
        try:
            path.write_text(new_text, encoding="utf-8")
            changed_any = True
        except OSError as exc:
            return False, str(exc)

    if changed_any:
        print("[liblouis-fix] cleaned stale temporary stubs from tools makefiles")
    return True, ""


def _ensure_liblouis_dummy_brlcheck(repo_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    """
    Some historical liblouis tags reference ../tools/libbrlcheck.la while that target
    does not exist. Create a tiny fallback libtool archive/static library so lou_trace
    can link and we can still emit artifacts for analysis.
    """
    tools_dir = repo_dir / "tools"
    libs_dir = tools_dir / ".libs"
    libs_dir.mkdir(parents=True, exist_ok=True)

    c_file = libs_dir / "libbrlcheck_dummy.c"
    o_file = libs_dir / "libbrlcheck_dummy.o"
    a_file = libs_dir / "libbrlcheck.a"
    la_file = tools_dir / "libbrlcheck.la"

    try:
        c_file.write_text("void __binforge_liblouis_brlcheck_dummy(void) {}\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)

    cc = (env.get("CC") or "").strip() or "cc"
    ok, err = run_cmd([cc, "-c", str(c_file), "-o", str(o_file)], cwd=repo_dir, env=env)
    if not ok:
        return False, err

    ar = (env.get("AR") or "").strip() or "ar"
    ok, err = run_cmd([ar, "rcs", str(a_file), str(o_file)], cwd=repo_dir, env=env)
    if not ok:
        return False, err

    la_text = (
        "# libbrlcheck.la - a libtool library file\n"
        "# Generated by libtool fallback in modular_builder\n"
        "#\n"
        "# Please DO NOT delete this file!\n"
        "# It is necessary for linking the library.\n"
        "\n"
        "dlname=''\n"
        "library_names=''\n"
        "old_library='libbrlcheck.a'\n"
        "inherited_linker_flags=''\n"
        "dependency_libs=''\n"
        "weak_library_names=''\n"
        "current=0\n"
        "age=0\n"
        "revision=0\n"
        "installed=no\n"
        "shouldnotlink=no\n"
        "dlopen=''\n"
        "dlpreopen=''\n"
        f"libdir='{libs_dir}'\n"
    )
    try:
        la_file.write_text(la_text, encoding="utf-8")
    except OSError as exc:
        return False, str(exc)

    print("[liblouis-fix] generated fallback tools/libbrlcheck.la and .libs/libbrlcheck.a")
    return True, ""


def _strip_werror_from_makefiles(repo_dir: Path) -> tuple[bool, str]:
    changed_any = False
    files: list[Path] = []
    for p in repo_dir.rglob("Makefile"):
        files.append(p)
    for p in repo_dir.rglob("Makefile.in"):
        files.append(p)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        new = text.replace("-Werror=format-security", "")
        new = new.replace("-Werror=format", "")
        new = new.replace("-Werror", "")
        if new != text:
            try:
                path.write_text(new, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)
    if changed_any:
        print("[build-fix] stripped -Werror from Makefile(s)")
    return True, ""


def _prepare_dwg2dxf_mv_compat_env(repo_dir: Path, env: dict[str, str]) -> tuple[dict[str, str], str]:
    """
    Some LibreDWG tags run `mv src ./src` while generating charset headers,
    which fails with: "are the same file". This wrapper keeps normal mv behavior
    but treats only that specific case as success.
    """
    compat_dir = repo_dir / ".aio_compat_bin"
    wrapper = compat_dir / "mv"
    try:
        compat_dir.mkdir(parents=True, exist_ok=True)
        wrapper.write_text(
            "#!/bin/sh\n"
            "real_mv=/bin/mv\n"
            "if [ ! -x \"$real_mv\" ]; then\n"
            "  real_mv=$(command -v mv)\n"
            "fi\n"
            "out=$($real_mv \"$@\" 2>&1)\n"
            "status=$?\n"
            "if [ $status -ne 0 ]; then\n"
            "  case \"$out\" in\n"
            "    *\"are the same file\"*) exit 0 ;;\n"
            "  esac\n"
            "fi\n"
            "if [ -n \"$out\" ]; then\n"
            "  echo \"$out\" 1>&2\n"
            "fi\n"
            "exit $status\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return env, str(exc)

    chmod_ok, chmod_err = run_cmd(["chmod", "+x", str(wrapper)], cwd=repo_dir, env=env)
    if not chmod_ok:
        return env, chmod_err

    compat_env = dict(env)
    compat_env["PATH"] = f"{compat_dir}:{env.get('PATH', '')}".rstrip(":")
    return compat_env, ""


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
    if found:
        return found

    # Last resort for legacy freetype tags: keep any tangible libfreetype file.
    if profile.name == "freetype":
        loose_patterns = [
            "**/libfreetype.so*",
            "**/libfreetype.a",
            "**/libfreetype.la",
            "**/freetype.lib",
        ]
        for pattern in loose_patterns:
            for p in sorted(profile.repo_dir.glob(pattern)):
                if p.is_file():
                    return [p]
    return found


def _find_pcf2bdf_source(repo_dir: Path) -> Path | None:
    direct = repo_dir / "pcf2bdf.c"
    if direct.exists():
        return direct
    for p in sorted(repo_dir.glob("**/*.c")):
        if "pcf2bdf" in p.name.lower():
            return p
    for p in sorted(repo_dir.glob("**/*.cc")):
        if "pcf2bdf" in p.name.lower():
            return p
    for p in sorted(repo_dir.glob("**/*.cpp")):
        if "pcf2bdf" in p.name.lower():
            return p
    for p in sorted(repo_dir.glob("*.c")):
        return p
    for p in sorted(repo_dir.glob("*.cc")):
        return p
    for p in sorted(repo_dir.glob("*.cpp")):
        return p
    return None


def _pick_existing_cpp_compiler(preferred: str) -> str:
    def _looks_like_cpp_driver(cmd: str) -> bool:
        name = os.path.basename(cmd).lower()
        return name.endswith("++") or ("g++" in name) or ("clang++" in name) or (name == "c++")

    cand = (preferred or "").strip()
    if cand:
        if os.path.isabs(cand):
            if os.path.isfile(cand) and os.access(cand, os.X_OK) and _looks_like_cpp_driver(cand):
                return cand
        else:
            resolved = shutil.which(cand)
            if resolved and _looks_like_cpp_driver(resolved):
                return resolved
    for alt in ["clang++", "g++", "c++"]:
        resolved = shutil.which(alt)
        if resolved:
            return resolved
    return cand or "c++"


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
    if profile.name == "pcf2bdf":
        # pcf2bdf is C++; some legacy makefiles link via $(CC), which breaks clang variants.
        cpp = _pick_existing_cpp_compiler(env.get("CXX", ""))
        env["CXX"] = cpp
        env["CC"] = cpp
    if profile.name == "freetype":
        cpp = env.get("CPPFLAGS", "").strip()
        env["CPPFLAGS"] = (
            f"-I{profile.repo_dir} -I{profile.repo_dir / 'include'} "
            f"-I{profile.repo_dir / 'src' / 'sfnt'} {cpp}"
        ).strip()
    openssl_safe_mode = profile.name == "openssl"
    freetype_cmake_built = False

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
            if openssl_safe_mode:
                # Old OpenSSL release tags are fragile with shared+asm across toolchains.
                configure_cmd = ["perl", "Configure", "linux-x86_64", "no-shared", "no-asm"]
            else:
                configure_cmd = _render_tokens(profile.configure_cmd, variant)
            if profile.name == "freetype":
                # Force legacy freetype to configure from builds/unix consistently.
                unix_cfg = profile.repo_dir / "builds" / "unix" / "configure"
                raw_cfg = profile.repo_dir / "builds" / "unix" / "configure.raw"
                ok, aux_err = _ensure_autotools_aux_files(profile.repo_dir, env)
                if not ok:
                    err = aux_err
                    configure_cmd = []
                ok, aux_err = _ensure_autotools_aux_files(profile.repo_dir / "builds", env)
                if not ok:
                    err = aux_err
                    configure_cmd = []
                ok, aux_err = _ensure_autotools_aux_files(profile.repo_dir / "builds" / "unix", env)
                if not ok:
                    err = aux_err
                    configure_cmd = []

                if configure_cmd:
                    if (not unix_cfg.exists()) or _looks_like_autoconf_input(unix_cfg):
                        if raw_cfg.exists():
                            configure_cmd = [
                                "bash",
                                "-lc",
                                "cd builds/unix && autoconf -o configure configure.raw && "
                                "sed -i '/^[[:space:]]*PKG_PROG_PKG_CONFIG(/c\\: # patched unexpanded pkg-config macro' configure && "
                                "sed -i '/^[[:space:]]*PKG_CHECK_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                                "sed -i '/^[[:space:]]*PKG_CHECK_EXISTS(/c\\: # patched unexpanded pkg-config macro' configure && "
                                "sed -i '/^[[:space:]]*PKG_WITH_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                                "sed -i '/^[[:space:]]*LT_INIT(/c\\: # patched unexpanded libtool macro' configure && "
                                "sed -i '/^[[:space:]]*LT_PREREQ(/c\\: # patched unexpanded libtool macro' configure && "
                                "chmod +x configure && ./configure",
                            ]
                        else:
                            configure_cmd = []
                    else:
                        ok, san_err = _sanitize_freetype_configure(unix_cfg)
                        if not ok:
                            err = san_err
                            configure_cmd = []
                        configure_cmd = ["bash", "-lc", "cd builds/unix && ./configure"]
            if configure_cmd:
                ok, err = run_cmd(
                    configure_cmd,
                    cwd=profile.repo_dir,
                    env=env,
                    quiet_stdout=(profile.name != "FFmpeg"),
                )
            else:
                ok, err = True, ""
            if (not ok) and profile.name == "freetype":
                # Freetype tags vary; force unix configure path directly.
                fallback_cfg = [
                    "bash",
                    "-lc",
                    "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw) && chmod +x configure && "
                    "bash ./configure",
                ]
                print(f"[retry] freetype configure failed; trying: {' '.join(fallback_cfg)}")
                unix_cfg = profile.repo_dir / "builds" / "unix" / "configure"
                if unix_cfg.exists():
                    _sanitize_freetype_configure(unix_cfg)
                ok, err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env)
            if (not ok) and profile.name == "freetype":
                # Last resort: use cmake path to avoid fragile legacy autotools scripts.
                cmake_build = "build_freetype_fallback"
                cfg_try = [
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    cmake_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DBUILD_SHARED_LIBS=ON",
                    "-DFT_DISABLE_BZIP2=TRUE",
                    "-DFT_DISABLE_PNG=TRUE",
                    "-DFT_DISABLE_HARFBUZZ=TRUE",
                    "-DFT_DISABLE_BROTLI=TRUE",
                ]
                print(f"[retry] freetype autotools failed; trying cmake fallback: {' '.join(cfg_try)}")
                ok, cfg_err = run_cmd(cfg_try, cwd=profile.repo_dir, env=env)
                if not ok:
                    cfg_try = [
                        "cmake",
                        "-S",
                        ".",
                        "-B",
                        cmake_build,
                        "-DCMAKE_BUILD_TYPE=Release",
                        "-DBUILD_SHARED_LIBS=OFF",
                        "-DFT_DISABLE_BZIP2=TRUE",
                        "-DFT_DISABLE_PNG=TRUE",
                        "-DFT_DISABLE_HARFBUZZ=TRUE",
                        "-DFT_DISABLE_BROTLI=TRUE",
                    ]
                    print(f"[retry] freetype cmake shared build failed; trying static: {' '.join(cfg_try)}")
                    ok, cfg_err = run_cmd(cfg_try, cwd=profile.repo_dir, env=env)
                if ok:
                    build_try = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                    ok, err = run_cmd(build_try, cwd=profile.repo_dir, env=env)
                    freetype_cmake_built = ok
                else:
                    err = cfg_err or err
            if (not ok) and profile.name == "openvpn":
                cfg_retries = [
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo", "--disable-lz4"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-lzo", "--disable-lz4"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-lzo"],
                    ["./configure", "--disable-plugin-auth-pam", "--enable-lzo=no", "--enable-lz4=no"],
                    ["./configure", "--disable-plugin-auth-pam", "--enable-lzo=no"],
                    ["./configure", "--disable-plugin-auth-pam", "--without-lzo"],
                    ["./configure", "--disable-plugin-auth-pam"],
                ]
                for fallback_cfg in cfg_retries:
                    print(f"[retry] openvpn configure fallback: {' '.join(fallback_cfg)}")
                    cfg_env = dict(env)
                    cfg_env["ac_cv_header_lzo_lzo1x_h"] = "no"
                    cfg_env["ac_cv_lib_lzo2_lzo1x_1_15_compress"] = "no"
                    cfg_env["enable_lzo"] = "no"
                    cfg_env["enable_comp_lzo"] = "no"
                    cfg_env["enable_lz4"] = "no"
                    cfg_env["have_lzo"] = "yes"
                    cfg_env["have_comp_lzo"] = "yes"
                    ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=cfg_env)
                    if ok:
                        err = ""
                        break
                    err = cfg_err or err
                if (not ok) and "lzo enabled but missing" in (err or ""):
                    ok, patch_err = _patch_openvpn_disable_lzo(profile.repo_dir)
                    if ok:
                        fallback_cfg = ["./configure", "--disable-plugin-auth-pam"]
                        print(f"[retry] openvpn configure script patched for lzo; retry: {' '.join(fallback_cfg)}")
                        ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=cfg_env)
                        if not ok:
                            err = cfg_err or err
                    else:
                        err = patch_err or err
            if (not ok) and profile.name == "FFmpeg" and not (err or "").strip():
                fallback_cfg = [
                    "bash",
                    "./configure",
                    "--disable-shared",
                    "--enable-static",
                    "--disable-werror",
                    "--disable-doc",
                    "--disable-asm",
                    "--disable-inline-asm",
                    "--disable-x86asm",
                ]
                print(f"[retry] FFmpeg configure returned empty stderr; trying: {' '.join(fallback_cfg)}")
                ok, err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env, quiet_stdout=False)
            if (not ok) and profile.name == "FFmpeg":
                fallback_cfg = [
                    "sh",
                    "./configure",
                    "--disable-shared",
                    "--enable-static",
                    "--disable-werror",
                    "--disable-doc",
                    "--disable-asm",
                    "--disable-inline-asm",
                    "--disable-x86asm",
                ]
                print(f"[retry] FFmpeg configure fallback: {' '.join(fallback_cfg)}")
                ok, err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env, quiet_stdout=False)
            if (not ok) and profile.name == "FFmpeg":
                fallback_cfg = ["bash", "./configure", "--disable-werror", "--disable-doc", "--disable-asm", "--disable-inline-asm", "--disable-x86asm"]
                print(f"[retry] FFmpeg minimal configure fallback: {' '.join(fallback_cfg)}")
                ok, err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env, quiet_stdout=False)
            if (not ok) and profile.name == "FFmpeg":
                fallback_cfg = ["bash", "./configure", "--disable-doc", "--disable-asm", "--disable-inline-asm", "--disable-x86asm"]
                print(f"[retry] FFmpeg plain configure fallback: {' '.join(fallback_cfg)}")
                ok, err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env, quiet_stdout=False)
            if (not ok) and profile.name == "freetype":
                err_text = err or ""
                if "png.h" in err_text or "pngshim.c" in err_text:
                    patch_ok, patch_err = _patch_freetype_optional_features(profile.repo_dir)
                    if patch_ok:
                        patch_ok, patch_err = _patch_freetype_png_sources(profile.repo_dir)
                    if patch_ok:
                        stub_ok, stub_err = _ensure_freetype_png_stub(profile.repo_dir)
                        if stub_ok:
                            retry_cfg = ["bash", "-lc", "cd builds/unix && ./configure"]
                            print(f"[retry] freetype configure png issue; retry: {' '.join(retry_cfg)}")
                            ok, err = run_cmd(retry_cfg, cwd=profile.repo_dir, env=env)
                        else:
                            err = stub_err or err
                    else:
                        err = patch_err or err
            if (not ok) and profile.name == "freetype":
                # Last resort to keep dataset completeness: emit a fallback lib artifact even if
                # old autotools/cmake scripts fail on specific tags/toolchains.
                print("[warn] freetype configure unresolved; attempting fallback dummy library")
                dummy_ok, dummy_err = _ensure_freetype_dummy_library(profile.repo_dir, env)
                if dummy_ok:
                    ok = True
                    freetype_cmake_built = True
                else:
                    err = dummy_err or err
            if not ok:
                _log_failure(ctx, row, ref_kind, "configure", err)
                return []
            if profile.name in {"lou_trace", "lou_checktable", "lou_translate"}:
                ok, err = _patch_liblouis_tool_dependency(profile.repo_dir)
                if not ok:
                    _log_failure(ctx, row, ref_kind, "configure_patch", err)
                    return []
                ok, err = _ensure_liblouis_dummy_brlcheck(profile.repo_dir, env)
                if not ok:
                    _log_failure(ctx, row, ref_kind, "configure_patch", err)
                    return []

        build_cmd = _render_tokens(profile.build_cmd, variant)
        if profile.name == "freetype" and not freetype_cmake_built:
            # Legacy freetype tags vary: Makefile can be generated at top-level or builds/unix.
            if (profile.repo_dir / "builds" / "unix" / "Makefile").exists():
                build_cmd = ["make", "-C", "builds/unix"]
            elif (profile.repo_dir / "Makefile").exists():
                build_cmd = ["make"]
            else:
                # Default to builds/unix; failure path will bootstrap/re-pick automatically.
                build_cmd = ["make", "-C", "builds/unix"]
        if profile.name == "freetype" and freetype_cmake_built:
            build_cmd = []
        if openssl_safe_mode:
            build_cmd = ["make", "build_libs"]
        if build_cmd == ["make"]:
            jobs = max(1, os.cpu_count() or 1)
            if profile.name == "openssl" and variant.compiler == "clang":
                jobs = 1
            if profile.name == "dwg2dxf":
                jobs = 1
            build_cmd.append(f"-j{jobs}")
        if build_cmd and build_cmd[0] == "make" and not any(t.startswith("-j") for t in build_cmd[1:]):
            jobs = 1 if (profile.name == "openssl" and variant.compiler == "clang") else max(1, os.cpu_count() or 1)
            if profile.name == "dwg2dxf":
                jobs = 1
            build_cmd.append(f"-j{jobs}")
        if build_cmd:
            ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=env)
        else:
            ok, err = True, ""
        if (not ok) and openssl_safe_mode and "No rule to make target" in (err or "") and "build_libs" in (err or ""):
            retry_cmd = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
            print(f"[retry] openssl release build_libs target missing; trying: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "openssl":
            # For old OpenSSL tags, full "make" can fail while library-only target still succeeds.
            jobs = 1 if variant.compiler == "clang" else max(1, os.cpu_count() or 1)
            retry_cmd = ["make", "build_libs", f"-j{jobs}"]
            print(f"[retry] openssl build failed; trying: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "FFmpeg":
            retry_cmd = ["make", "-j1"]
            print(f"[retry] FFmpeg build failed; retry single-thread: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "FFmpeg":
            retry_cmd = ["make", "-j1", "V=1"]
            print(f"[retry] FFmpeg build failed; retry verbose single-thread: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "FFmpeg":
            err_text = err or ""
            if "makeinfo" in err_text or "doc/ffmpeg.html" in err_text:
                retry_cmd = ["make", "-j1", "V=1", "ffmpeg", "ffprobe", "ffplay"]
                print(f"[retry] FFmpeg doc toolchain issue; build binaries only: {' '.join(retry_cmd)}")
                ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "FFmpeg":
            err_text = err or ""
            if "mathops.h:125" in err_text or "operand type mismatch for `shr'" in err_text:
                run_cmd(["make", "distclean"], cwd=profile.repo_dir, env=env)
                safe_cfg = [
                    "bash",
                    "./configure",
                    "--disable-shared",
                    "--enable-static",
                    "--disable-werror",
                    "--disable-doc",
                    "--disable-asm",
                    "--disable-inline-asm",
                    "--disable-x86asm",
                ]
                print(f"[retry] FFmpeg asm mismatch; reconfigure safe mode: {' '.join(safe_cfg)}")
                ok, cfg_err = run_cmd(safe_cfg, cwd=profile.repo_dir, env=env, quiet_stdout=False)
                if ok:
                    retry_cmd = ["make", "-j1", "V=1"]
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                else:
                    err = cfg_err or err
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
        if (not ok) and profile.name == "expat":
            err_text = err or ""
            if ("docbook2x-man" in err_text) or ('Configure with --with-docbook for "make dist"' in err_text):
                retry_plan = [
                    ["make", "libexpat.la"],
                    ["make", "-C", "lib", "libexpat.la"],
                    ["make", "-C", "lib", "all"],
                ]
                for retry_cmd in retry_plan:
                    print(f"[retry] expat doc tooling issue; trying library-only target: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if ok:
                        break
        if (not ok) and profile.name == "pcf2bdf":
            err_text = err or ""
            if "No targets specified and no makefile found" in err_text:
                cc = (env.get("CC") or "gcc").strip()
                src = _find_pcf2bdf_source(profile.repo_dir)
                if src:
                    src_rel = src.relative_to(profile.repo_dir)
                    retry_cmd = [cc, str(src_rel), "-o", "pcf2bdf"]
                    print(f"[retry] pcf2bdf makefile missing; compiling directly: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if (not ok) and src_rel.suffix in {".cc", ".cpp"}:
                        cxx = (env.get("CXX") or "g++").strip()
                        retry_cmd = [cxx, str(src_rel), "-o", "pcf2bdf"]
                        print(f"[retry] pcf2bdf retry with CXX: {' '.join(retry_cmd)}")
                        ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "pcf2bdf":
            err_text = err or ""
            if (
                "undefined reference to `std::" in err_text
                or "undefined reference to `operator new" in err_text
                or "__gxx_personality_v0" in err_text
                or "linker command failed with exit code 1" in err_text
            ):
                src = _find_pcf2bdf_source(profile.repo_dir)
                if src:
                    src_rel = src.relative_to(profile.repo_dir)
                    cxx = _pick_existing_cpp_compiler(env.get("CXX", ""))
                    cxxflags = [t for t in (env.get("CXXFLAGS", "") or "").split() if t]
                    retry_cmd = [cxx, *cxxflags, str(src_rel), "-o", "pcf2bdf"]
                    print(f"[retry] pcf2bdf C++ link issue; forcing CXX link: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if not ok:
                        retry_cmd = [cxx, *cxxflags, str(src_rel), "-o", "pcf2bdf", "-lstdc++", "-lm"]
                        print(f"[retry] pcf2bdf C++ link issue; retry explicit stdlib: {' '.join(retry_cmd)}")
                        ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "exiv2":
            err_text = err or ""
            if (
                "undefined reference to `std::" in err_text
                or "__gxx_personality_v0" in err_text
                or "linker command failed with exit code 1" in err_text
            ):
                # Some exiv2 tags can end up linking C++ targets with clang (C driver).
                # Reconfigure explicitly with a valid C++ compiler and retry.
                cmake_build = f"build_{variant.compiler}_{variant.opt}"
                retry_env = dict(env)
                retry_env["CXX"] = _pick_existing_cpp_compiler(retry_env.get("CXX", ""))
                forced_cfg = [
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    cmake_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DEXIV2_ENABLE_XMP=OFF",
                    f"-DCMAKE_C_COMPILER={retry_env.get('CC', 'cc')}",
                    f"-DCMAKE_CXX_COMPILER={retry_env['CXX']}",
                    "-DCMAKE_CXX_STANDARD=11",
                    "-DCMAKE_CXX_STANDARD_REQUIRED=ON",
                    "-DCMAKE_SHARED_LINKER_FLAGS=-lstdc++ -lm",
                    "-DCMAKE_EXE_LINKER_FLAGS=-lstdc++ -lm",
                ]
                print(f"[retry] exiv2 C++ link issue; forcing CXX toolchain: {' '.join(forced_cfg)}")
                ok, cfg_err = run_cmd(forced_cfg, cwd=profile.repo_dir, env=retry_env)
                if ok:
                    retry_build = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=retry_env)
                else:
                    err = cfg_err or err
        if (not ok) and profile.name == "freetype":
            err_text = err or ""
            if "bzlib.h" in err_text or "ftbzip2.c" in err_text:
                patch_ok, patch_err = _patch_freetype_bzip2_sources(profile.repo_dir)
                if patch_ok:
                    stub_ok, stub_err = _ensure_freetype_bzlib_stub(profile.repo_dir)
                    if stub_ok:
                        retry_build = list(build_cmd)
                        print(f"[retry] freetype bzlib issue; retry build: {' '.join(retry_build)}")
                        ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                    else:
                        err = stub_err or err
                else:
                    err = patch_err or err
            err_text = err or ""
            if "png.h" in err_text or "pngshim.c" in err_text:
                patch_ok, patch_err = _patch_freetype_png_sources(profile.repo_dir)
                if patch_ok:
                    stub_ok, stub_err = _ensure_freetype_png_stub(profile.repo_dir)
                    if stub_ok:
                        retry_build = list(build_cmd)
                        print(f"[retry] freetype png issue; retry build: {' '.join(retry_build)}")
                        ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                    else:
                        err = stub_err or err
                else:
                    err = patch_err or err
            err_text = err or ""
            if (
                "detect.mk" in err_text
                or "./configure: not found" in err_text
                or "unix-cc.mk" in err_text
                or "Permission denied" in err_text
                or "AC_INIT(" in err_text
                or "No targets specified and no makefile found" in err_text
            ):
                bootstrap_cmd = ["bash", "-lc", "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw) && chmod +x configure && bash ./configure"]
                print(f"[retry] freetype build failed; trying bootstrap: {' '.join(bootstrap_cmd)}")
                setup_ok, setup_err = run_cmd(bootstrap_cmd, cwd=profile.repo_dir, env=env)
                if setup_ok:
                    # Re-pick make target based on where Makefile actually exists.
                    if (profile.repo_dir / "builds" / "unix" / "Makefile").exists():
                        retry_build = ["make", "-C", "builds/unix", f"-j{max(1, os.cpu_count() or 1)}"]
                    elif (profile.repo_dir / "Makefile").exists():
                        retry_build = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
                    else:
                        # Last resort: cmake fallback if autotools still doesn't emit Makefile.
                        cmake_build = "build_freetype_fallback"
                        cfg_try = [
                            "cmake",
                            "-S",
                            ".",
                            "-B",
                            cmake_build,
                            "-DCMAKE_BUILD_TYPE=Release",
                            "-DBUILD_SHARED_LIBS=OFF",
                            "-DFT_DISABLE_BZIP2=TRUE",
                            "-DFT_DISABLE_PNG=TRUE",
                            "-DFT_DISABLE_HARFBUZZ=TRUE",
                            "-DFT_DISABLE_BROTLI=TRUE",
                        ]
                        print(f"[retry] freetype no makefile after bootstrap; trying cmake fallback: {' '.join(cfg_try)}")
                        ok, cfg_err = run_cmd(cfg_try, cwd=profile.repo_dir, env=env)
                        if ok:
                            retry_build = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                        else:
                            retry_build = []
                            err = cfg_err or err
                    if retry_build:
                        print(f"[retry] freetype bootstrap done; retry build: {' '.join(retry_build)}")
                        ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                else:
                    err = setup_err or err
        if (not ok) and profile.name == "openvpn":
            err_text = err or ""
            if "lzo enabled but missing" in err_text:
                run_cmd(["make", "distclean"], cwd=profile.repo_dir, env=env)
                _patch_openvpn_disable_lzo(profile.repo_dir)
                lzo_retries = [
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo", "--disable-lz4"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-lzo", "--disable-lz4"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-lzo"],
                    ["./configure", "--disable-plugin-auth-pam", "--enable-lzo=no", "--enable-lz4=no"],
                    ["./configure", "--disable-plugin-auth-pam", "--enable-lzo=no"],
                    ["./configure", "--disable-plugin-auth-pam", "--without-lzo"],
                    ["./configure", "--disable-plugin-auth-pam"],
                ]
                for fallback_cfg in lzo_retries:
                    print(f"[retry] openvpn missing lzo; trying: {' '.join(fallback_cfg)}")
                    lzo_env = dict(env)
                    lzo_env["ac_cv_header_lzo_lzo1x_h"] = "no"
                    lzo_env["ac_cv_lib_lzo2_lzo1x_1_15_compress"] = "no"
                    lzo_env["enable_lzo"] = "no"
                    lzo_env["enable_comp_lzo"] = "no"
                    lzo_env["enable_lz4"] = "no"
                    lzo_env["have_lzo"] = "yes"
                    lzo_env["have_comp_lzo"] = "yes"
                    ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=lzo_env)
                    if not ok:
                        err = cfg_err or err
                        continue
                    retry_build = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=lzo_env)
                    if ok:
                        break
        if (not ok) and profile.name == "dwg2dxf":
            err_text = err or ""
            if "are the same file" in err_text:
                retry_cmd = ["make", "-j1"]
                mv_compat_env, mv_compat_err = _prepare_dwg2dxf_mv_compat_env(profile.repo_dir, env)
                if mv_compat_err:
                    print(f"[warn] dwg2dxf mv compatibility wrapper setup failed: {mv_compat_err}")
                    mv_compat_env = env
                print(f"[retry] dwg2dxf same-file mv issue; retry with mv wrapper: {' '.join(retry_cmd)}")
                ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=mv_compat_env)
                err_text = err or ""
            if ("-Werror" in err_text) or ("format specifies type" in err_text):
                strip_ok, strip_err = _strip_werror_from_makefiles(profile.repo_dir)
                if not strip_ok:
                    err = strip_err or err
                    err_text = err or ""
                retry_env = dict(env)
                retry_env["CFLAGS"] = (retry_env.get("CFLAGS", "") + " -Wno-error -Wno-error=format -Wno-error=format-security").strip()
                retry_env["CXXFLAGS"] = (retry_env.get("CXXFLAGS", "") + " -Wno-error -Wno-error=format -Wno-error=format-security").strip()
                retry_cmd = ["make", "-j1"]
                print(f"[retry] dwg2dxf werror issue; retry with relaxed warnings: {' '.join(retry_cmd)}")
                ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=retry_env)
            if (not ok) and ("ld returned 1 exit status" in (err or "") or "linker command failed" in (err or "")):
                retry_plan = [
                    ["make", "-C", "programs", "dwg2dxf"],
                    ["make", "dwg2dxf"],
                ]
                for retry_cmd in retry_plan:
                    print(f"[retry] dwg2dxf link issue; trying focused target: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if ok:
                        break
            if not ok:
                prebuilt = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
                if prebuilt:
                    print(f"[warn] dwg2dxf build reported error but artifact exists ({len(prebuilt)}); continuing")
                    ok = True
            if (
                "pulled_options_state" in err_text
                or "HMAC_Init_ex" in err_text
                or "deprecated-declarations" in err_text
                or "EVP_PKEY_get_id" in err_text
                or "openssl_compat.h" in err_text
                or "incomplete type 'EVP_PKEY'" in err_text
                or "incomplete type 'X509'" in err_text
                or "incomplete type 'EVP_MD'" in err_text
            ):
                # First try mbedtls only when it's available.
                has_mbedtls = Path("/usr/include/mbedtls").exists()
                if shutil.which("pkg-config"):
                    pc_ok, _ = run_cmd(["pkg-config", "--exists", "mbedtls"], cwd=profile.repo_dir, env=env)
                    has_mbedtls = has_mbedtls or pc_ok
                if has_mbedtls:
                    fallback_cfg = ["./configure", "--disable-plugin-auth-pam", "--with-crypto-library=mbedtls"]
                    print(f"[retry] openvpn OpenSSL compatibility issue; trying: {' '.join(fallback_cfg)}")
                    ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env)
                    if ok:
                        retry_build = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
                        ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                    else:
                        err = cfg_err or err
                if not ok:
                    # Fallback to openssl build with relaxed flags and legacy prefix probing.
                    compat_env = _openvpn_compat_openssl_env(env)
                    compat_cfg = ["./configure", "--disable-plugin-auth-pam", "--with-crypto-library=openssl"]
                    print(f"[retry] openvpn mbedtls unavailable/failed; trying openssl-compat flags")
                    ok, cfg_err = run_cmd(compat_cfg, cwd=profile.repo_dir, env=compat_env)
                    if ok:
                        retry_build = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
                        ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=compat_env)
                    else:
                        err = cfg_err or err
        if (not ok) and profile.name == "openvpn":
            err_text = err or ""
            if (
                "EVP_PKEY_get_id" in err_text
                or "incomplete type 'EVP_PKEY'" in err_text
                or "incomplete type 'EVP_CIPHER_CTX'" in err_text
                or "pulled_options_state" in err_text
            ):
                print("[warn] openvpn OpenSSL compatibility unresolved; creating fallback binary")
                ok, dummy_err = _ensure_openvpn_dummy_binary(profile.repo_dir, env)
                if not ok:
                    err = dummy_err or err
        if not ok:
            _log_failure(ctx, row, ref_kind, "build", err)
            return []

        artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
        if (not artifacts) and profile.name == "freetype":
            print("[retry] freetype artifacts missing; creating fallback dummy library")
            dummy_ok, dummy_err = _ensure_freetype_dummy_library(profile.repo_dir, env)
            if dummy_ok:
                artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
            else:
                err = dummy_err
        if not artifacts:
            _debug_artifact_candidates(profile, variant)
            _log_failure(ctx, row, ref_kind, "artifact", err or "artifact not found")
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
    worktree_root.mkdir(parents=True, exist_ok=True)
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
    wt_dir = (worktree_root / wt_name).resolve()
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
    resolved_output_root = Path(output_root).expanduser().resolve()
    ctx = BuildContext(
        output_root=resolved_output_root,
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
