from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock

from .models import BuildRow
from .profiles import BuildProfile, build_profiles, resolve_artifacts
from .utils import is_real_binary_or_library, parse_commit_hash, resolve_command, run_cmd
from .versioning import release_tags_in_range

MAX_FAILURE_LOG_LINES = int(os.getenv("MAX_FAILURE_LOG_LINES", "40"))
_TCPDUMP_LIBPCAP_LOCK = Lock()
_OPENVPN_OPENSSL_LOCK = Lock()


@dataclass
class BuildContext:
    output_root: Path
    failures: list[str]
    built_cache: set[tuple[str, str, str]]
    parallel_workers: int
    project_workers: int
    enable_pie: bool
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
        sig = [
            ln
            for ln in lines
            if (
                ("error:" in ln.lower())
                or ("undefined reference" in ln.lower())
                or ("fatal:" in ln.lower())
                or ("cannot find" in ln.lower())
                or ("ld:" in ln.lower())
            )
        ]
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
    with ctx.lock:
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
        if profile.name == "dwg2dxf" and first.endswith("autogen.sh"):
            # Some libredwg snapshots (e.g., release_0.11) have broken autotools metadata.
            # Skip autogen and prefer the shipped configure script when available.
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
        ok, err = _strip_werror_from_makefiles(profile.repo_dir)
        if not ok:
            return False, err
        ok, err = _patch_freetype_brotli_sources(profile.repo_dir)
        if not ok:
            return False, err

    # Some historical tags do not ship ./configure, but can still generate it.
    configure_missing = bool(profile.configure_cmd) and ("./configure" in profile.configure_cmd) and not configure_path.exists()
    if configure_missing:
        autogen = profile.repo_dir / "autogen.sh"
        if autogen.exists() and profile.name not in {"freetype", "libtiff", "dwg2dxf"}:
            ok, err = run_cmd(["sh", "./autogen.sh"], cwd=profile.repo_dir, env=env)
            if not ok:
                return False, err
        if (
            profile.name not in {"freetype", "dwg2dxf"}
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
                    # Many legacy freetype tags have no configure.ac; fall back to configure.raw directly.
                    ok, err_copy = run_cmd(
                        ["bash", "-lc", "cd builds/unix && cp configure.raw configure && chmod +x configure"],
                        cwd=profile.repo_dir,
                        env=env,
                    )
                    if not ok:
                        if (profile.repo_dir / "configure.ac").exists() or (profile.repo_dir / "configure.in").exists():
                            ok, err_auto = run_cmd(["autoreconf", "-fi"], cwd=profile.repo_dir, env=env)
                            if not ok:
                                return False, f"{err}\n{err_auto}"
                        else:
                            return False, f"{err}\n{err_copy}"
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
        if (not configure_path.exists()) and profile.name == "dwg2dxf":
            ok, err = _ensure_dwg2dxf_configure_script(profile.repo_dir, env)
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


def _detect_openssl_prefix() -> Path | None:
    candidates = [
        os.getenv("OPENSSL_LEGACY_PREFIX", ""),
        os.getenv("OPENSSL_PREFIX", ""),
        "/home/user/openssl-1.1-install",
        "/home/user/BinForge/local/openssl-1.1",
        "/home/user/BinForge/local/openssl",
        "/usr/local/openssl-1.1",
        "/opt/openssl-1.1",
        "/opt/openssl",
        "/usr",
    ]
    for raw in candidates:
        if not raw:
            continue
        prefix = Path(raw)
        header = prefix / "include" / "openssl" / "evp.h"
        x509 = prefix / "include" / "openssl" / "x509.h"
        if header.exists() and x509.exists():
            return prefix
    return None


def _has_openssl_prefix(prefix: Path) -> bool:
    include_dir = prefix / "include" / "openssl"
    lib_dirs = [prefix / "lib", prefix / "lib64", prefix / "lib" / "x86_64-linux-gnu"]
    header_ok = (include_dir / "evp.h").exists() and (include_dir / "x509.h").exists()
    lib_ok = any((lib_dir / name).exists() for lib_dir in lib_dirs for name in ["libssl.so", "libssl.a", "libcrypto.so", "libcrypto.a"])
    return header_ok and lib_ok


def _ensure_openvpn_openssl_dependency(profile: BuildProfile, env: dict[str, str]) -> tuple[bool, dict[str, str], str]:
    existing = _detect_openssl_prefix()
    if existing and _has_openssl_prefix(existing):
        return True, _apply_openssl_prefix(env, existing), ""

    src_dir = Path(os.getenv("OPENSSL_SRC_DIR", str(profile.repo_dir.parent / "openssl-1.1-src")))
    prefix = Path(os.getenv("OPENSSL_PREFIX", str(profile.repo_dir.parent / "openssl-1.1-install")))
    with _OPENVPN_OPENSSL_LOCK:
        if _has_openssl_prefix(prefix):
            print(f"[openvpn-fix] using built OpenSSL prefix: {prefix}")
            return True, _apply_openssl_prefix(env, prefix), ""

        if not src_dir.exists():
            ref = os.getenv("OPENSSL_REF", "OpenSSL_1_1_1w")
            ok, err = run_cmd(
                ["git", "clone", "--depth", "1", "--branch", ref, "https://github.com/openssl/openssl.git", str(src_dir)],
                cwd=profile.repo_dir.parent,
                quiet_stdout=False,
            )
            if not ok:
                return False, env, err
        elif (src_dir / ".git").exists() and os.getenv("OPENSSL_REF"):
            ref = os.getenv("OPENSSL_REF", "")
            ok, err = run_cmd(["git", "fetch", "--tags"], cwd=src_dir, env=env)
            if not ok:
                return False, env, err
            ok, err = run_cmd(["git", "checkout", "-f", ref], cwd=src_dir, env=env)
            if not ok:
                return False, env, err

        if not (src_dir / "Configure").exists():
            return False, env, f"OpenSSL Configure not found: {src_dir / 'Configure'}"

        prefix.mkdir(parents=True, exist_ok=True)
        build_env = dict(env)
        run_cmd(["make", "clean"], cwd=src_dir, env=build_env)
        ok, err = run_cmd(
            ["perl", "Configure", "linux-x86_64", "shared", "no-tests", f"--prefix={prefix}", f"--openssldir={prefix / 'ssl'}"],
            cwd=src_dir,
            env=build_env,
            quiet_stdout=False,
        )
        if not ok:
            return False, env, err
        ok, err = run_cmd(["make", f"-j{max(1, os.cpu_count() or 1)}"], cwd=src_dir, env=build_env)
        if not ok:
            return False, env, err
        ok, err = run_cmd(["make", "install_sw"], cwd=src_dir, env=build_env)
        if not ok:
            return False, env, err
        if not _has_openssl_prefix(prefix):
            return False, env, f"OpenSSL build completed but no usable headers/library found under {prefix}"

    print(f"[openvpn-fix] built OpenSSL prefix: {prefix}")
    return True, _apply_openssl_prefix(env, prefix), ""


def _prepend_env_tokens(env: dict[str, str], key: str, tokens: list[str]) -> None:
    existing = env.get(key, "").split()
    merged: list[str] = []
    for token in [*tokens, *existing]:
        if token and token not in merged:
            merged.append(token)
    env[key] = " ".join(merged).strip()


def _remove_env_tokens(env: dict[str, str], key: str, tokens: set[str]) -> None:
    existing = env.get(key, "").split()
    env[key] = " ".join(token for token in existing if token not in tokens).strip()


def _filter_path_entries(value: str, blocked_parts: tuple[str, ...]) -> str:
    entries = []
    for entry in value.split(":"):
        if not entry:
            continue
        if any(part in entry for part in blocked_parts):
            continue
        entries.append(entry)
    return ":".join(entries)


def _existing_include_flag(header_relpath: str, candidates: list[Path]) -> str:
    for include_dir in candidates:
        if (include_dir / header_relpath).exists():
            return f"-I{include_dir}"
    return ""


def _existing_library_dir_flag(names: list[str], candidates: list[Path]) -> str:
    for lib_dir in candidates:
        if any((lib_dir / name).exists() for name in names):
            return f"-L{lib_dir}"
    return ""


def _apply_openssl_prefix(env: dict[str, str], prefix: Path) -> dict[str, str]:
    compat_env = dict(env)
    include_dir = prefix / "include"
    lib_dirs = [prefix / "lib", prefix / "lib64", prefix / "lib" / "x86_64-linux-gnu"]
    include_flag = f"-I{include_dir}"
    lib_tokens = [f"-L{lib_dir}" for lib_dir in lib_dirs if lib_dir.exists()]

    for key in ["CPPFLAGS", "CFLAGS", "CXXFLAGS", "AM_CPPFLAGS", "AM_CFLAGS"]:
        _prepend_env_tokens(compat_env, key, [include_flag])
    if lib_tokens:
        _prepend_env_tokens(compat_env, "LDFLAGS", lib_tokens)
    compat_env["OPENSSL_CFLAGS"] = include_flag
    compat_env["OPENSSL_LIBS"] = " ".join([*lib_tokens, "-lssl", "-lcrypto"]).strip()
    compat_env["CRYPTO_CFLAGS"] = include_flag
    compat_env["CRYPTO_LIBS"] = compat_env["OPENSSL_LIBS"]

    pkg_dirs = [lib_dir / "pkgconfig" for lib_dir in lib_dirs if (lib_dir / "pkgconfig").exists()]
    pkg = ":".join(str(p) for p in pkg_dirs)
    if pkg:
        compat_env["PKG_CONFIG_PATH"] = f"{pkg}:{compat_env.get('PKG_CONFIG_PATH', '')}".strip(":")

    ld_lib = compat_env.get("LD_LIBRARY_PATH", "").strip()
    lib_path = ":".join(str(lib_dir) for lib_dir in lib_dirs if lib_dir.exists())
    if lib_path:
        compat_env["LD_LIBRARY_PATH"] = f"{lib_path}:{ld_lib}".strip(":")
    _remove_env_tokens(compat_env, "LIBS", {"-lssl", "-lcrypto"})
    return compat_env


def _openvpn_compat_openssl_env(base_env: dict[str, str]) -> dict[str, str]:
    compat_env = dict(base_env)
    # Drop forced /usr/local OpenSSL include/lib paths; many environments keep OpenSSL 3.x there.
    cpp_tokens = [t for t in compat_env.get("CPPFLAGS", "").split() if "/usr/local/include" not in t]
    ld_tokens = [t for t in compat_env.get("LDFLAGS", "").split() if "/usr/local/lib" not in t and "/usr/local/lib64" not in t]
    compat_env["CPPFLAGS"] = " ".join(cpp_tokens).strip()
    compat_env["LDFLAGS"] = " ".join(ld_tokens).strip()
    compat_env["PKG_CONFIG_PATH"] = _filter_path_entries(
        compat_env.get("PKG_CONFIG_PATH", ""),
        ("/usr/local/lib/pkgconfig", "/usr/local/lib64/pkgconfig", "/usr/local/share/pkgconfig"),
    )

    openssl_prefix = _detect_openssl_legacy_prefix() or _detect_openssl_prefix()
    if openssl_prefix:
        compat_env = _apply_openssl_prefix(compat_env, openssl_prefix)
        print(f"[openvpn-fix] using OpenSSL prefix: {openssl_prefix}")
    else:
        print("[openvpn-fix] OpenSSL prefix not found; retrying without /usr/local OpenSSL paths")
    header_flag = _existing_include_flag(
        "openssl/evp.h",
        [
            Path("/usr/include"),
            Path("/usr/include/x86_64-linux-gnu"),
            Path("/opt/openssl/include"),
            Path("/opt/openssl-1.1/include"),
        ],
    )
    lib_flag = _existing_library_dir_flag(
        ["libssl.so", "libssl.a", "libcrypto.so", "libcrypto.a"],
        [
            Path("/usr/lib/x86_64-linux-gnu"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib64"),
            Path("/lib64"),
            Path("/opt/openssl/lib"),
            Path("/opt/openssl-1.1/lib"),
        ],
    )
    if header_flag:
        _prepend_env_tokens(compat_env, "CPPFLAGS", [header_flag])
        _prepend_env_tokens(compat_env, "CFLAGS", [header_flag])
        compat_env["OPENSSL_CFLAGS"] = header_flag
    if lib_flag:
        _prepend_env_tokens(compat_env, "LDFLAGS", [lib_flag])
    openssl_cflags = _pkg_config_output("openssl", "--cflags")
    openssl_libs = _pkg_config_output("openssl", "--libs")
    if openssl_cflags:
        _prepend_env_tokens(compat_env, "CPPFLAGS", openssl_cflags.split())
        _prepend_env_tokens(compat_env, "CFLAGS", openssl_cflags.split())
        compat_env["OPENSSL_CFLAGS"] = openssl_cflags
    if openssl_libs:
        ld_flags = " ".join(tok for tok in openssl_libs.split() if tok.startswith("-L"))
        link_libs = " ".join(tok for tok in openssl_libs.split() if not tok.startswith("-L"))
        if ld_flags:
            _prepend_env_tokens(compat_env, "LDFLAGS", ld_flags.split())
        if link_libs:
            compat_env["OPENSSL_LIBS"] = link_libs
    else:
        compat_env.setdefault("OPENSSL_LIBS", "-lssl -lcrypto")
    _remove_env_tokens(compat_env, "LIBS", {"-lssl", "-lcrypto"})
    compat_env["ac_cv_header_openssl_ssl_h"] = "yes"
    compat_env["ac_cv_header_openssl_evp_h"] = "yes"
    compat_env["ac_cv_header_openssl_x509_h"] = "yes"
    compat_env["ac_cv_lib_ssl_SSL_new"] = "yes"
    compat_env["ac_cv_lib_crypto_EVP_CIPHER_CTX_new"] = "yes"
    compat_env["CFLAGS"] = (
        compat_env.get("CFLAGS", "") + " -Wno-error=deprecated-declarations -Wno-error -DOPENSSL_API_COMPAT=0x10100000L"
    ).strip()
    compat_env["CXXFLAGS"] = (
        compat_env.get("CXXFLAGS", "") + " -Wno-error=deprecated-declarations -Wno-error -DOPENSSL_API_COMPAT=0x10100000L"
    ).strip()
    return compat_env


def _with_system_include_lib_paths(base_env: dict[str, str]) -> dict[str, str]:
    compat_env = dict(base_env)
    cpp = compat_env.get("CPPFLAGS", "").strip()
    ld = compat_env.get("LDFLAGS", "").strip()
    compat_env["CPPFLAGS"] = f"-I/usr/include -I/usr/include/x86_64-linux-gnu {cpp}".strip()
    compat_env["LDFLAGS"] = f"-L/usr/lib/x86_64-linux-gnu -L/lib/x86_64-linux-gnu -L/usr/lib64 -L/lib64 {ld}".strip()
    return compat_env


def _pkg_config_output(package: str, flag: str) -> str:
    if not shutil.which("pkg-config"):
        return ""
    try:
        proc = subprocess.run(
            ["pkg-config", flag, package],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _tcpdump_compat_env(base_env: dict[str, str]) -> dict[str, str]:
    compat_env = _with_system_include_lib_paths(base_env)
    bad_prefix = "/home/user/BinForge/local/libpcap"
    cpp_tokens = [t for t in compat_env.get("CPPFLAGS", "").split() if bad_prefix not in t]
    ld_tokens = [t for t in compat_env.get("LDFLAGS", "").split() if bad_prefix not in t]
    compat_env["CPPFLAGS"] = " ".join(cpp_tokens).strip()
    compat_env["LDFLAGS"] = " ".join(ld_tokens).strip()
    header_flag = _existing_include_flag(
        "pcap.h",
        [
            Path("/usr/include"),
            Path("/usr/include/x86_64-linux-gnu"),
            Path("/usr/local/include"),
            Path("/opt/libpcap/include"),
        ],
    )
    if not header_flag:
        header_flag = _existing_include_flag(
            "pcap/pcap.h",
            [
                Path("/usr/include"),
                Path("/usr/include/x86_64-linux-gnu"),
                Path("/usr/local/include"),
                Path("/opt/libpcap/include"),
            ],
        )
    lib_flag = _existing_library_dir_flag(
        ["libpcap.so", "libpcap.a"],
        [
            Path("/usr/lib/x86_64-linux-gnu"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib64"),
            Path("/lib64"),
            Path("/usr/local/lib"),
            Path("/opt/libpcap/lib"),
        ],
    )
    if header_flag:
        _prepend_env_tokens(compat_env, "CPPFLAGS", [header_flag])
        _prepend_env_tokens(compat_env, "CFLAGS", [header_flag])
        compat_env["LIBPCAP_CFLAGS"] = header_flag
    if lib_flag:
        _prepend_env_tokens(compat_env, "LDFLAGS", [lib_flag])

    for pkg in ["libpcap", "pcap"]:
        cflags = _pkg_config_output(pkg, "--cflags")
        libs = _pkg_config_output(pkg, "--libs")
        if cflags:
            _prepend_env_tokens(compat_env, "CPPFLAGS", cflags.split())
            _prepend_env_tokens(compat_env, "CFLAGS", cflags.split())
            compat_env["LIBPCAP_CFLAGS"] = cflags
        if libs:
            ld_flags = " ".join(tok for tok in libs.split() if tok.startswith("-L"))
            link_libs = " ".join(tok for tok in libs.split() if not tok.startswith("-L"))
            if ld_flags:
                _prepend_env_tokens(compat_env, "LDFLAGS", ld_flags.split())
            if link_libs:
                compat_env["LIBPCAP_LIBS"] = link_libs
        if cflags or libs:
            break
    pcap_config = shutil.which("pcap-config")
    if pcap_config:
        compat_env["PCAP_CONFIG"] = pcap_config
        pc_cflags = _pkg_config_output("libpcap", "--cflags")
        pc_libs = _pkg_config_output("libpcap", "--libs")
        if not pc_cflags:
            try:
                proc = subprocess.run([pcap_config, "--cflags"], capture_output=True, text=True, check=False)
                pc_cflags = (proc.stdout or "").strip() if proc.returncode == 0 else ""
            except OSError:
                pc_cflags = ""
        if not pc_libs:
            try:
                proc = subprocess.run([pcap_config, "--libs"], capture_output=True, text=True, check=False)
                pc_libs = (proc.stdout or "").strip() if proc.returncode == 0 else ""
            except OSError:
                pc_libs = ""
        if pc_cflags:
            _prepend_env_tokens(compat_env, "CPPFLAGS", pc_cflags.split())
            _prepend_env_tokens(compat_env, "CFLAGS", pc_cflags.split())
            compat_env["LIBPCAP_CFLAGS"] = pc_cflags
        if pc_libs:
            ld_flags = " ".join(tok for tok in pc_libs.split() if tok.startswith("-L"))
            link_libs = " ".join(tok for tok in pc_libs.split() if not tok.startswith("-L"))
            if ld_flags:
                _prepend_env_tokens(compat_env, "LDFLAGS", ld_flags.split())
            if link_libs:
                compat_env["LIBPCAP_LIBS"] = link_libs
    if "LIBPCAP_LIBS" not in compat_env:
        compat_env["LIBPCAP_LIBS"] = "-lpcap"
    _remove_env_tokens(compat_env, "LIBS", {"-lpcap"})
    compat_env["ac_cv_header_pcap_h"] = "yes"
    compat_env["ac_cv_header_pcap_pcap_h"] = "yes"
    compat_env["ac_cv_func_pcap_loop"] = "yes"
    compat_env["ac_cv_lib_pcap_pcap_loop"] = "yes"
    return compat_env


def _has_libpcap_prefix(prefix: Path) -> bool:
    include_dir = prefix / "include"
    lib_dirs = [prefix / "lib", prefix / "lib64"]
    header_ok = (include_dir / "pcap.h").exists() or (include_dir / "pcap" / "pcap.h").exists()
    lib_ok = any((lib_dir / name).exists() for lib_dir in lib_dirs for name in ["libpcap.so", "libpcap.a"])
    return header_ok and lib_ok


def _apply_libpcap_prefix(env: dict[str, str], prefix: Path) -> dict[str, str]:
    compat_env = dict(env)
    include_dir = prefix / "include"
    lib_dir = prefix / "lib"
    lib64_dir = prefix / "lib64"
    lib_tokens = [f"-L{p}" for p in [lib_dir, lib64_dir] if p.exists()]
    _prepend_env_tokens(compat_env, "CPPFLAGS", [f"-I{include_dir}"])
    _prepend_env_tokens(compat_env, "CFLAGS", [f"-I{include_dir}"])
    if lib_tokens:
        _prepend_env_tokens(compat_env, "LDFLAGS", lib_tokens)
    compat_env["LIBPCAP_CFLAGS"] = f"-I{include_dir}"
    compat_env["LIBPCAP_LIBS"] = " ".join([*lib_tokens, "-lpcap"]).strip()
    compat_env["PKG_CONFIG_PATH"] = ":".join(
        str(p) for p in [lib_dir / "pkgconfig", lib64_dir / "pkgconfig"] if p.exists()
    ) + ((":" + compat_env.get("PKG_CONFIG_PATH", "")) if compat_env.get("PKG_CONFIG_PATH") else "")
    pcap_config = prefix / "bin" / "pcap-config"
    if pcap_config.exists():
        compat_env["PCAP_CONFIG"] = str(pcap_config)
    ld_lib = compat_env.get("LD_LIBRARY_PATH", "").strip()
    compat_env["LD_LIBRARY_PATH"] = ":".join(str(p) for p in [lib_dir, lib64_dir] if p.exists())
    if ld_lib:
        compat_env["LD_LIBRARY_PATH"] = f"{compat_env['LD_LIBRARY_PATH']}:{ld_lib}".strip(":")
    _remove_env_tokens(compat_env, "LIBS", {"-lpcap"})
    return compat_env


def _ensure_tcpdump_libpcap_dependency(profile: BuildProfile, env: dict[str, str]) -> tuple[bool, dict[str, str], str]:
    prefixes = [Path("/home/user/BinForge/local/libpcap"), profile.repo_dir.parent / "libpcap-install"]
    if os.getenv("LIBPCAP_PREFIX"):
        prefixes.insert(0, Path(os.getenv("LIBPCAP_PREFIX", "")))
    for prefix in prefixes:
        if _has_libpcap_prefix(prefix):
            print(f"[tcpdump-fix] using libpcap prefix: {prefix}")
            return True, _apply_libpcap_prefix(env, prefix), ""

    src_dir = Path(os.getenv("LIBPCAP_DIR", str(profile.repo_dir.parent / "libpcap")))
    prefix = Path(os.getenv("LIBPCAP_PREFIX", str(profile.repo_dir.parent / "libpcap-install")))
    with _TCPDUMP_LIBPCAP_LOCK:
        if _has_libpcap_prefix(prefix):
            print(f"[tcpdump-fix] using libpcap prefix: {prefix}")
            return True, _apply_libpcap_prefix(env, prefix), ""

        if not src_dir.exists():
            ref = os.getenv("LIBPCAP_REF", "libpcap-1.9.1")
            ok, err = run_cmd(
                ["git", "clone", "--depth", "1", "--branch", ref, "https://github.com/the-tcpdump-group/libpcap.git", str(src_dir)],
                cwd=profile.repo_dir.parent,
                quiet_stdout=False,
            )
            if not ok:
                ok, err = run_cmd(
                    ["git", "clone", "https://github.com/the-tcpdump-group/libpcap.git", str(src_dir)],
                    cwd=profile.repo_dir.parent,
                    quiet_stdout=False,
                )
                if not ok:
                    return False, env, err

        dep_env = dict(env)
        if (src_dir / ".git").exists() and os.getenv("LIBPCAP_REF"):
            ref = os.getenv("LIBPCAP_REF", "")
            ok, err = run_cmd(["git", "fetch", "--tags"], cwd=src_dir, env=dep_env)
            if not ok:
                return False, env, err
            ok, err = run_cmd(["git", "checkout", "-f", ref], cwd=src_dir, env=dep_env)
            if not ok:
                return False, env, err

        configure = src_dir / "configure"
        if not configure.exists() and (src_dir / "autogen.sh").exists():
            ok, err = run_cmd(["sh", "./autogen.sh"], cwd=src_dir, env=dep_env)
            if not ok:
                return False, env, err
        if not configure.exists():
            return False, env, f"libpcap configure not found: {configure}"

        prefix.mkdir(parents=True, exist_ok=True)
        run_cmd(["make", "distclean"], cwd=src_dir, env=dep_env)
        ok, err = run_cmd(["./configure", f"--prefix={prefix}"], cwd=src_dir, env=dep_env)
        if not ok:
            return False, env, err
        ok, err = run_cmd(["make", f"-j{max(1, os.cpu_count() or 1)}"], cwd=src_dir, env=dep_env)
        if not ok:
            return False, env, err
        ok, err = run_cmd(["make", "install"], cwd=src_dir, env=dep_env)
        if not ok:
            return False, env, err
        if not _has_libpcap_prefix(prefix):
            return False, env, f"libpcap build completed but no usable headers/library found under {prefix}"

    print(f"[tcpdump-fix] built libpcap prefix: {prefix}")
    return True, _apply_libpcap_prefix(env, prefix), ""


def _detect_zlib_for_cmake() -> tuple[str, str]:
    include_candidates = [
        Path("/usr/include"),
        Path("/usr/include/x86_64-linux-gnu"),
    ]
    lib_candidates = [
        Path("/usr/lib/x86_64-linux-gnu/libz.so"),
        Path("/usr/lib/x86_64-linux-gnu/libz.a"),
        Path("/lib/x86_64-linux-gnu/libz.so"),
        Path("/lib/x86_64-linux-gnu/libz.a"),
        Path("/usr/lib64/libz.so"),
        Path("/usr/lib64/libz.a"),
        Path("/usr/lib/libz.so"),
        Path("/usr/lib/libz.a"),
    ]

    include_dir = ""
    lib_path = ""
    for cand in include_candidates:
        if (cand / "zlib.h").exists():
            include_dir = str(cand)
            break
    for cand in lib_candidates:
        if cand.exists():
            lib_path = str(cand)
            break

    if not include_dir:
        pc_cflags = _pkg_config_output("zlib", "--cflags-only-I")
        for token in pc_cflags.split():
            if token.startswith("-I"):
                path = token[2:]
                if path and Path(path, "zlib.h").exists():
                    include_dir = path
                    break
    if not lib_path:
        pc_libs = _pkg_config_output("zlib", "--libs-only-L")
        for token in pc_libs.split():
            if token.startswith("-L"):
                for leaf in ["libz.so", "libz.a"]:
                    cand = Path(token[2:]) / leaf
                    if cand.exists():
                        lib_path = str(cand)
                        break
                if lib_path:
                    break
    return include_dir, lib_path


def _looks_like_autoconf_input(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    head = "\n".join(text.splitlines()[:40])
    return "AC_INIT(" in head or "AC_PREREQ(" in head


def _resolve_git_dir(repo_dir: Path) -> Path:
    dot_git = repo_dir / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():
        try:
            text = dot_git.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return dot_git
        m = re.search(r"gitdir:\s*(.+)", text)
        if m:
            cand = (repo_dir / m.group(1).strip()).resolve()
            return cand
    return dot_git


def _ensure_autotools_aux_files(base_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    names = ["install-sh", "config.guess", "config.sub", "compile"]
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
                    if name in {"install-sh", "config.guess", "config.sub", "compile"}:
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
                    if name in {"install-sh", "config.guess", "config.sub", "compile"}:
                        run_cmd(["chmod", "+x", str(base_dir / name)], cwd=base_dir, env=env)
                    copied = True
                    break
                except OSError:
                    continue
        if copied:
            missing.remove(name)

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


def _patch_openvpn_disable_openssl_check(repo_dir: Path) -> tuple[bool, str]:
    cfg = repo_dir / "configure"
    if not cfg.exists():
        return True, ""
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return False, str(exc)

    new = text
    new = new.replace("configure: error: openssl check failed", "configure: warning: openssl check bypassed")
    new = re.sub(
        r"as_fn_error([^\n]*openssl check failed[^\n]*)",
        r"echo\1",
        new,
    )
    new = re.sub(
        r"as_fn_error([^\n]*openssl check bypassed[^\n]*)",
        r"echo\1",
        new,
    )
    new = new.replace(
        'if test "x$have_openssl_engine" != "xyes"; then',
        'if false; then # patched: disable strict openssl engine requirement',
    )
    new = new.replace(
        'if test "x$have_openssl" != "xyes"; then',
        'if false; then # patched: disable strict openssl requirement',
    )
    new = re.sub(r"\bhave_openssl=\$\{have_openssl-no\}", "have_openssl=yes", new)
    new = re.sub(r"\bhave_openssl_engine=\$\{have_openssl_engine-no\}", "have_openssl_engine=yes", new)
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
        if 'have_librsvg="yes (pkg-config)", have_librsvg=no)' in stripped:
            new_lines.append("have_librsvg=no # patched malformed librsvg check")
            changed = True
            continue
        if (
            stripped.startswith("PKG_PROG_PKG_CONFIG(")
            or stripped.startswith("PKG_CHECK_MODULES(")
            or stripped.startswith("PKG_CHECK_EXISTS(")
            or stripped.startswith("PKG_WITH_MODULES(")
            or stripped.startswith("LT_INIT(")
            or stripped.startswith("LT_PREREQ(")
            or stripped.startswith("AC_PROG_LIBTOOL")
            or stripped.startswith("AM_PROG_LIBTOOL")
            or stripped.startswith("AX_PROG_PYTHON_VERSION(")
            or stripped.startswith("AX_PTHREAD(")
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


def _ensure_freetype_unix_libtool(repo_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    """
    Some freetype tags require ./builds/unix/libtool during make, but it is occasionally
    missing after checkout/configure in detached worktrees.
    """
    unix_dir = repo_dir / "builds" / "unix"
    unix_libtool = unix_dir / "libtool"
    if unix_libtool.exists() and os.access(unix_libtool, os.X_OK):
        # If this is our minimal wrapper, keep healing until a real libtool script exists.
        try:
            existing = unix_libtool.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            existing = ""
        if "freetype libtool script not found" not in existing:
            return True, ""

    bootstrap_cmds = [
        [
            "bash",
            "-lc",
            "cd builds/unix && "
            "(test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && "
            "(libtoolize --force --copy || glibtoolize --force --copy || true) && "
            "(bash ./configure --enable-shared || bash ./configure)",
        ],
    ]
    has_autoreconf_inputs = any(
        p.exists()
        for p in (
            repo_dir / "configure.ac",
            repo_dir / "configure.in",
            repo_dir / "builds" / "unix" / "configure.ac",
            repo_dir / "builds" / "unix" / "configure.in",
        )
    )
    if has_autoreconf_inputs:
        bootstrap_cmds.extend(
            [
                ["bash", "-lc", "cd builds/unix && (libtoolize --force --copy || glibtoolize --force --copy || true) && autoreconf -fi"],
                ["bash", "-lc", "(libtoolize --force --copy || glibtoolize --force --copy || true) && autoreconf -fi"],
                ["bash", "-lc", "cd builds/unix && autoreconf -fi"],
                ["autoreconf", "-fi"],
            ]
        )
    last_err = ""
    for cmd in bootstrap_cmds:
        ok, err = run_cmd(cmd, cwd=repo_dir, env=env)
        if ok and unix_libtool.exists():
            run_cmd(["chmod", "+x", str(unix_libtool)], cwd=repo_dir, env=env)
            try:
                generated = unix_libtool.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                generated = ""
            if "freetype libtool script not found" not in generated:
                return True, ""
        if err:
            last_err = err

    root_libtool = repo_dir / "libtool"
    if root_libtool.exists():
        try:
            unix_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root_libtool, unix_libtool)
        except OSError as exc:
            return False, str(exc)
        run_cmd(["chmod", "+x", str(unix_libtool)], cwd=repo_dir, env=env)
        if unix_libtool.exists():
            print("[freetype-fix] copied top-level libtool to builds/unix/libtool")
            return True, ""

    wrapper_lines = [
        "#!/usr/bin/env sh",
        'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        'TAG=""',
        'case " $* " in',
        '  *" --tag="*) TAG="";;',
        '  *) TAG="--tag=CC";;',
        "esac",
        'if [ -x "$SCRIPT_DIR/libtool.real" ]; then',
        '  exec "$SCRIPT_DIR/libtool.real" $TAG "$@"',
        "fi",
        'if [ -x "$SCRIPT_DIR/../libtool" ]; then',
        '  exec "$SCRIPT_DIR/../libtool" $TAG "$@"',
        "fi",
        'if [ -x "$SCRIPT_DIR/../../libtool" ]; then',
        '  exec "$SCRIPT_DIR/../../libtool" $TAG "$@"',
        "fi",
        'if command -v libtool >/dev/null 2>&1; then',
        '  _lt="$(command -v libtool)"',
        '  if ! grep -q "@RC@" "$_lt" 2>/dev/null; then',
        '    exec "$_lt" $TAG "$@"',
        "  fi",
        "fi",
        'if command -v glibtool >/dev/null 2>&1; then',
        '  _lt="$(command -v glibtool)"',
        '  if ! grep -q "@RC@" "$_lt" 2>/dev/null; then',
        '    exec "$_lt" $TAG "$@"',
        "  fi",
        "fi",
        'echo "freetype libtool script not found" >&2',
        "exit 127",
    ]
    try:
        unix_dir.mkdir(parents=True, exist_ok=True)
        if unix_libtool.exists():
            try:
                current = unix_libtool.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                current = ""
            if "freetype libtool script not found" not in current:
                # Preserve any non-wrapper libtool script as libtool.real.
                real_libtool = unix_dir / "libtool.real"
                try:
                    shutil.copy2(unix_libtool, real_libtool)
                    run_cmd(["chmod", "+x", str(real_libtool)], cwd=repo_dir, env=env)
                except OSError:
                    pass
        unix_libtool.write_text("\n".join(wrapper_lines) + "\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    run_cmd(["chmod", "+x", str(unix_libtool)], cwd=repo_dir, env=env)
    if unix_libtool.exists():
        print("[freetype-fix] created builds/unix/libtool wrapper")
        has_backend = any(
            p.exists() and os.access(p, os.X_OK)
            for p in (
                unix_dir / "libtool.real",
                unix_dir.parent / "libtool",
                repo_dir / "libtool",
            )
        )
        if has_backend:
            return True, ""
        sys_libtool_ok, _ = run_cmd(
            [
                "bash",
                "-lc",
                "lt=$(command -v libtool 2>/dev/null || command -v glibtool 2>/dev/null || true); "
                "test -n \"$lt\" && ! grep -q '@RC@' \"$lt\" 2>/dev/null",
            ],
            cwd=repo_dir,
            env=env,
        )
        if sys_libtool_ok:
            return True, ""
        # Do not fail configure stage only because backend libtool is absent yet.
        # Legacy tags can still proceed and resolve this during build retries.
        print("[freetype-fix] backend libtool script is not ready yet; continuing")
        return True, ""
    return False, last_err or "failed to provision builds/unix/libtool"


def _patch_freetype_libtool_tag(repo_dir: Path) -> tuple[bool, str]:
    targets: list[Path] = [
        repo_dir / "builds" / "freetype.mk",
        repo_dir / "builds" / "unix" / "freetype.mk",
    ]
    # Newer tags scatter libtool invocations across several *.mk files.
    for pat in ("**/*.mk", "**/Makefile", "**/Makefile.in"):
        for p in repo_dir.glob(pat):
            if p not in targets and p.is_file():
                targets.append(p)
    changed = False
    for mk in targets:
        if not mk.exists():
            continue
        try:
            text = mk.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        # Prefer forcing LIBTOOL variable itself so downstream rules cannot escape to /usr/bin/libtool.
        new = re.sub(
            r"^(\s*LIBTOOL\s*[:?+]?=\s*).*$",
            r"\1./builds/unix/libtool --tag=CC",
            text,
            flags=re.M,
        )
        new = re.sub(r"(\./builds/unix/libtool)\s+(--mode=)", r"\1 --tag=CC \2", new)
        new = re.sub(r"(\.\./builds/unix/libtool)\s+(--mode=)", r"\1 --tag=CC \2", new)
        # Force system/bare libtool calls to use the repository-local script.
        # Handle cases where extra args appear before --mode= (e.g., --silent).
        new = re.sub(r"(?<![\w./-])/usr/bin/libtool\b", r"./builds/unix/libtool --tag=CC", new)
        new = re.sub(r"(?<![\w./-])libtool\b", r"./builds/unix/libtool --tag=CC", new)
        # Cleanup accidental duplicate --tag injections after repeated retries.
        new = re.sub(r"(?:--tag=CC\s+){2,}", "--tag=CC ", new)
        if new != text:
            try:
                mk.write_text(new, encoding="utf-8")
            except OSError as exc:
                return False, str(exc)
            changed = True
    if changed:
        print("[freetype-fix] patched freetype makefiles to pass --tag=CC to libtool")
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
            if ("pngshim.c" in low) or ("ftbzip2.c" in low) or ("sfwoff2.c" in low) or ("brotli" in low):
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


def _patch_freetype_brotli_sources(repo_dir: Path) -> tuple[bool, str]:
    """
    Disable WOFF2/brotli compilation path in legacy freetype tags without host brotli headers.
    We do this by removing sfwoff2.c inclusion from sfnt.c and commenting module entries.
    """
    changed_any = False

    for path in repo_dir.glob("**/sfnt.c"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)
        new = re.sub(
            r'^\s*#\s*include\s*"sfwoff2\.c"\s*$',
            "/* #include \"sfwoff2.c\" */ /* patched: disable WOFF2/brotli */",
            text,
            flags=re.M,
        )
        if new != text:
            try:
                path.write_text(new, encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)

    module_files: list[Path] = []
    for p in repo_dir.glob("**/modules.cfg"):
        module_files.append(p)
    for p in repo_dir.glob("**/modules.cfg.in"):
        module_files.append(p)
    for p in repo_dir.glob("**/*.mk"):
        module_files.append(p)
    for path in module_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        new_lines: list[str] = []
        local_changed = False
        for ln in lines:
            low = ln.lower()
            if ("sfwoff2" in low) or ("brotli" in low):
                if ln.lstrip().startswith("#"):
                    new_lines.append(ln)
                else:
                    new_lines.append(f"# {ln}")
                local_changed = True
            else:
                new_lines.append(ln)
        if local_changed:
            try:
                path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                changed_any = True
            except OSError as exc:
                return False, str(exc)

    if changed_any:
        print("[freetype-fix] disabled sfwoff2/brotli sources")
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


def _patch_dwg2dxf_configure_ac(repo_dir: Path) -> tuple[bool, str]:
    """
    Some LibreDWG tags (e.g., release_0.11) have malformed AC_INIT in configure.ac,
    which makes autogen/autoreconf fail before ./configure is generated.
    """
    path = repo_dir / "configure.ac"
    if not path.exists():
        return True, ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return False, str(exc)

    m = re.search(r"AC_INIT\s*\(", text)
    if not m:
        return True, ""

    # Replace the whole AC_INIT(...) call with a minimal stable form.
    # We must parse balanced parentheses because nested calls such as m4_esyscmd(...)
    # appear inside AC_INIT args on some tags.
    open_paren = text.find("(", m.start())
    if open_paren == -1:
        return True, ""
    depth = 0
    close_paren = -1
    for i in range(open_paren, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_paren = i
                break
    if close_paren == -1:
        return False, "failed to parse AC_INIT(...) in configure.ac"

    replacement = "AC_INIT([libredwg],[0.11])"
    current = text[m.start() : close_paren + 1]
    if current.strip() == replacement:
        return True, ""
    new_text = text[: m.start()] + replacement + text[close_paren + 1 :]
    try:
        path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    print("[dwg2dxf-fix] patched malformed AC_INIT in configure.ac")
    return True, ""


def _ensure_dwg2dxf_configure_script(repo_dir: Path, env: dict[str, str]) -> tuple[bool, str]:
    cfg = repo_dir / "configure"
    if cfg.exists():
        run_cmd(["chmod", "+x", str(cfg)], cwd=repo_dir, env=env)
        ok, err = _ensure_autotools_aux_files(repo_dir, env)
        if not ok:
            return False, err
        return True, ""

    ok, err = _patch_dwg2dxf_configure_ac(repo_dir)
    if not ok:
        return False, err

    errors: list[str] = []
    autogen = repo_dir / "autogen.sh"
    if autogen.exists():
        ok, e = run_cmd(["sh", "./autogen.sh"], cwd=repo_dir, env=env)
        if ok and cfg.exists():
            run_cmd(["chmod", "+x", str(cfg)], cwd=repo_dir, env=env)
            return True, ""
        if e:
            errors.append(e)

    if (repo_dir / "configure.ac").exists() or (repo_dir / "configure.in").exists():
        ok, e = run_cmd(["autoreconf", "-fi"], cwd=repo_dir, env=env)
        if ok and cfg.exists():
            run_cmd(["chmod", "+x", str(cfg)], cwd=repo_dir, env=env)
            return True, ""
        if e:
            errors.append(e)

    if cfg.exists():
        run_cmd(["chmod", "+x", str(cfg)], cwd=repo_dir, env=env)
        ok, err = _ensure_autotools_aux_files(repo_dir, env)
        if not ok:
            return False, err
        return True, ""
    return False, "\n".join(errors) if errors else "dwg2dxf configure script was not generated"


def _patch_liblouis_tool_dependency(repo_dir: Path) -> tuple[bool, str]:
    targets: list[Path] = []
    for name in ["Makefile", "Makefile.in", "Makefile.am"]:
        targets.extend(repo_dir.rglob(name))
    changed_any = False

    for path in targets:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return False, str(exc)

        # Clean up any previously injected makefile entries to keep this idempotent.
        new_text = text.replace("\n../tools/libbrlcheck.la:\n\t@true\n", "\n")
        new_text = new_text.replace("\n../tools/libbrlcheck.la:\n    @true\n", "\n")
        new_text = new_text.replace("\n\\:\n\t@true\n", "\n")
        new_text = new_text.replace("\n\\:\n    @true\n", "\n")
        new_text = re.sub(r"(?m)^\s*\.\./tools/libbrlcheck\.la\s*:\s*(?:\n[ \t].*)?", "", new_text)
        new_text = re.sub(r"(?m)^\s*tools/libbrlcheck\.la\s*:\s*(?:\n[ \t].*)?", "", new_text)
        new_text = re.sub(
            r"(?m)^(\s*lou_checktable(?:\$\(EXEEXT\))?\s*:[^\n]*?)\s+\.\./tools/libbrlcheck\.la\b",
            r"\1",
            new_text,
        )
        new_text = re.sub(
            r"(?m)^(\s*lou_checktable(?:\$\(EXEEXT\))?_DEPENDENCIES\s*=.*?)\s+\.\./tools/libbrlcheck\.la\b",
            r"\1",
            new_text,
        )
        new_text = re.sub(
            r"(?m)^(\s*lou_checktable(?:\$\(EXEEXT\))?_LDADD\s*=.*?)\s+\.\./tools/libbrlcheck\.la\b",
            r"\1",
            new_text,
        )
        new_text = re.sub(
            r"(?m)^(\s*am_lou_checktable_OBJECTS\s*=.*)$",
            r"\1",
            new_text,
        )
        new_text = re.sub(r"(?m)([ \t])(?:\.\./)?tools/libbrlcheck\.la\b", "", new_text)
        new_text = re.sub(r"(?m)([ \t])\$\(top_builddir\)/tools/libbrlcheck\.la\b", "", new_text)
        new_text = re.sub(r"(?m)([ \t])\$\(top_srcdir\)/tools/libbrlcheck\.la\b", "", new_text)
        new_text = new_text.replace(" ../tools/libbrlcheck.la", "")
        new_text = new_text.replace("\t../tools/libbrlcheck.la", "")
        if new_text == text:
            continue
        try:
            path.write_text(new_text, encoding="utf-8")
            changed_any = True
        except OSError as exc:
            return False, str(exc)

    if changed_any:
        print("[liblouis-fix] removed stale libbrlcheck makefile dependency")
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
            "**/freetype*.so*",
            "**/freetype*.a",
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


def _compiler_can_link(cc: str, env: dict[str, str], cflags: str = "", ldflags: str = "") -> tuple[bool, str]:
    if not cc:
        return False, "empty compiler"
    with tempfile.TemporaryDirectory(prefix="binforge_cc_probe_") as tmp:
        tmp_dir = Path(tmp)
        src = tmp_dir / "probe.c"
        out = tmp_dir / "probe"
        src.write_text("int main(void){return 0;}\n", encoding="ascii")
        libs = env.get("LIBS", "")
        cmd = [cc, *cflags.split(), str(src), "-o", str(out), *ldflags.split(), *libs.split()]
        try:
            proc = subprocess.run(
                cmd,
                cwd=tmp,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError as exc:
            return False, str(exc)
        if proc.returncode == 0 and out.exists():
            return True, ""
        err = (proc.stderr or proc.stdout or "").strip()
        return False, err or f"compiler exited with {proc.returncode}"


def _linkable_c_compiler(preferred: str, family: str, env: dict[str, str]) -> tuple[str, str]:
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
    if family == "clang":
        candidates.extend(["clang"])
    else:
        candidates.extend(["gcc", "cc"])

    seen: set[str] = set()
    for cand in candidates:
        resolved = cand
        if not os.path.isabs(cand):
            resolved = shutil.which(cand) or cand
        if resolved in seen:
            continue
        seen.add(resolved)
        ok, _ = _compiler_can_link(resolved, env, env.get("CFLAGS", ""), env.get("LDFLAGS", ""))
        if ok:
            return resolved, ""

    ok, err = _compiler_can_link(preferred, env, env.get("CFLAGS", ""), env.get("LDFLAGS", ""))
    return "", err


def _linkable_cxx_compiler(preferred: str, family: str) -> str:
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
    if family == "clang":
        candidates.extend(["clang++"])
    else:
        candidates.extend(["g++", "c++"])
    for cand in candidates:
        if os.path.isabs(cand):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        resolved = shutil.which(cand)
        if resolved:
            return resolved
    return preferred or ("clang++" if family == "clang" else "g++")


def _ensure_linkable_c_compiler(env: dict[str, str], variant: BuildVariant, project: str) -> None:
    cc = env.get("CC", "").strip()
    ok, err = _compiler_can_link(cc, env, env.get("CFLAGS", ""), env.get("LDFLAGS", ""))
    if ok:
        return

    fallback, fallback_err = _linkable_c_compiler(cc, variant.compiler, env)
    if fallback:
        old_cxx = env.get("CXX", "").strip()
        env["CC"] = fallback
        env["CXX"] = _linkable_cxx_compiler(old_cxx, variant.compiler)
        print(
            f"[toolchain-fix] project={project} variant={variant.key} "
            f"compiler could not link; switched CC {cc or '<empty>'} -> {fallback}"
        )
        if err:
            print(f"[toolchain-fix] original link failure: {_short_error(err)}")
        return

    print(
        f"[toolchain-warn] project={project} variant={variant.key} "
        f"no linkable compiler fallback found: {_short_error(fallback_err or err)}"
    )


def _append_config_log_tail(err: str, repo_dir: Path) -> str:
    config_log = repo_dir / "config.log"
    if not config_log.exists():
        return err
    try:
        text = config_log.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return err
    tail = text[-6000:].strip()
    if not tail:
        return err
    if "[config.log-tail]" in err:
        return err
    return f"{err}\n[config.log-tail]\n{tail}".strip()


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


def _append_flag(flags: str, flag: str) -> str:
    tokens = flags.split()
    if flag in tokens:
        return flags.strip()
    return f"{flags} {flag}".strip()


def _openssl_debug_configure_args(env: dict[str, str]) -> list[str]:
    tokens = env.get("CFLAGS", "").split()
    cflags = " ".join(tokens)
    m = re.search(r"(?<!\S)-O(0|1|2|3|s|fast)(?=\s|$)", cflags)
    args = ["-g"]
    for flag in tokens:
        if flag in {"-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-pie", "-fno-PIE"}:
            args.append(flag)
    opt = f"-O{m.group(1)}" if m else "-O0"
    args.append(opt)
    return args


def _openssl_configure_args(env: dict[str, str], row: BuildRow) -> list[str]:
    # CVE-2016-2176 targets X509_NAME_oneline's EBCDIC-specific path.
    extra = ["-DCHARSET_EBCDIC"] if row.cve == "CVE-2016-2176" else []
    return [
        "perl",
        "Configure",
        "linux-x86_64",
        "shared",
        "no-asm",
        *_openssl_debug_configure_args(env),
        *extra,
    ]


def _cache_variant_key(profile: BuildProfile, row: BuildRow, variant: BuildVariant) -> str:
    if profile.name == "openssl" and row.cve == "CVE-2016-2176":
        return f"{variant.key}_ebcdic"
    return variant.key


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
    cache_variant_key = _cache_variant_key(profile, row, variant)
    cache_key = (profile.name, ref, cache_variant_key)
    cache_dir = ctx.output_root / "_cache" / profile.name / ref / cache_variant_key
    cached_files = [p for p in cache_dir.iterdir() if p.is_file()] if cache_dir.exists() else []
    if cached_files:
        print(f"[cache-hit] project={profile.name} ref={ref} variant={variant.key}")
        return cached_files
    with ctx.lock:
        if cache_key in ctx.built_cache and cache_dir.exists():
            print(f"[cache-hit] project={profile.name} ref={ref} variant={variant.key}")
            return [p for p in cache_dir.iterdir() if p.is_file()]

    env = os.environ.copy()
    # Prevent caller-shell git overrides from breaking detached worktree builds.
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    env.pop("GIT_INDEX_FILE", None)
    env.update(profile.env_overrides)
    env.update(variant.env_overrides)
    if profile.name in {"tcpdump", "libxml2", "exiv2", "openvpn"}:
        env = _with_system_include_lib_paths(env)
    if profile.name == "tcpdump":
        env = _tcpdump_compat_env(env)
    if profile.name == "openvpn":
        env = _openvpn_compat_openssl_env(env)
    if ctx.enable_pie:
        if profile.name == "dwg2dxf":
            # Legacy dwg2dxf tags (e.g., 0.5) frequently fail PIE linking due to non-PIE objects.
            # Keep global PIE mode on for other projects, but force no-PIE for this project.
            env["CFLAGS"] = _append_flag(env.get("CFLAGS", ""), "-fno-pie")
            env["CXXFLAGS"] = _append_flag(env.get("CXXFLAGS", ""), "-fno-pie")
            env["LDFLAGS"] = _append_flag(env.get("LDFLAGS", ""), "-no-pie")
        else:
            builds_shared_libs = any(".so" in pattern for pattern in profile.artifact_globs)
            if builds_shared_libs:
                # Shared libraries should be built as PIC, not linked as PIE executables.
                env["CFLAGS"] = _append_flag(env.get("CFLAGS", ""), "-fPIC")
                env["CXXFLAGS"] = _append_flag(env.get("CXXFLAGS", ""), "-fPIC")
            else:
                env["CFLAGS"] = _append_flag(env.get("CFLAGS", ""), "-fPIE")
                env["CXXFLAGS"] = _append_flag(env.get("CXXFLAGS", ""), "-fPIE")
                env["LDFLAGS"] = _append_flag(env.get("LDFLAGS", ""), "-pie")
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
        env["CFLAGS"] = (
            env.get("CFLAGS", "") + " -Wno-error -Wno-cpp -Wno-error=cpp -Wno-error=pedantic -Wno-pedantic"
        ).strip()
        env["CXXFLAGS"] = (
            env.get("CXXFLAGS", "") + " -Wno-error -Wno-cpp -Wno-error=cpp -Wno-error=pedantic -Wno-pedantic"
        ).strip()
    if profile.name in {"tcpdump", "openvpn"}:
        _ensure_linkable_c_compiler(env, variant, profile.name)
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
        if profile.name == "tcpdump":
            ok, env, err = _ensure_tcpdump_libpcap_dependency(profile, env)
            if not ok:
                _log_failure(ctx, row, ref_kind, "configure", err)
                return []
        if profile.name == "openvpn":
            ok, env, err = _ensure_openvpn_openssl_dependency(profile, env)
            if not ok:
                _log_failure(ctx, row, ref_kind, "configure", err)
                return []

        if profile.configure_cmd:
            if openssl_safe_mode:
                # Keep shared libraries enabled (.so) while still avoiding fragile asm paths.
                configure_cmd = _openssl_configure_args(env, row)
            else:
                configure_cmd = _render_tokens(profile.configure_cmd, variant)
            if profile.name == "expat":
                # Some expat tags keep autotools files under ./expat.
                top_cfg = profile.repo_dir / "configure"
                nested_cfg = profile.repo_dir / "expat" / "configure"
                if (not top_cfg.exists()) and nested_cfg.exists():
                    configure_cmd = ["bash", "-lc", "cd expat && ./configure"]
            if profile.name == "dwg2dxf":
                ok, dwg_err = _ensure_dwg2dxf_configure_script(profile.repo_dir, env)
                if ok:
                    configure_cmd = [
                        "bash",
                        "-lc",
                        "test -x ./configure || sh ./autogen.sh || autoreconf -fi; test -x ./configure && sh ./configure",
                    ]
                else:
                    configure_cmd = []
                    err = dwg_err
            if profile.name == "freetype":
                # Prefer top-level configure for modern tags, fallback to builds/unix for legacy tags.
                top_cfg = profile.repo_dir / "configure"
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
                    if top_cfg.exists() and not _looks_like_autoconf_input(top_cfg):
                        configure_cmd = ["bash", "-lc", "./configure --enable-shared || ./configure"]
                    else:
                        if (not unix_cfg.exists()) or _looks_like_autoconf_input(unix_cfg):
                            if raw_cfg.exists():
                                configure_cmd = [
                                    "bash",
                                    "-lc",
                                    "cd builds/unix && (autoconf -o configure configure.raw || cp configure.raw configure) && "
                                    "sed -i '/^[[:space:]]*PKG_PROG_PKG_CONFIG(/c\\: # patched unexpanded pkg-config macro' configure && "
                                    "sed -i '/^[[:space:]]*PKG_CHECK_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                                    "sed -i '/^[[:space:]]*PKG_CHECK_EXISTS(/c\\: # patched unexpanded pkg-config macro' configure && "
                                    "sed -i '/^[[:space:]]*PKG_WITH_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                                    "chmod +x configure && (./configure --enable-shared || ./configure)",
                                ]
                            else:
                                configure_cmd = []
                        else:
                            ok, san_err = _sanitize_freetype_configure(unix_cfg)
                            if not ok:
                                err = san_err
                                configure_cmd = []
                            configure_cmd = ["bash", "-lc", "cd builds/unix && (./configure --enable-shared || ./configure)"]
                    if configure_cmd and not (top_cfg.exists() and not _looks_like_autoconf_input(top_cfg)):
                        # Keep unix build scripts using local libtool wrapper.
                        _patch_freetype_libtool_tag(profile.repo_dir)
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
                    "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && chmod +x configure && "
                    "(bash ./configure --enable-shared || bash ./configure)",
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
                    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_Brotli=TRUE",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=TRUE",
                    "-DFT_REQUIRE_BROTLI=FALSE",
                    "-DFT_WITH_BROTLI=OFF",
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
                        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                        "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE",
                        "-DCMAKE_DISABLE_FIND_PACKAGE_Brotli=TRUE",
                        "-DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=TRUE",
                        "-DFT_REQUIRE_BROTLI=FALSE",
                        "-DFT_WITH_BROTLI=OFF",
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
                    if not ok:
                        # Shared fallback can fail when only non-PIC static deps are available (e.g., libz.a).
                        cfg_try = [
                            "cmake",
                            "-S",
                            ".",
                            "-B",
                            cmake_build,
                            "-DCMAKE_BUILD_TYPE=Release",
                            "-DBUILD_SHARED_LIBS=OFF",
                            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_Brotli=TRUE",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=TRUE",
                            "-DFT_REQUIRE_BROTLI=FALSE",
                            "-DFT_WITH_BROTLI=OFF",
                            "-DFT_DISABLE_BZIP2=TRUE",
                            "-DFT_DISABLE_PNG=TRUE",
                            "-DFT_DISABLE_HARFBUZZ=TRUE",
                            "-DFT_DISABLE_BROTLI=TRUE",
                        ]
                        print(f"[retry] freetype cmake shared build failed; trying static rebuild: {' '.join(cfg_try)}")
                        cfg2_ok, cfg2_err = run_cmd(cfg_try, cwd=profile.repo_dir, env=env)
                        if cfg2_ok:
                            ok, err = run_cmd(build_try, cwd=profile.repo_dir, env=env)
                        else:
                            err = cfg2_err or err
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
                if (not ok) and "openssl check failed" in (err or "").lower():
                    compat_env = _openvpn_compat_openssl_env(env)
                    compat_retries = [
                        ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo", "--disable-lz4", "--with-crypto-library=openssl"],
                        ["./configure", "--disable-plugin-auth-pam", "--with-crypto-library=openssl"],
                    ]
                    for fallback_cfg in compat_retries:
                        print(f"[retry] openvpn openssl configure fallback: {' '.join(fallback_cfg)}")
                        ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=compat_env)
                        if ok:
                            err = ""
                            env.update(compat_env)
                            break
                        err = cfg_err or err
                    if (not ok) and "openssl check failed" in (err or "").lower():
                        patch_ok, patch_err = _patch_openvpn_disable_openssl_check(profile.repo_dir)
                        if patch_ok:
                            fallback_cfg = ["./configure", "--disable-plugin-auth-pam", "--with-crypto-library=openssl"]
                            print(f"[retry] openvpn configure script patched for openssl; retry: {' '.join(fallback_cfg)}")
                            ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=compat_env)
                            if ok:
                                err = ""
                                env.update(compat_env)
                            else:
                                err = cfg_err or err
                        else:
                            err = patch_err or err
            if (not ok) and profile.name == "tcpdump":
                compat_env = _tcpdump_compat_env(env)
                retry_plan = [
                    ["./configure"],
                    ["bash", "-lc", "command -v pcap-config >/dev/null 2>&1 && export CPPFLAGS=\"$(pcap-config --cflags) $CPPFLAGS\" && export LDFLAGS=\"$(pcap-config --libs | sed 's/-lpcap//g') $LDFLAGS\"; ./configure"],
                ]
                for fallback_cfg in retry_plan:
                    print(f"[retry] tcpdump configure fallback: {' '.join(fallback_cfg)}")
                    ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=compat_env)
                    if ok:
                        err = ""
                        env.update(compat_env)
                        break
                    err = cfg_err or err
            if (not ok) and profile.name == "expat":
                expat_retries = [
                    ["bash", "-lc", "test -x ./configure && ./configure"],
                    ["bash", "-lc", "test -x ./buildconf.sh && sh ./buildconf.sh && test -x ./configure && ./configure"],
                    ["bash", "-lc", "cd expat && test -x ./configure && ./configure"],
                    ["bash", "-lc", "cd expat && test -x ./buildconf.sh && sh ./buildconf.sh && test -x ./configure && ./configure"],
                ]
                for fallback_cfg in expat_retries:
                    print(f"[retry] expat configure fallback: {' '.join(fallback_cfg)}")
                    ok, cfg_err = run_cmd(fallback_cfg, cwd=profile.repo_dir, env=env)
                    if ok:
                        err = ""
                        break
                    err = cfg_err or err
            if (not ok) and profile.name == "dwg2dxf":
                err_text = err or ""
                if "No such file or directory: './configure'" in err_text or "cannot open ./configure" in err_text:
                    regen_ok, regen_err = _ensure_dwg2dxf_configure_script(profile.repo_dir, env)
                    if regen_ok:
                        retry_cfg = [
                            "bash",
                            "-lc",
                            "test -x ./configure || sh ./autogen.sh || autoreconf -fi; test -x ./configure && sh ./configure",
                        ]
                        print(f"[retry] dwg2dxf configure script missing; retry: {' '.join(retry_cfg)}")
                        ok, err = run_cmd(retry_cfg, cwd=profile.repo_dir, env=env)
                    else:
                        err = regen_err or err
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
                        retry_cfg = ["bash", "-lc", "cd builds/unix && (./configure --enable-shared || ./configure)"]
                        print(f"[retry] freetype configure png issue; retry without generated helper files: {' '.join(retry_cfg)}")
                        ok, err = run_cmd(retry_cfg, cwd=profile.repo_dir, env=env)
                    else:
                        err = patch_err or err
            if (not ok) and profile.name == "freetype":
                print("[warn] freetype configure unresolved; real-build-only mode keeps this as failure")
            if (not ok) and profile.name == "freetype":
                err_text = err or ""
                if "collect2: error: ld returned 1 exit status" in err_text or "ld returned 1 exit status" in err_text:
                    # Some tags fail configure link checks under PIE-default toolchains.
                    retry_env = dict(env)
                    retry_env["CFLAGS"] = _append_flag(_append_flag(retry_env.get("CFLAGS", ""), "-fno-PIE"), "-fPIC")
                    retry_env["CXXFLAGS"] = _append_flag(_append_flag(retry_env.get("CXXFLAGS", ""), "-fno-PIE"), "-fPIC")
                    retry_env["LDFLAGS"] = _append_flag(retry_env.get("LDFLAGS", ""), "-no-pie")
                    retry_cfg = [
                        "bash",
                        "-lc",
                        "cd builds/unix && "
                        "(test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && "
                        "sed -i '/^[[:space:]]*PKG_PROG_PKG_CONFIG(/c\\: # patched unexpanded pkg-config macro' configure && "
                        "sed -i '/^[[:space:]]*PKG_CHECK_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                        "sed -i '/^[[:space:]]*PKG_CHECK_EXISTS(/c\\: # patched unexpanded pkg-config macro' configure && "
                        "sed -i '/^[[:space:]]*PKG_WITH_MODULES(/c\\: # patched unexpanded pkg-config macro' configure && "
                        "chmod +x configure && bash ./configure",
                    ]
                    print(f"[retry] freetype configure link issue; trying no-pie configure: {' '.join(retry_cfg)}")
                    ok, err = run_cmd(retry_cfg, cwd=profile.repo_dir, env=retry_env)
                    if ok:
                        env.update(retry_env)
            if ok and profile.name == "freetype":
                libtool_ok, libtool_err = _ensure_freetype_unix_libtool(profile.repo_dir, env)
                if not libtool_ok:
                    ok = False
                    err = libtool_err or err
                else:
                    tag_ok, tag_err = _patch_freetype_libtool_tag(profile.repo_dir)
                    if not tag_ok:
                        ok = False
                        err = tag_err or err
            if (not ok) and profile.name == "tcpdump":
                print("[warn] tcpdump configure unresolved; real-build-only mode keeps this as failure")
            if not ok:
                err = _append_config_log_tail(err, profile.repo_dir)
                _log_failure(ctx, row, ref_kind, "configure", err)
                return []
            if profile.name in {"lou_trace", "lou_checktable", "lou_translate"}:
                ok, err = _patch_liblouis_tool_dependency(profile.repo_dir)
                if not ok:
                    _log_failure(ctx, row, ref_kind, "configure_patch", err)
                    return []

        build_cmd = _render_tokens(profile.build_cmd, variant)
        if profile.name == "expat":
            if (profile.repo_dir / "expat" / "Makefile").exists() and not (profile.repo_dir / "Makefile").exists():
                build_cmd = ["make", "-C", "expat"]
        if profile.name == "freetype" and not freetype_cmake_built:
            # Legacy freetype tags vary: Makefile can be generated at top-level or builds/unix.
            if (profile.repo_dir / "Makefile").exists():
                build_cmd = ["make"]
            elif (profile.repo_dir / "builds" / "unix" / "Makefile").exists():
                build_cmd = ["make", "-C", "builds/unix"]
            else:
                # Default to builds/unix; failure path will bootstrap/re-pick automatically.
                build_cmd = ["make", "-C", "builds/unix"]
        if profile.name == "freetype" and freetype_cmake_built:
            build_cmd = []
        if openssl_safe_mode:
            # OpenSSL rows only need libcrypto/libssl. Building apps/tests can fail on
            # old 1.0.x commits after the shared libraries have already been produced.
            build_cmd = ["make", "-j1", "build_libs"]
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
        if build_cmd and build_cmd[0] == "make" and profile.name == "freetype":
            if "-C" in build_cmd and "builds/unix" in build_cmd:
                if not any(token.startswith("LIBTOOL=") for token in build_cmd):
                    build_cmd.append("LIBTOOL=./libtool")
            else:
                if not any(token.startswith("LIBTOOL=") for token in build_cmd):
                    build_cmd.append("LIBTOOL=./builds/unix/libtool")
        if build_cmd:
            ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=env)
        else:
            ok, err = True, ""
        if (not ok) and profile.name == "openssl":
            partial_artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
            if partial_artifacts:
                print(
                    f"[warn] openssl build reported failure, but shared artifacts exist "
                    f"({len(partial_artifacts)}); continuing"
                )
                ok, err = True, ""
        if (not ok) and profile.name == "openssl":
            err_text = err or ""
            if "member " in err_text and "archive is not an object" in err_text:
                print("[retry] openssl archive looks stale/corrupt; clean before rebuilding libraries")
                run_cmd(["make", "clean"], cwd=profile.repo_dir, env=env)
            retry_cmd = ["make", "-j1", "build_libs"]
            print(f"[retry] openssl build failed; build shared libraries only: {' '.join(retry_cmd)}")
            libs_ok, libs_err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
            if libs_ok:
                ok, err = True, ""
            else:
                err = libs_err or err
        if (not ok) and profile.name == "openssl" and "No rule to make target" in (err or ""):
            retry_cmd = ["make", "-j1", "build_crypto", "build_ssl"]
            print(f"[retry] openssl build_libs target missing; build crypto/ssl libraries: {' '.join(retry_cmd)}")
            libs_ok, libs_err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
            if libs_ok:
                ok, err = True, ""
            else:
                err = libs_err or err
        if (not ok) and profile.name == "openssl":
            retry_cmd = ["make", "-j1"]
            print(f"[retry] openssl library build failed; retry legacy full make single-thread: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "openssl":
            partial_artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
            if partial_artifacts:
                print(
                    f"[warn] openssl build reported link failure, but shared artifacts exist "
                    f"({len(partial_artifacts)}); continuing"
                )
                ok, err = True, ""
        if (not ok) and profile.name == "FFmpeg":
            retry_cmd = ["make", "-j1"]
            print(f"[retry] FFmpeg build failed; retry single-thread: {' '.join(retry_cmd)}")
            ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
        if (not ok) and profile.name == "tcpdump":
            err_text = err or ""
            if "No targets specified and no makefile found" in err_text:
                print("[warn] tcpdump build has no Makefile; real-build-only mode keeps this as failure")
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
            patch_ok, patch_err = _patch_liblouis_tool_dependency(profile.repo_dir)
            if not patch_ok:
                err = patch_err or err
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
                    ["make", "-C", "expat", "libexpat.la"],
                    ["make", "-C", "expat", "all"],
                    ["make", "-C", "expat/lib", "all"],
                ]
                for retry_cmd in retry_plan:
                    print(f"[retry] expat doc tooling issue; trying library-only target: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if ok:
                        break
            if (not ok) and ("make: *** lib: No such file or directory" in err_text or "No such file or directory" in err_text):
                retry_plan = [
                    ["make", "-C", "expat", "all"],
                    ["make", "-C", "expat", "libexpat.la"],
                    ["make", "-C", "expat/lib", "all"],
                    ["make", "-C", "expat/lib", "libexpat.la"],
                ]
                for retry_cmd in retry_plan:
                    print(f"[retry] expat layout mismatch; trying: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    if ok:
                        break
            if not ok:
                prebuilt = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
                if prebuilt:
                    print(f"[warn] expat build reported error but artifact exists ({len(prebuilt)}); continuing")
                    ok = True
                else:
                    print("[warn] expat build produced no real artifact; real-build-only mode keeps this as failure")
        if (not ok) and profile.name == "libxml2":
            err_text = err or ""
            if ("zlib.h" in err_text) or ("ld returned 1 exit status" in err_text):
                retry_env = _with_system_include_lib_paths(env)
                retry_env["CFLAGS"] = _append_flag(retry_env.get("CFLAGS", ""), "-fno-pie")
                retry_env["CXXFLAGS"] = _append_flag(retry_env.get("CXXFLAGS", ""), "-fno-pie")
                retry_env["LDFLAGS"] = _append_flag(retry_env.get("LDFLAGS", ""), "-no-pie")
                reconfigure = [
                    "bash",
                    "-lc",
                    "if [ -x ./configure ]; then make clean >/dev/null 2>&1 || true; "
                    "./configure --without-python --without-lzma --without-zlib || "
                    "./configure --without-python --without-lzma; fi",
                ]
                print(f"[retry] libxml2 dependency/link issue; reconfiguring: {' '.join(reconfigure)}")
                cfg_ok, cfg_err = run_cmd(reconfigure, cwd=profile.repo_dir, env=retry_env)
                if cfg_ok:
                    retry_cmd = ["make", "-j1"]
                    print(f"[retry] libxml2 rebuilding single-thread: {' '.join(retry_cmd)}")
                    ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=retry_env)
                    if ok:
                        env.update(retry_env)
                else:
                    err = cfg_err or err
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
            if "zlib.h" in err_text or "pngchunk_int.cpp" in err_text:
                cmake_build = f"build_{variant.compiler}_{variant.opt}"
                retry_env = _with_system_include_lib_paths(env)
                zlib_include, zlib_library = _detect_zlib_for_cmake()
                rebuild_cfg = [
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    cmake_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DEXIV2_ENABLE_XMP=OFF",
                ]
                if zlib_include and zlib_library:
                    rebuild_cfg.extend(
                        [
                            f"-DZLIB_INCLUDE_DIR={zlib_include}",
                            f"-DZLIB_LIBRARY={zlib_library}",
                        ]
                    )
                else:
                    rebuild_cfg.append("-DEXIV2_ENABLE_PNG=OFF")
                print(f"[retry] exiv2 build zlib issue; reconfiguring: {' '.join(rebuild_cfg)}")
                ok, cfg_err = run_cmd(rebuild_cfg, cwd=profile.repo_dir, env=retry_env)
                if ok:
                    retry_build = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=retry_env)
                    if ok:
                        env.update(retry_env)
                else:
                    err = cfg_err or err
            err_text = err or ""
            if "Could NOT find ZLIB" in err_text:
                cmake_build = f"build_{variant.compiler}_{variant.opt}"
                retry_env = _with_system_include_lib_paths(env)
                zlib_include, zlib_library = _detect_zlib_for_cmake()
                forced_cfg = [
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    cmake_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DEXIV2_ENABLE_XMP=OFF",
                ]
                if zlib_include and zlib_library:
                    forced_cfg.extend(
                        [
                            f"-DZLIB_INCLUDE_DIR={zlib_include}",
                            f"-DZLIB_LIBRARY={zlib_library}",
                        ]
                    )
                else:
                    forced_cfg.append("-DEXIV2_ENABLE_PNG=OFF")
                print(f"[retry] exiv2 zlib detection issue; retrying configure: {' '.join(forced_cfg)}")
                ok, cfg_err = run_cmd(forced_cfg, cwd=profile.repo_dir, env=retry_env)
                if ok:
                    retry_build = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=retry_env)
                else:
                    err = cfg_err or err
                    zlib_off_cfg = [
                        "cmake",
                        "-S",
                        ".",
                        "-B",
                        cmake_build,
                        "-DCMAKE_BUILD_TYPE=Release",
                        "-DEXIV2_ENABLE_XMP=OFF",
                        "-DEXIV2_ENABLE_PNG=OFF",
                    ]
                    print(f"[retry] exiv2 zlib still unavailable; disabling png support: {' '.join(zlib_off_cfg)}")
                    ok, cfg_err = run_cmd(zlib_off_cfg, cwd=profile.repo_dir, env=retry_env)
                if ok:
                    retry_build = ["cmake", "--build", cmake_build, "-j", str(max(1, os.cpu_count() or 1))]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=retry_env)
                else:
                    err = cfg_err or err
            if (not ok) and ("zlib.h" in (err or "") or "pngchunk_int.cpp" in (err or "")):
                print("[warn] exiv2 zlib dependency unresolved; real-build-only mode keeps this as failure")
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
            if "./builds/unix/libtool: not found" in err_text or "builds/unix/libtool: not found" in err_text:
                lt_ok, lt_err = _ensure_freetype_unix_libtool(profile.repo_dir, env)
                if lt_ok:
                    retry_build = list(build_cmd)
                    print(f"[retry] freetype missing libtool fixed; retry build: {' '.join(retry_build)}")
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                else:
                    err = lt_err or err
            err_text = err or ""
            if "freetype libtool script not found" in err_text:
                lt_ok, lt_err = _ensure_freetype_unix_libtool(profile.repo_dir, env)
                tag_ok, tag_err = _patch_freetype_libtool_tag(profile.repo_dir)
                if lt_ok and tag_ok:
                    retry_build = list(build_cmd)
                    print(f"[retry] freetype libtool wrapper issue; retry build: {' '.join(retry_build)}")
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                    if (not ok) and "freetype libtool script not found" in (err or ""):
                        bootstrap_cmd = [
                            "bash",
                            "-lc",
                            "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && chmod +x configure && (bash ./configure --enable-shared || bash ./configure)",
                        ]
                        print(f"[retry] freetype libtool still missing; bootstrap again: {' '.join(bootstrap_cmd)}")
                        setup_ok, setup_err = run_cmd(bootstrap_cmd, cwd=profile.repo_dir, env=env)
                        if setup_ok:
                            _ensure_freetype_unix_libtool(profile.repo_dir, env)
                            ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                        else:
                            err = setup_err or err
                else:
                    err = (lt_err or tag_err or err)
            err_text = err or ""
            if "libtool:   error: specify a tag with '--tag'" in err_text:
                tag_ok, tag_err = _patch_freetype_libtool_tag(profile.repo_dir)
                if tag_ok:
                    retry_build = list(build_cmd)
                    print(f"[retry] freetype libtool tag issue; retry build: {' '.join(retry_build)}")
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                else:
                    err = tag_err or err
            err_text = err or ""
            if "/usr/bin/libtool: line 1920: @RC@: command not found" in err_text or "@RC@: command not found" in err_text:
                patch_ok, patch_err = _patch_freetype_libtool_tag(profile.repo_dir)
                if patch_ok:
                    retry_build = list(build_cmd)
                    print(f"[retry] freetype system libtool issue; retry build with local libtool: {' '.join(retry_build)}")
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
                else:
                    err = patch_err or err
            err_text = err or ""
            if "bzlib.h" in err_text or "ftbzip2.c" in err_text:
                print("[warn] freetype bzlib dependency unresolved; real-build-only mode keeps this as failure")
            err_text = err or ""
            if "png.h" in err_text or "pngshim.c" in err_text:
                print("[warn] freetype png dependency unresolved; real-build-only mode keeps this as failure")
            err_text = err or ""
            if "brotli/decode.h" in err_text or "sfwoff2.c" in err_text:
                patch_ok, patch_err = _patch_freetype_brotli_sources(profile.repo_dir)
                if patch_ok:
                    retry_build = list(build_cmd)
                    print(f"[retry] freetype brotli issue; retry build: {' '.join(retry_build)}")
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=env)
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
                or "freetype libtool script not found" in err_text
            ):
                bootstrap_cmd = ["bash", "-lc", "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && chmod +x configure && (bash ./configure --enable-shared || bash ./configure)"]
                print(f"[retry] freetype build failed; trying bootstrap: {' '.join(bootstrap_cmd)}")
                setup_ok, setup_err = run_cmd(bootstrap_cmd, cwd=profile.repo_dir, env=env)
                if setup_ok:
                    _ensure_freetype_unix_libtool(profile.repo_dir, env)
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
                            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_Brotli=TRUE",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=TRUE",
                            "-DFT_REQUIRE_BROTLI=FALSE",
                            "-DFT_WITH_BROTLI=OFF",
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
        if (not ok) and profile.name == "freetype":
            err_text = err or ""
            if "fatal: not a git repository" in err_text:
                retry_env = dict(env)
                git_dir = _resolve_git_dir(profile.repo_dir)
                retry_env["GIT_DIR"] = str(git_dir)
                retry_env["GIT_WORK_TREE"] = str(profile.repo_dir)
                print("[retry] freetype git context issue; retry build with explicit GIT_DIR/GIT_WORK_TREE")
                ok, err = run_cmd(build_cmd, cwd=profile.repo_dir, env=retry_env)
                if ok:
                    env.update(retry_env)
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
        if (not ok) and profile.name == "openvpn":
            err_text = err or ""
            if (
                "openssl/evp.h" in err_text
                or "openssl/x509.h" in err_text
                or "'openssl/evp.h' file not found" in err_text
                or "'openssl/x509.h' file not found" in err_text
            ):
                compat_env = _openvpn_compat_openssl_env(env)
                run_cmd(["make", "distclean"], cwd=profile.repo_dir, env=compat_env)
                _patch_openvpn_disable_lzo(profile.repo_dir)
                compat_cfgs = [
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo", "--disable-lz4", "--with-crypto-library=openssl"],
                    ["./configure", "--disable-plugin-auth-pam", "--disable-comp-lzo", "--with-crypto-library=openssl"],
                    ["./configure", "--disable-plugin-auth-pam", "--with-crypto-library=openssl"],
                ]
                for compat_cfg in compat_cfgs:
                    print(f"[retry] openvpn missing OpenSSL headers; trying: {' '.join(compat_cfg)}")
                    ok, cfg_err = run_cmd(compat_cfg, cwd=profile.repo_dir, env=compat_env)
                    if not ok:
                        err = cfg_err or err
                        continue
                    retry_build = ["make", f"-j{max(1, os.cpu_count() or 1)}"]
                    ok, err = run_cmd(retry_build, cwd=profile.repo_dir, env=compat_env)
                    if ok:
                        env.update(compat_env)
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
                    ["make", "-C", "programs"],
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
                else:
                    src_candidates = [
                        profile.repo_dir / "programs" / "dwg2dxf.c",
                        profile.repo_dir / "src" / "dwg2dxf.c",
                    ]
                    src = next((p for p in src_candidates if p.exists()), None)
                    if src is not None:
                        cc = (env.get("CC") or "cc").strip()
                        out = profile.repo_dir / "programs" / "dwg2dxf"
                        out.parent.mkdir(parents=True, exist_ok=True)
                        include_candidates = [
                            profile.repo_dir / "include",
                            profile.repo_dir / "inc",
                            profile.repo_dir / "src",
                            profile.repo_dir,
                        ]
                        include_flags: list[str] = []
                        for inc in include_candidates:
                            if inc.exists():
                                include_flags.extend(["-I", str(inc)])
                        retry_cmd = [cc, *include_flags, str(src), "-o", str(out)]
                        print(f"[retry] dwg2dxf target missing; compile directly: {' '.join(retry_cmd)}")
                        ok, err = run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                        if ok:
                            prebuilt = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
                            ok = bool(prebuilt)
                    if (not ok) and (
                        "dwg.h: No such file or directory" in (err or "")
                        or "'dwg.h' file not found" in (err or "")
                        or "undefined reference to `dwg_" in (err or "")
                        or "ld returned 1 exit status" in (err or "")
                        or "linker command failed" in (err or "")
                    ):
                        print("[warn] dwg2dxf legacy link/header issue; real-build-only mode keeps this as failure")
            if (
                "pulled_options_state" in err_text
                or "HMAC_Init_ex" in err_text
                or "deprecated-declarations" in err_text
                or "EVP_PKEY_get_id" in err_text
                or "openssl_compat.h" in err_text
                or "incomplete type 'EVP_PKEY'" in err_text
                or "incomplete type 'X509'" in err_text
                or "incomplete type 'EVP_MD'" in err_text
                or "openssl/evp.h" in err_text
                or "openssl/x509.h" in err_text
                or "'openssl/evp.h' file not found" in err_text
                or "'openssl/x509.h' file not found" in err_text
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
                or "openssl/evp.h" in err_text
                or "openssl/x509.h" in err_text
            ):
                print("[warn] openvpn OpenSSL compatibility unresolved; real-build-only mode keeps this as failure")
        if (not ok) and profile.name == "freetype" and "fatal: not a git repository" in (err or ""):
            print("[warn] freetype git metadata issue; real-build-only mode keeps this as failure")
        if not ok:
            _log_failure(ctx, row, ref_kind, "build", err)
            return []

        artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
        if (not artifacts) and profile.name == "openssl":
            jobs = 1 if variant.compiler == "clang" else max(1, os.cpu_count() or 1)
            retry_cmd = ["make", f"-j{jobs}"]
            print(f"[retry] openssl shared artifacts missing; rerun make: {' '.join(retry_cmd)}")
            run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
            artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
        if (not artifacts) and profile.name == "openssl":
            # Some historical commits produce only static outputs with perl Configure.
            # Retry with ./config shared to force SHLIB settings in legacy trees.
            print("[retry] openssl shared artifacts still missing; reconfigure with ./config shared no-asm")
            run_cmd(["make", "clean"], cwd=profile.repo_dir, env=env)
            debug_flags = " ".join(_openssl_debug_configure_args(env))
            cfg_cmd = [
                "bash",
                "-lc",
                f"if [ -x ./config ]; then ./config shared no-asm {debug_flags}; "
                f"else perl Configure linux-x86_64 shared no-asm {debug_flags}; fi",
            ]
            cfg_ok, cfg_err = run_cmd(cfg_cmd, cwd=profile.repo_dir, env=env)
            if cfg_ok:
                build_retry = ["make", f"-j{jobs}"]
                run_cmd(build_retry, cwd=profile.repo_dir, env=env)
                artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
            else:
                err = cfg_err or err
        if (not artifacts) and profile.name == "openssl":
            static_hits: list[str] = []
            for pat in ("**/libcrypto.a", "**/libssl.a"):
                for p in sorted(profile.repo_dir.glob(pat)):
                    if p.is_file():
                        static_hits.append(str(p.relative_to(profile.repo_dir)))
                        if len(static_hits) >= 10:
                            break
                if len(static_hits) >= 10:
                    break
            if static_hits:
                err = (
                    "shared artifacts not produced (.so missing) while static archives exist; "
                    "shared-only policy rejected static outputs: " + ", ".join(static_hits)
                )
        if (not artifacts) and profile.name == "freetype":
            jobs = max(1, os.cpu_count() or 1)
            _ensure_freetype_unix_libtool(profile.repo_dir, env)
            run_cmd(["bash", "-lc", "cd builds/unix && (test -x configure && ! grep -q 'AC_INIT(' configure || autoconf -o configure configure.raw || cp configure.raw configure) && chmod +x configure && (bash ./configure --enable-shared || bash ./configure)"], cwd=profile.repo_dir, env=env)
            recover_plan = [
                ["make", "-C", "builds/unix", f"-j{jobs}"],
                ["make", "-C", "builds/unix", "shared", f"-j{jobs}"],
                ["make", "-C", "builds/unix", "all", f"-j{jobs}"],
                ["make", "-C", "builds/unix", "install", f"-j{jobs}"],
                ["make", f"-j{jobs}"],
                ["make", "all", f"-j{jobs}"],
            ]
            for retry_cmd in recover_plan:
                print(f"[retry] freetype artifacts missing; trying extra build: {' '.join(retry_cmd)}")
                run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
                if artifacts:
                    break
            if (not artifacts) and (profile.repo_dir / "build_freetype_fallback").exists():
                retry_cmd = ["cmake", "--build", "build_freetype_fallback", "-j", str(jobs)]
                print(f"[retry] freetype artifacts missing; retry cmake fallback build: {' '.join(retry_cmd)}")
                run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
            if not artifacts:
                cmake_build = "build_freetype_fallback"
                cfg_try = [
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    cmake_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DBUILD_SHARED_LIBS=ON",
                    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_Brotli=TRUE",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=TRUE",
                    "-DFT_REQUIRE_BROTLI=FALSE",
                    "-DFT_WITH_BROTLI=OFF",
                    "-DFT_DISABLE_BZIP2=TRUE",
                    "-DFT_DISABLE_PNG=TRUE",
                    "-DFT_DISABLE_HARFBUZZ=TRUE",
                    "-DFT_DISABLE_BROTLI=TRUE",
                ]
                print(f"[retry] freetype artifacts missing; trying cmake configure: {' '.join(cfg_try)}")
                cfg_ok, _ = run_cmd(cfg_try, cwd=profile.repo_dir, env=env)
                if cfg_ok:
                    retry_cmd = ["cmake", "--build", cmake_build, "-j", str(jobs)]
                    print(f"[retry] freetype artifacts missing; trying cmake build: {' '.join(retry_cmd)}")
                    run_cmd(retry_cmd, cwd=profile.repo_dir, env=env)
                    artifacts = _resolve_artifacts_for_variant(profile, row, ref_kind, variant)
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
    m = re.search(r"-O(0|1|2|3|s|fast)", flags)
    opt = f"O{m.group(1)}" if m else "O0"
    cc = (profile.env_overrides.get("CC") or "").lower()
    compiler = "clang" if "clang" in cc else "gcc"
    return BuildVariant(compiler=compiler, opt=opt, env_overrides={})


def _release_variants() -> list[BuildVariant]:
    gcc = resolve_command(
        os.getenv("GCC_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc"),
        ["gcc", "cc", "clang"],
    )
    gpp = resolve_command(
        os.getenv("GPP_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++"),
        ["g++", "c++", "clang++"],
    )
    clang = resolve_command(
        os.getenv("CLANG_BIN", "/home/user/BinForge/tools/clang/clang-13.0.1/bin/clang"),
        ["clang"],
    )
    clangpp = resolve_command(
        os.getenv("CLANGPP_BIN", "/home/user/BinForge/tools/clang/clang-13.0.1/bin/clang++"),
        ["clang++"],
    )
    llvm_ar = resolve_command(os.getenv("LLVM_AR_BIN", "/usr/bin/llvm-ar"), ["llvm-ar", "ar"])
    llvm_ranlib = resolve_command(os.getenv("LLVM_RANLIB_BIN", "/usr/bin/llvm-ranlib"), ["llvm-ranlib", "ranlib"])
    llvm_nm = resolve_command(os.getenv("LLVM_NM_BIN", "/usr/bin/llvm-nm"), ["llvm-nm", "nm"])
    probe_env = os.environ.copy()
    gcc_probe_env = {
        **probe_env,
        "CC": gcc,
        "CXX": gpp,
        "CFLAGS": "-O0 -g",
        "CXXFLAGS": "-O0 -g",
    }
    linkable_gcc, gcc_err = _linkable_c_compiler(gcc, "gcc", gcc_probe_env)
    if linkable_gcc:
        if linkable_gcc != gcc:
            print(f"[toolchain-fix] release gcc compiler switched {gcc} -> {linkable_gcc}")
        gcc = linkable_gcc
        gpp = _linkable_cxx_compiler(gpp, "gcc")
    else:
        print(f"[toolchain-warn] gcc release compiler is not linkable: {_short_error(gcc_err)}")

    variants: list[BuildVariant] = []
    toolchains: list[tuple[str, str, str]] = [("gcc", gcc, gpp)]
    clang_available = bool(clang) and (os.path.isfile(clang) or shutil.which(os.path.basename(clang)))
    clangpp_available = bool(clangpp) and (os.path.isfile(clangpp) or shutil.which(os.path.basename(clangpp)))
    if clang_available and clangpp_available:
        clang_probe_env = {
            **probe_env,
            "CC": clang,
            "CXX": clangpp,
            "CFLAGS": "-O0 -g",
            "CXXFLAGS": "-O0 -g",
        }
        linkable_clang, clang_err = _linkable_c_compiler(clang, "clang", clang_probe_env)
        if linkable_clang:
            if linkable_clang != clang:
                print(f"[toolchain-fix] release clang compiler switched {clang} -> {linkable_clang}")
            toolchains.append(("clang", linkable_clang, _linkable_cxx_compiler(clangpp, "clang")))
        else:
            print(f"[toolchain-skip] clang toolchain cannot link executables: {_short_error(clang_err)}")
    else:
        print(
            "[toolchain-skip] clang toolchain unavailable; "
            f"skipping clang release variants (cc={clang}, cxx={clangpp})"
        )

    for compiler, cc, cxx in toolchains:
        for opt in ["O0", "O1", "O2", "O3", "Os", "Ofast"]:
            extra: dict[str, str] = {}
            if compiler == "clang":
                # Keep binutils consistent with clang, but only pin tools that actually exist.
                if llvm_ar and (os.path.isfile(llvm_ar) or shutil.which(os.path.basename(llvm_ar))):
                    extra["AR"] = llvm_ar
                if llvm_ranlib and (os.path.isfile(llvm_ranlib) or shutil.which(os.path.basename(llvm_ranlib))):
                    extra["RANLIB"] = llvm_ranlib
                if llvm_nm and (os.path.isfile(llvm_nm) or shutil.which(os.path.basename(llvm_nm))):
                    extra["NM"] = llvm_nm
            variants.append(
                BuildVariant(
                    compiler=compiler,
                    opt=opt,
                    env_overrides={
                        "CC": cc,
                        "CXX": cxx,
                        "CFLAGS": f"-{opt} -g",
                        "CXXFLAGS": f"-{opt} -g",
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
                preferred = next((p for p in cache_files if "libcrypto.so" in p.name), None)
            elif row.file.startswith("ssl/"):
                preferred = next((p for p in cache_files if "libssl.so" in p.name), None)

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
    print(f"[release-variants] count={len(variants)} (gcc/clang x O0/O1/O2/O3/Os/Ofast, with -g)")
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

    def _add_worktree() -> tuple[bool, str]:
        return run_cmd(
            ["git", "worktree", "add", "--detach", "--force", str(wt_dir), ref],
            cwd=profile.repo_dir,
            quiet_stdout=False,
        )

    def _prune_worktrees() -> None:
        run_cmd(["git", "worktree", "prune", "--expire", "now"], cwd=profile.repo_dir, quiet_stdout=False)

    with ctx.lock:
        if wt_dir.exists():
            shutil.rmtree(wt_dir, ignore_errors=True)
        _prune_worktrees()
        ok, err = _add_worktree()
        if (not ok) and ("commondir" in (err or "").lower() or "worktrees/" in (err or "").lower()):
            # Stale metadata from an interrupted prior run can break new worktree creation.
            _prune_worktrees()
            ok, err = _add_worktree()
    if not ok:
        _log_failure(ctx, row, kind, "worktree_add", err)
        return None

    try:
        local_profile = replace(profile, repo_dir=wt_dir)
        cache_files = _build_once(local_profile, row, ref, kind, variant, ctx)
        return kind, variant, cache_files
    finally:
        with ctx.lock:
            run_cmd(["git", "worktree", "remove", "--force", str(wt_dir)], cwd=profile.repo_dir, quiet_stdout=False)
            _prune_worktrees()
        if wt_dir.exists():
            shutil.rmtree(wt_dir, ignore_errors=True)


def _process_project_rows(
    project: str,
    rows: list[BuildRow],
    profiles: dict[str, BuildProfile],
    ctx: BuildContext,
    mode: str,
    clone_missing: bool,
) -> None:
    profile = profiles.get(project)
    if not profile:
        for row in rows:
            _log_failure(ctx, row, "profile", "resolve", "unsupported project profile")
        return

    if not profile.repo_dir.exists():
        if not clone_missing:
            for row in rows:
                _log_failure(ctx, row, "profile", "repo_dir", f"repo path not found: {profile.repo_dir}")
            return
        ok, err = _ensure_repo(profile)
        if not ok:
            for row in rows:
                _log_failure(ctx, row, "profile", "clone", err)
            return

    for row in rows:
        print(f"\n[row] project={row.project} cve={row.cve} file={row.file}")
        if mode in {"all", "commits"}:
            _process_commits(profile, row, ctx)
        if mode in {"all", "releases"}:
            _process_releases(profile, row, ctx)


def run_pipeline(
    csv_path: str,
    output_root: str,
    only_project: str = "",
    only_cve: str = "",
    mode: str = "all",
    clone_missing: bool = True,
    parallel_workers: int = 1,
    project_workers: int = 1,
    enable_pie: bool = False,
) -> list[str]:
    profiles = build_profiles()
    resolved_output_root = Path(output_root).expanduser().resolve()
    ctx = BuildContext(
        output_root=resolved_output_root,
        failures=[],
        built_cache=set(),
        parallel_workers=max(1, int(parallel_workers)),
        project_workers=max(1, int(project_workers)),
        enable_pie=enable_pie,
        lock=Lock(),
    )
    ctx.output_root.mkdir(parents=True, exist_ok=True)

    grouped_rows: dict[str, list[BuildRow]] = {}
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            row = BuildRow.from_csv_row(raw)
            if not row.project:
                continue
            if only_project and row.project != only_project:
                continue
            if only_cve and row.cve != only_cve:
                continue
            grouped_rows.setdefault(row.project, []).append(row)

    if not grouped_rows:
        return ctx.failures

    if ctx.project_workers <= 1 or len(grouped_rows) <= 1:
        for project, rows in grouped_rows.items():
            _process_project_rows(project, rows, profiles, ctx, mode, clone_missing)
        return ctx.failures

    with ThreadPoolExecutor(max_workers=ctx.project_workers) as ex:
        futures = [
            ex.submit(_process_project_rows, project, rows, profiles, ctx, mode, clone_missing)
            for project, rows in grouped_rows.items()
        ]
        for fut in as_completed(futures):
            fut.result()

    return ctx.failures
