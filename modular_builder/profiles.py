from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import BuildRow
from .utils import is_real_binary_or_library


PreStep = Callable[[Path, dict[str, str], BuildRow], None]
ArtifactResolver = Callable[[Path, BuildRow], list[Path]]


@dataclass(frozen=True)
class BuildProfile:
    name: str
    repo_dir: Path
    repo_url: str
    configure_cmd: list[str]
    pre_steps: list[list[str]]
    build_cmd: list[str]
    clean_cmd: list[str]
    env_overrides: dict[str, str]
    artifact_globs: list[str]
    artifact_resolver: ArtifactResolver | None = None


def _default_env() -> dict[str, str]:
    gcc = os.getenv("GCC_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc")
    gpp = os.getenv("GPP_BIN", "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++")
    return {
        "CC": gcc,
        "CXX": gpp,
        "CFLAGS": "-O0 -g",
        "CXXFLAGS": "-O0 -g",
    }


def _openssl_resolver(repo_dir: Path, row: BuildRow) -> list[Path]:
    patterns = ["libcrypto.so*", "libssl.so*"]
    if row.file.startswith("crypto/"):
        patterns = ["libcrypto.so*"]
    elif row.file.startswith("ssl/"):
        patterns = ["libssl.so*"]
    found: list[Path] = []
    for pattern in patterns:
        for p in sorted(repo_dir.glob(f"**/{pattern}")):
            if p.is_file() and is_real_binary_or_library(p):
                found.append(p)
                break
    return found


def _generic_resolver(repo_dir: Path, row: BuildRow, globs: list[str]) -> list[Path]:
    found: list[Path] = []
    for pattern in globs:
        for p in sorted(repo_dir.glob(pattern)):
            if p.is_file() and is_real_binary_or_library(p):
                found.append(p)
                break
    return found


def _liblouis_resolver(repo_dir: Path, row: BuildRow) -> list[Path]:
    exe = row.project
    choices = [
        repo_dir / "tools" / exe,
        repo_dir / exe,
        repo_dir / "bin" / exe,
    ]
    return [p for p in choices if p.exists() and is_real_binary_or_library(p)]


def _libtiff_resolver(repo_dir: Path, row: BuildRow) -> list[Path]:
    leaf = Path(row.file).stem
    choices = [
        repo_dir / "tools" / leaf,
        repo_dir / leaf,
    ]
    valid = [p for p in choices if p.exists() and is_real_binary_or_library(p)]
    if valid:
        return valid
    return _generic_resolver(repo_dir, row, ["tools/*", "*/.libs/*.so*"])


def _ffmpeg_resolver(repo_dir: Path, row: BuildRow) -> list[Path]:
    choices = [repo_dir / "ffmpeg", repo_dir / "ffprobe", repo_dir / "ffplay"]
    return [p for p in choices if p.exists() and is_real_binary_or_library(p)]


def build_profiles() -> dict[str, BuildProfile]:
    base = _default_env()
    return {
        "openssl": BuildProfile(
            name="openssl",
            repo_dir=Path(os.getenv("OPENSSL_DIR", "/home/user/openssl")),
            repo_url="https://github.com/openssl/openssl.git",
            configure_cmd=["perl", "Configure", "linux-x86_64", "shared", "-g", "-O0"],
            pre_steps=[],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["**/libcrypto.so*", "**/libssl.so*"],
            artifact_resolver=_openssl_resolver,
        ),
        "tcpdump": BuildProfile(
            name="tcpdump",
            repo_dir=Path(os.getenv("TCPDUMP_DIR", "/home/user/tcpdump")),
            repo_url="https://github.com/the-tcpdump-group/tcpdump.git",
            configure_cmd=["./configure"],
            pre_steps=[],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides={**base, "CPPFLAGS": "-I/home/user/BinForge/local/libpcap/include", "LDFLAGS": "-L/home/user/BinForge/local/libpcap/lib"},
            artifact_globs=["tcpdump", "./tcpdump"],
        ),
        "libxml2": BuildProfile(
            name="libxml2",
            repo_dir=Path(os.getenv("LIBXML2_DIR", "/home/user/libxml2")),
            repo_url="https://gitlab.gnome.org/GNOME/libxml2.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides={**base, "NOCONFIGURE": "1"},
            artifact_globs=[".libs/libxml2.so*", ".libs/libxml2.a"],
        ),
        "freetype": BuildProfile(
            name="freetype",
            repo_dir=Path(os.getenv("FREETYPE_DIR", "/home/user/freetype")),
            repo_url="https://gitlab.freedesktop.org/freetype/freetype.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides={**base, "CPPFLAGS": "-I/usr/include -I/usr/include/x86_64-linux-gnu", "LDFLAGS": "-L/usr/lib/x86_64-linux-gnu -L/lib/x86_64-linux-gnu"},
            artifact_globs=["objs/.libs/libfreetype.so*", "objs/.libs/libfreetype.a"],
        ),
        "expat": BuildProfile(
            name="expat",
            repo_dir=Path(os.getenv("EXPAT_DIR", "/home/user/libexpat/expat")),
            repo_url="https://github.com/libexpat/libexpat.git",
            configure_cmd=["./configure"],
            pre_steps=[["./buildconf.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=[".libs/libexpat.so*", ".libs/libexpat.a"],
        ),
        "openvpn": BuildProfile(
            name="openvpn",
            repo_dir=Path(os.getenv("OPENVPN_DIR", "/home/user/openvpn")),
            repo_url="https://github.com/OpenVPN/openvpn.git",
            configure_cmd=["./configure", "--disable-plugin-auth-pam"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides={
                **base,
                "PKG_CONFIG_PATH": "/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/share/pkgconfig:" + os.getenv("PKG_CONFIG_PATH", ""),
                "CPPFLAGS": "-I/usr/local/include",
                "LDFLAGS": "-L/usr/local/lib -L/usr/local/lib64",
            },
            artifact_globs=["src/openvpn/openvpn", "src/openvpn"],
        ),
        "lou_trace": BuildProfile(
            name="lou_trace",
            repo_dir=Path(os.getenv("LIBLOUIS_DIR", "/home/user/liblouis")),
            repo_url="https://github.com/liblouis/liblouis.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["tools/lou_trace"],
            artifact_resolver=_liblouis_resolver,
        ),
        "lou_checktable": BuildProfile(
            name="lou_checktable",
            repo_dir=Path(os.getenv("LIBLOUIS_DIR", "/home/user/liblouis")),
            repo_url="https://github.com/liblouis/liblouis.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["tools/lou_checktable"],
            artifact_resolver=_liblouis_resolver,
        ),
        "lou_translate": BuildProfile(
            name="lou_translate",
            repo_dir=Path(os.getenv("LIBLOUIS_DIR", "/home/user/liblouis")),
            repo_url="https://github.com/liblouis/liblouis.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["tools/lou_translate"],
            artifact_resolver=_liblouis_resolver,
        ),
        "libtiff": BuildProfile(
            name="libtiff",
            repo_dir=Path(os.getenv("LIBTIFF_DIR", "/home/user/libtiff")),
            repo_url="https://gitlab.com/libtiff/libtiff.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["tools/*"],
            artifact_resolver=_libtiff_resolver,
        ),
        "pcf2bdf": BuildProfile(
            name="pcf2bdf",
            repo_dir=Path(os.getenv("PCF2BDF_DIR", "/home/user/pcf2bdf")),
            repo_url="https://github.com/ganaware/pcf2bdf.git",
            configure_cmd=[],
            pre_steps=[],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["pcf2bdf"],
        ),
        "dwg2dxf": BuildProfile(
            name="dwg2dxf",
            repo_dir=Path(os.getenv("LIBREDWG_DIR", "/home/user/libredwg")),
            repo_url="https://github.com/LibreDWG/libredwg.git",
            configure_cmd=["./configure"],
            pre_steps=[["./autogen.sh"]],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["programs/dwg2dxf", "src/dwg2dxf"],
        ),
        "exiv2": BuildProfile(
            name="exiv2",
            repo_dir=Path(os.getenv("EXIV2_DIR", "/home/user/exiv2")),
            repo_url="https://github.com/Exiv2/exiv2.git",
            configure_cmd=["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_COMPILER=" + base["CC"], "-DCMAKE_CXX_COMPILER=" + base["CXX"]],
            pre_steps=[],
            build_cmd=["cmake", "--build", "build", "-j"],
            clean_cmd=["cmake", "--build", "build", "--target", "clean"],
            env_overrides=base,
            artifact_globs=["build/bin/exiv2", "bin/exiv2"],
        ),
        "FFmpeg": BuildProfile(
            name="FFmpeg",
            repo_dir=Path(os.getenv("FFMPEG_DIR", "/home/user/FFmpeg")),
            repo_url="https://github.com/FFmpeg/FFmpeg.git",
            configure_cmd=["./configure", "--disable-shared", "--enable-static"],
            pre_steps=[],
            build_cmd=["make"],
            clean_cmd=["make", "clean"],
            env_overrides=base,
            artifact_globs=["ffmpeg"],
            artifact_resolver=_ffmpeg_resolver,
        ),
    }


def resolve_artifacts(profile: BuildProfile, row: BuildRow) -> list[Path]:
    if profile.artifact_resolver:
        artifacts = profile.artifact_resolver(profile.repo_dir, row)
        if artifacts:
            return artifacts
    return _generic_resolver(profile.repo_dir, row, profile.artifact_globs)
