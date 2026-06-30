# Tools Modular Builder README

이 디렉터리의 중심 실행 파일은 `all_in_one_modular_builder.py`입니다. `all_in_one.csv`의 각 행을 읽고, 프로젝트별 빌드 프로필에 따라 patch/vuln commit 및 release tag 바이너리를 실제로 빌드한 뒤 결과물을 output 디렉터리에 복사합니다.

## 빠른 실행

```bash
python all_in_one_modular_builder.py --csv all_in_one.csv --output /home/user/all_in_one --mode all
```

특정 프로젝트만:

```bash
python all_in_one_modular_builder.py --only-project tcpdump --output /home/user/tools/tcpdump_rebuild --fail-log /home/user/tools/tcpdump_rebuild_failed_steps.txt
```

특정 CVE만:

```bash
python all_in_one_modular_builder.py --only-project openvpn --only-cve CVE-2017-7520 --output /home/user/tools/openvpn_rebuild
```

## 입력 CSV

기본 입력은 `all_in_one.csv`입니다. 스크립트는 다음 컬럼명을 사용합니다.

```text
Project
CVE
File
Function
Patch commit
Ex-patch commit
Dataset Type
Bug start
Bug end
Patch start
Patch end
```

`Patch commit`은 `patch`, `Ex-patch commit`은 `vuln`으로 빌드됩니다. release 빌드는 `Bug start` 또는 `Patch start`부터 `Patch end`까지의 git tag 범위를 스캔해서 수행합니다.

## 주요 옵션

```bash
python all_in_one_modular_builder.py [options]
```

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `--csv` | `all_in_one.csv` | 입력 CSV 경로 |
| `--output` | `/home/user/all_in_one` | 결과물 및 cache 출력 경로 |
| `--only-project` | 없음 | 특정 프로젝트만 처리 |
| `--only-cve` | 없음 | 특정 CVE만 처리 |
| `--mode` | `all` | `all`, `commits`, `releases` 중 선택 |
| `--parallel-workers` | `1` | release variant 병렬 빌드 수 |
| `--project-workers` | `1` | 서로 다른 프로젝트 병렬 처리 수 |
| `--pie` | off | 실행파일은 `-fPIE -pie`, 공유 라이브러리는 `-fPIC` 적용 |
| `--no-clone` | off | 누락된 repo를 자동 clone하지 않음 |
| `--fail-log` | `all_in_one_failed_steps.txt` | 실패 로그 출력 경로 |

## 지원 프로젝트명

`--only-project`에는 아래 이름을 그대로 사용합니다.

```text
openssl
tcpdump
libxml2
freetype
expat
openvpn
lou_trace
lou_checktable
lou_translate
libtiff
pcf2bdf
dwg2dxf
exiv2
FFmpeg
```

liblouis 계열은 하나의 `liblouis` 프로젝트명이 아니라 도구별 프로필로 나뉘어 있습니다.

```bash
python all_in_one_modular_builder.py --only-project lou_trace
python all_in_one_modular_builder.py --only-project lou_checktable
python all_in_one_modular_builder.py --only-project lou_translate
```

## 출력 구조

결과물은 기본적으로 프로젝트별 디렉터리에 복사됩니다.

```text
<output>/<project>/
```

commit 결과물 이름은 대체로 다음 형식입니다.

```text
<CVE>_<patch|vuln>_<compiler>_<opt>
```

release 결과물은 다음 정보를 포함합니다.

```text
<artifact>_<project>-<version>_<opt>_<arch>_<compiler>
```

중복 빌드를 줄이기 위해 cache도 함께 사용합니다.

```text
<output>/_cache/<project>/<ref>/<variant>/
```

cache hit가 나면 실제 repo를 다시 빌드하지 않고 cache 결과물을 복사합니다.

## 빌드 variant

commit 빌드는 기본 variant 하나를 사용합니다. release 빌드는 가능한 toolchain 기준으로 여러 variant를 돌립니다.

```text
gcc/clang x O0/O1/O2/O3/Os/Ofast
```

컴파일러가 링크 가능한지 먼저 검사하며, 기본 BinForge compiler가 현재 환경에서 실행파일을 링크하지 못하면 시스템 `gcc`, `cc`, `clang` 등으로 fallback하거나 해당 toolchain variant를 건너뜁니다.

## 주요 환경변수

repo 위치를 바꾸고 싶으면 아래 환경변수를 사용합니다.

| 프로젝트 | 환경변수 | 기본 경로 |
|---|---|---|
| openssl | `OPENSSL_DIR` | `/home/user/openssl` |
| tcpdump | `TCPDUMP_DIR` | `/home/user/tcpdump` |
| libxml2 | `LIBXML2_DIR` | `/home/user/libxml2` |
| freetype | `FREETYPE_DIR` | `/home/user/freetype` |
| expat | `EXPAT_DIR` | `/home/user/libexpat/expat` |
| openvpn | `OPENVPN_DIR` | `/home/user/openvpn` |
| liblouis tools | `LIBLOUIS_DIR` | `/home/user/liblouis` |
| libtiff | `LIBTIFF_DIR` | `/home/user/libtiff` |
| pcf2bdf | `PCF2BDF_DIR` | `/home/user/pcf2bdf` |
| dwg2dxf | `LIBREDWG_DIR` | `/home/user/libredwg` |
| exiv2 | `EXIV2_DIR` | `/home/user/exiv2` |
| FFmpeg | `FFMPEG_DIR` | `/home/user/FFmpeg` |

toolchain 관련:

```bash
export GCC_BIN=/path/to/gcc
export GPP_BIN=/path/to/g++
export CLANG_BIN=/path/to/clang
export CLANGPP_BIN=/path/to/clang++
export TARGET_ARCH=x86
```

dependency 관련:

```bash
export LIBPCAP_DIR=/home/user/libpcap
export LIBPCAP_PREFIX=/home/user/libpcap-install
export LIBPCAP_REF=libpcap-1.9.1

export OPENSSL_SRC_DIR=/home/user/openssl-1.1-src
export OPENSSL_PREFIX=/home/user/openssl-1.1-install
export OPENSSL_REF=OpenSSL_1_1_1w
export OPENSSL_LEGACY_PREFIX=/home/user/BinForge/local/openssl-1.1
```

## 자동 dependency 처리

일부 프로젝트는 시스템 패키지 상태에 따라 configure는 통과해도 build에서 깨질 수 있습니다. 현재 빌더는 다음 dependency를 실제 소스/설치 prefix 기반으로 보정합니다.

### tcpdump

`libpcap` 헤더/라이브러리를 찾습니다. 없으면 실제 libpcap repository를 clone/build/install해서 `LIBPCAP_PREFIX`를 tcpdump configure에 넘깁니다.

기본값:

```text
source: /home/user/libpcap
prefix: /home/user/libpcap-install
ref:    libpcap-1.9.1
```

### openvpn

OpenVPN 2.4.x 빌드에 필요한 OpenSSL 헤더와 라이브러리를 찾습니다. 없으면 OpenSSL 1.1.1w를 실제로 clone/build/install해서 사용합니다.

기본값:

```text
source: /home/user/openssl-1.1-src
prefix: /home/user/openssl-1.1-install
ref:    OpenSSL_1_1_1w
```

이 dependency 처리는 더미 파일을 만들지 않습니다. 실제 헤더와 실제 라이브러리를 빌드해서 사용합니다.

## 실패 로그 읽는 법

실패 로그는 `--fail-log`로 지정한 파일에 기록됩니다.

예:

```text
tcpdump,CVE-2018-16228,vuln,configure fail | ...
openvpn,CVE-2017-7520,release_2.4.0,build fail | ...
```

`configure fail`은 configure 단계 실패, `build fail`은 make/cmake build 단계 실패입니다. 로그는 너무 길어지지 않도록 핵심 error line과 tail 중심으로 축약됩니다.

자주 보이는 패턴:

| 로그 | 의미 |
|---|---|
| `C compiler cannot create executables` | compiler 또는 linker가 현재 환경에서 실행파일을 못 만듦 |
| `see the INSTALL doc for more info` | configure 내부 dependency 검사 실패일 가능성이 큼 |
| `openssl/evp.h file not found` | OpenSSL 개발 헤더가 compile flag에 안 들어감 또는 prefix 없음 |
| `pcap.h not found`, `-lpcap` 관련 오류 | libpcap 개발 헤더/라이브러리 문제 |

## 주의점

- 빌더는 repo에서 `git reset --hard HEAD`와 `git clean -xfd`를 사용합니다. 기본 repo 경로 안에 수동 작업물을 두면 지워질 수 있습니다.
- 같은 repo를 여러 프로젝트/worker가 동시에 만지면 충돌할 수 있습니다. 처음 문제를 재현할 때는 `--parallel-workers 1 --project-workers 1`을 권장합니다.
- `--project-workers`는 서로 다른 프로젝트 병렬 처리용입니다. repo 경로가 겹치는 liblouis 계열은 병렬 실행을 피하는 것이 안전합니다.
- `--parallel-workers`는 release variant 병렬 빌드용입니다. 오래된 autotools 프로젝트는 병렬 clean/configure에 약할 수 있어 문제가 나면 1로 낮추세요.
- 기본 출력에 cache가 들어갑니다. 이전 실패/성공 결과를 완전히 무시하고 싶으면 output의 `_cache`를 삭제하고 다시 실행하세요.
- `--no-clone`을 주면 repo가 없을 때 실패합니다. repo 자동 준비가 필요하면 이 옵션을 빼세요.
- Windows PowerShell에서 실행하는 문서가 아니라, 실제 빌드는 보통 Linux 경로(`/home/user/...`) 기준 환경에서 실행됩니다.
- 기존 `binxray_builder.py`는 이 README의 중심 대상이 아닙니다. 현재 권장 진입점은 `all_in_one_modular_builder.py`입니다.

## 추천 실행 예시

tcpdump만 전체 재빌드:

```bash
python all_in_one_modular_builder.py \
  --csv all_in_one.csv \
  --output /home/user/tools/tcpdump_rebuild \
  --only-project tcpdump \
  --fail-log /home/user/tools/tcpdump_rebuild_failed_steps.txt
```

openvpn 특정 CVE만:

```bash
python all_in_one_modular_builder.py \
  --csv all_in_one.csv \
  --output /home/user/tools/openvpn_rebuild \
  --only-project openvpn \
  --only-cve CVE-2017-7520 \
  --fail-log /home/user/tools/openvpn_rebuild_failed_steps.txt
```

release만 빌드:

```bash
python all_in_one_modular_builder.py --mode releases --only-project openssl
```

commit patch/vuln만 빌드:

```bash
python all_in_one_modular_builder.py --mode commits --only-project tcpdump
```

PIE 플래그를 켜서 빌드:

```bash
python all_in_one_modular_builder.py --only-project openvpn --pie
```

## 결과물 확인

실제 바이너리인지 확인:

```bash
file /home/user/tools/tcpdump_rebuild/tcpdump/*
file /home/user/tools/openvpn_rebuild/openvpn/*
```

ELF executable 또는 ELF shared object로 나오면 실제 빌드 산출물입니다.
