import os
import csv
import shutil
import subprocess

# 기본 경로 및 명령어 설정
OPENSSL_DIR = "/home/user/openssl"
TCPDUMP_DIR = "/home/user/tcpdump"
FREETYPE_DIR = "/home/user/freetype"
LIBXML2_DIR = "/home/user/libxml2"

CLANG_BIN = "/home/user/BinForge/tools/clang/clang-14.0.6/bin/clang"
GCC_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc"
GPP_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++"
CSV_FILE = "binxray_info.csv"
FAILED_LOG_FILE = "binxray_failed_steps.txt"


CFLAGS = ["linux-x86_64", "shared", "-g", "-O0"]

def is_real_binary_or_library(path):
    """
    실제 빌드 산출물(ELF executable/shared object/static archive)인지 확인.
    tcpdump.1 같은 문서 파일을 걸러냄.
    """
    if not os.path.isfile(path):
        return False

    # 너무 뻔한 문서/스크립트/메타파일 제외
    bad_suffixes = (
        ".1", ".3", ".5", ".7", ".8", ".txt", ".md", ".in", ".pc", ".la", ".a.la"
    )
    if path.endswith(bad_suffixes):
        return False

    # file 명령으로 타입 판별
    try:
        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True,
            text=True,
            check=False,
        )
        desc = result.stdout.strip().lower()
    except OSError:
        # file 명령이 없으면 확장자 기반 최소 판별
        base = os.path.basename(path)
        return (
            ".so" in base
            or base.endswith(".a")
            or os.access(path, os.X_OK)
        )

    if "elf" in desc:
        return True
    if "current ar archive" in desc:
        return True

    return False

def find_built_artifact(project):
    """
    프로젝트별로 '실제 빌드 산출물'만 찾는다.
    우선순위가 높은 경로를 먼저 보고, 없으면 제한된 패턴 탐색 후 file로 필터링한다.
    """
    match project:
        case "tcpdump":
            binary_name = "tcpdump"
            project_dir = TCPDUMP_DIR
        case "libxml2":
            binary_name = "libxml2.so.2"
            project_dir = LIBXML2_DIR
        case "freetype":
            binary_name = "libfreetype.so.6"
            project_dir = FREETYPE_DIR
        case _:
            pass

    # 1) 우선순위 경로
    candidate_paths = {
        "tcpdump": [
            "tcpdump",                 # 실제 실행 파일
            "./tcpdump",
        ],
        "freetype": [
            "objs/.libs/libfreetype.so",
            "objs/.libs/libfreetype.a",
            "objs/.libs/libfreetype.so.6",
            "objs/.libs/libfreetype.so.6.0.0",
        ],
        "libxml2": [
            ".libs/libxml2.so",
            ".libs/libxml2.a",
            ".libs/libxml2.so.2",
        ],
        # openssl은 현재 process_commit에서 실질 지원 안 함
        "openssl": [],
    }

    for rel in candidate_paths.get(project, []):
        full = os.path.join(project_dir, rel)
        if os.path.exists(full) and is_real_binary_or_library(full):
            return full

    # 2) 제한된 패턴 탐색
    pattern_map = {
        "tcpdump": ["tcpdump"],
        "freetype": ["libfreetype.so*", "libfreetype.a"],
        "libxml2": ["libxml2.so*", "libxml2.a"],
        "openssl": [],
    }

    search_roots = {
        "tcpdump": ["."],
        "freetype": ["objs/.libs", "."],
        "libxml2": [".libs", "."],
        "openssl": ["."],
    }

    for root in search_roots.get(project, ["."]):
        root_path = os.path.join(project_dir, root)
        if not os.path.exists(root_path):
            continue

        for pattern in pattern_map.get(project, []):
            try:
                result = subprocess.run(
                    ["find", root, "-name", pattern, "-type", "f"],
                    cwd=project_dir,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except OSError:
                continue

            if result.returncode != 0 or not result.stdout.strip():
                continue

            found = [line.strip() for line in result.stdout.splitlines() if line.strip()]

            # 긴 버전의 .so 우선, 그 다음 실제 바이너리/라이브러리만 통과
            found.sort(key=lambda p: (".so." not in p, len(p)))

            for relpath in found:
                full = os.path.join(project_dir, relpath.lstrip("./"))
                if is_real_binary_or_library(full):
                    return full

    return None


def run_cmd(cmd, project, env=None):
    """지정된 디렉터리에서 셸 명령어를 실행합니다."""
    print(f"[*] 실행 중: {' '.join(cmd)}")
    if project == "openssl":
        cwd = OPENSSL_DIR
    elif project == "tcpdump":
        cwd = TCPDUMP_DIR
    elif project == "freetype":
        cwd = FREETYPE_DIR
    elif project == "libxml2":
        cwd = LIBXML2_DIR
    try:
        result = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        error_text = str(e)
        print(f"[!] 에러 발생: {error_text}")
        return False, error_text

    if result.returncode != 0:
        print(f"[!] 에러 발생: {result.stderr}")
        return False, result.stderr.strip()
    return True, ""

def record_failure(failures, cve_id, state, step, error_msg=""):
    line = f"{cve_id}, {state}, {step} fail"
    if error_msg:
        one_line_error = " ".join(error_msg.split())
        line = f"{line} | {one_line_error}"
    failures.append(line)
    print(f"[!] 실패 기록: {line}")

def process_commit(commit_url, project, cve_id, target_file, state, failures):
    """특정 커밋으로 이동하여 -O0 및 -O3 버전을 각각 추출합니다."""
    # 1. 커밋 해시 추출 (URL의 마지막 부분)
    if not commit_url or not commit_url.strip():
        record_failure(failures, cve_id, state, "commit_url")
        return

    commit_hash = commit_url.strip().split('/')[-1]
    print(f"\n--- [ {cve_id} / {state} ] 커밋 {commit_hash} 처리 시작 ---")

    # 2. git checkout
    checkout_ok, checkout_err = run_cmd(["git", "checkout", "-f", commit_hash], project)
    if not checkout_ok:
        record_failure(failures, cve_id, state, "checkout", checkout_err)
        return

    # 3. Configure 설정
    # configure_env = os.environ.copy()
    # configure_env["CC"] = GCC_BIN
    # configure_env["CXX"] = GPP_BIN
    # 
    """
    tcpdump:
        CPPFLAGS="-I/home/user/BinForge/local/libpcap/include" \
        LDFLAGS="-L/home/user/BinForge/local/libpcap/lib" \
        CC={GCC_BIN} \
        CXX={GPP_BIN} \
        CFLAGS="-O0 -g" \
        CXXFLAGS="-O0 -g" \
        ./configure
    libxml2:
        NOCONFIGURE=1 ./autogen.sh
        CC={GCC_BIN} CXX={GPP_BIN} CFLAGS="-O0 -g" CXXFLAGS="-O0 -g" ./configure
    freetype:
        CC={GCC_BIN} CXX={GPP_BIN} CPPFLAGS="-I/usr/include -I/usr/include/x86_64-linux-gnu" LDFLAGS="-L/usr/lib/x86_64-linux-gnu -L/lib/x86_64-linux-gnu" CFLAGS="-O0 -g" CXXFLAGS="-O0 -g" ./configure
    """
    configure_env = os.environ.copy()
    configure_env["CC"] = GCC_BIN
    configure_env["CXX"] = GPP_BIN
    configure_env["CFLAGS"] = "-O0 -g"
    configure_env["CXXFLAGS"] = "-O0 -g"
    match project:
        case "tcpdump":
            configure_env["CPPFLAGS"] = "-I/home/user/BinForge/local/libpcap/include"
            configure_env["LDFLAGS"] = "-L/home/user/BinForge/local/libpcap/lib"

        case "libxml2":
            configure_env["NOCONFIGURE"] = "1"
            run_cmd(["./autogen.sh"], project, env=configure_env)

        case "freetype":
            # 이전 설정 꼬임 방지
            config_mk = os.path.join(FREETYPE_DIR, "config.mk")
            if os.path.exists(config_mk):
                os.remove(config_mk)
            run_cmd(["./autogen.sh"], project, env=configure_env)
            configure_env["CPPFLAGS"] = "-I/usr/include -I/usr/include/x86_64-linux-gnu"
            configure_env["LDFLAGS"] = "-L/usr/lib/x86_64-linux-gnu -L/lib/x86_64-linux-gnu"
            
        case _:
            pass

    configure_ok, configure_err = run_cmd(["./configure"], project, env=configure_env)
    # configure_ok, configure_err = run_cmd(["perl", "Configure", *CFLAGS], env=configure_env)
    
    if not configure_ok:
        record_failure(failures, cve_id, state, "configure", configure_err)
        return

    # 4. make -j$(nproc)
    jobs = max(1, os.cpu_count() or 1)
    make_ok, make_err = run_cmd(["make", f"-j{jobs}"], project, env=configure_env)
    if not make_ok:
        record_failure(failures, cve_id, state, "make", make_err)
        return

    # 5. 바이너리 복사
    """
    tcpdump:
        tcpdump/tcpdump
    libxml2:
        libxml2/.libs/libxml2.so.2.*
    freetype:
        freetype/objs/.libs/libfreetype.so.6.*
    """
    """
    find_result = subprocess.run(
            ["find", ".", "-name", f"{lib}*", "-type", "f"],
            cwd=OPENSSL_DIR,
            capture_output=True,
            text=True
        )
        
    """
    artifact_path = find_built_artifact(project)
    if artifact_path:
        ext = os.path.splitext(artifact_path)[1]
        output_name = f"{cve_id}_{state}_gcc_O0"
        output_path = os.path.abspath(os.path.join("/home/user/binxray_output", project, output_name))

        try:
            shutil.copy2(artifact_path, output_path)
            print(f"[+] 성공적으로 복사됨: {artifact_path} -> {output_path}")
        except OSError as e:
            record_failure(failures, cve_id, state, f"copy artifact", str(e))
    else:
        print(f"[!] 실제 빌드 산출물을 찾을 수 없음: {project}")
        record_failure(failures, cve_id, state, "copy artifact", "built artifact not found")
    
    # 6. make clean (다음 빌드 꼬임 방지용 초기화)
    clean_ok, clean_err = run_cmd(["make", "clean"], project)
    if not clean_ok:
        record_failure(failures, cve_id, state, "clean", clean_err)

    # 8. git reset --hard HEAD (다음 커밋 처리 전에 작업 디렉터리 초기화)
    # git clean -xfd
    # git reset --hard HEAD
    run_cmd(["git", "checkout", "."], project)
    clean_ok, clean_err = run_cmd(["git", "clean", "-xfd"], project)
    if not clean_ok:
        record_failure(failures, cve_id, state, "git clean", clean_err)
    reset_ok, reset_err = run_cmd(["git", "reset", "--hard", "HEAD"], project)
    if not reset_ok:
        record_failure(failures, cve_id, state, "git reset", reset_err)


def main():
    failures = []

    # 1. CSV 파일 읽고 한줄씩 처리
    with open(CSV_FILE, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            project = row['Project']
            cve_id = row['CVE']
            target_file = row['File']
            patch_commit_url = row['Patch commit']
            vuln_commit_url = row['Ex-patch commit']

            print(f"\n=================================================")
            print(f"🎯 처리 대상: {project} | {cve_id} | {target_file}")
            print(f"===================================================")

            # 패치 버전 (patch) 처리
            process_commit(patch_commit_url, project, cve_id, target_file, "patch", failures)

            # 패치 이전 취약버전 (vuln) 처리
            process_commit(vuln_commit_url, project, cve_id, target_file, "vuln", failures)

    with open(FAILED_LOG_FILE, 'w', encoding='utf-8') as f:
        if failures:
            f.write("\n".join(failures) + "\n")
        else:
            f.write("No failures\n")

    print(f"\n[📄] 실패 로그 저장 완료: {FAILED_LOG_FILE}")

    print("\n[🎉] 모든 작업이 완료되었습니다!")

if __name__ == "__main__":
    main()
