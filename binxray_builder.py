import os
import csv
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
    match project:
        case "tcpdump":
            binary_name = "tcpdump"
            working_dir = TCPDUMP_DIR
        case "libxml2":
            binary_name = "libxml2.so.2"
            working_dir = LIBXML2_DIR
        case "freetype":
            binary_name = "libfreetype.so.6"
            working_dir = FREETYPE_DIR
        case _:
            pass
    find_result = subprocess.run(
        ["find", ".", "-name", f"{binary_name}*", "-type", "f"],
        cwd=working_dir,
        capture_output=True,
        text=True
    )

    if find_result.returncode == 0 and find_result.stdout.strip():
        # 찾은 파일들 출력
        found_files = find_result.stdout.strip().split('\n')
        print(f"[*] {binary_name} 패턴으로 찾은 파일들: {found_files}")
        
        # 심볼릭 링크가 아닌 실제 파일 우선 선택, 없으면 첫 번째 파일 사용
        lib_path = None
        for f in found_files:
            full_path = os.path.join(working_dir, f.lstrip('./'))
            if not os.path.islink(full_path):
                lib_path = f
                break
        if not lib_path:
            lib_path = found_files[0]
        
        full_lib_path = os.path.join(working_dir, lib_path.lstrip('./'))
        
        output_name = f"{cve_id}_{state}_gcc_O0"
        output_path = os.path.join("..", output_name)
        copy_ok, copy_err = run_cmd(["cp", full_lib_path, output_path], project)
        if copy_ok:
            print(f"[+] 성공적으로 복사됨: {lib_path} -> {output_path}")
        else:
            record_failure(failures, cve_id, state, f"copy {binary_name}", copy_err)
    else:
        print(f"[!] 라이브러리 파일을 찾을 수 없음: {binary_name}")
        record_failure(failures, cve_id, state, f"copy {binary_name}", "library file not found")
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
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
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
