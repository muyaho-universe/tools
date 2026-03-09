import os
import csv
import subprocess

import git

# 기본 경로 및 명령어 설정
OPENSSL_DIR = "/home/user/openssl"
CLANG_BIN = "/home/user/BinForge/tools/clang/clang-14.0.6/bin/clang"
GCC_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc"
GPP_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++"
CSV_FILE = "openssl_old.csv"
FAILED_LOG_FILE = "openssl_failed_steps.txt"


CFLAGS = ["linux-x86_64", "shared", "-g", "-O0"]

def run_cmd(cmd, cwd=OPENSSL_DIR, env=None):
    """지정된 디렉터리에서 셸 명령어를 실행합니다."""
    print(f"[*] 실행 중: {' '.join(cmd)}")
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

def process_commit(commit_url, cve_id, target_file, state, failures):
    """특정 커밋으로 이동하여 -O0 및 -O3 버전을 각각 추출합니다."""
    # 1. 커밋 해시 추출 (URL의 마지막 부분)
    if not commit_url or not commit_url.strip():
        record_failure(failures, cve_id, state, "commit_url")
        return

    commit_hash = commit_url.strip().split('/')[-1]
    print(f"\n--- [ {cve_id} / {state} ] 커밋 {commit_hash} 처리 시작 ---")

    # 2. git checkout
    checkout_ok, checkout_err = run_cmd(["git", "checkout", "-f", commit_hash])
    if not checkout_ok:
        record_failure(failures, cve_id, state, "checkout", checkout_err)
        return

    # 3. Configure test/build.info 파일 수정 (필요한 경우에만)
    build_info_path = os.path.join(OPENSSL_DIR, "test", "build.info")
    configure_path = os.path.join(OPENSSL_DIR, "Configure")
    
    # grep으로 File::Glob 패턴이 있는지 확인
    grep_result = subprocess.run(
        ["grep", "-n", "File::Glob", "Configure", "test/build.info"],
        cwd=OPENSSL_DIR,
        capture_output=True,
        text=True
    )
    
    # File::Glob 패턴이 발견되면 파일 수정
    fixed = False
    if grep_result.returncode == 0 and "File::Glob" in grep_result.stdout:
        print(f"[*] File::Glob 패턴 감지, 파일 수정 실행")
        # Convert both "qw/glob/" and "qw( glob )" forms to "qw/:glob/".
        run_cmd(["perl", "-pi", "-e", 'if(/File::Glob/){ s/qw\\s*[\\(\\/]\\s*:?\\s*glob\\s*[\\)\\/]/qw\\/:glob\\//g }', configure_path, build_info_path])
        fixed = True
    else:
        print(f"[*] File::Glob 패턴이 없음, 파일 수정 건너뛰기")

    # 4. Configure 설정
    configure_env = os.environ.copy()
    configure_env["CC"] = GCC_BIN
    configure_env["CXX"] = GPP_BIN
    print(f"[*] 실행 중: ./Configure {' '.join(CFLAGS)} (CC={GCC_BIN}, CXX={GPP_BIN})")
    configure_ok, configure_err = run_cmd(["./Configure", *CFLAGS], env=configure_env)
    if not configure_ok:
        record_failure(failures, cve_id, state, "configure", configure_err)
        return

    # 5. make -j$(nproc)
    jobs = max(1, os.cpu_count() or 1)
    make_ok, make_err = run_cmd(["make", f"-j{jobs}"])
    if not make_ok:
        record_failure(failures, cve_id, state, "make", make_err)
        return

    # 6. target_file 경로를 기반으로 필요한 라이브러리만 찾아서 복사
    # File 열이 crypto로 시작하면 libcrypto.so, ssl로 시작하면 libssl.so 복사
    if target_file.startswith("crypto/"):
        libs_to_copy = ["libcrypto.so"]
    elif target_file.startswith("ssl/"):
        libs_to_copy = ["libssl.so"]
    else:
        # 기본적으로 둘 다 복사
        libs_to_copy = ["libcrypto.so", "libssl.so"]
    
    for lib in libs_to_copy:
        # find 명령으로 라이브러리 파일 위치 찾기 (하위 디렉터리 포함)
        find_result = subprocess.run(
            ["find", ".", "-name", lib, "-type", "f"],
            cwd=OPENSSL_DIR,
            capture_output=True,
            text=True
        )
        
        if find_result.returncode == 0 and find_result.stdout.strip():
            # 첫 번째로 찾은 파일 사용
            lib_path = find_result.stdout.strip().split('\n')[0]
            full_lib_path = os.path.join(OPENSSL_DIR, lib_path.lstrip('./'))
            
            output_name = f"{cve_id}_{state}_gcc_O0_{lib}"
            output_path = os.path.join("..", output_name)
            copy_ok, copy_err = run_cmd(["cp", full_lib_path, output_path], cwd=OPENSSL_DIR)
            if copy_ok:
                print(f"[+] 성공적으로 복사됨: {lib_path} -> {output_path}")
            else:
                record_failure(failures, cve_id, state, f"copy {lib}", copy_err)
        else:
            print(f"[!] 라이브러리 파일을 찾을 수 없음: {lib}")
            record_failure(failures, cve_id, state, f"copy {lib}", "library file not found")

    # 7. make clean (다음 빌드 꼬임 방지용 초기화)
    distclean_ok, distclean_err = run_cmd(["make", "clean"])
    if not distclean_ok:
        record_failure(failures, cve_id, state, "clean", distclean_err)

    # 8. git reset --hard HEAD (다음 커밋 처리 전에 작업 디렉터리 초기화)
    # git clean -xfd
    # git reset --hard HEAD
    run_cmd(["git", "checkout", "."])
    clean_ok, clean_err = run_cmd(["git", "clean", "-xfd"])
    if not clean_ok:
        record_failure(failures, cve_id, state, "git clean", clean_err)
    reset_ok, reset_err = run_cmd(["git", "reset", "--hard", "HEAD"])
    if not reset_ok:
        record_failure(failures, cve_id, state, "git reset", reset_err)


def main():
    failures = []

    # 1. CSV 파일 읽고 한줄씩 처리
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row['CVE']
            target_file = row['File']
            patch_commit_url = row['Patch commit']
            vuln_commit_url = row['Ex-patch commit']

            print(f"\n=========================================")
            print(f"🎯 처리 대상: {cve_id} | {target_file}")
            print(f"=========================================")

            # 패치 버전 (patch) 처리
            process_commit(patch_commit_url, cve_id, target_file, "patch", failures)

            # 패치 이전 취약버전 (vuln) 처리
            process_commit(vuln_commit_url, cve_id, target_file, "vuln", failures)

    with open(FAILED_LOG_FILE, 'w', encoding='utf-8') as f:
        if failures:
            f.write("\n".join(failures) + "\n")
        else:
            f.write("No failures\n")

    print(f"\n[📄] 실패 로그 저장 완료: {FAILED_LOG_FILE}")

    print("\n[🎉] 모든 작업이 완료되었습니다!")

if __name__ == "__main__":
    main()
