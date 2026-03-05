import os
import csv
import subprocess

# 기본 경로 및 명령어 설정
OPENSSL_DIR = "/home/user/openssl"
CLANG_BIN = "/home/user/BinForge/tools/clang/clang-14.0.6/bin/clang"
GCC_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-gcc"
GPP_BIN = "/home/user/BinForge/tools/gcc/x86_64-unknown-linux-gnu-9.5.0/bin/x86_64-unknown-linux-gnu-g++"
CSV_FILE = "openssl_old.csv"
FAILED_LOG_FILE = "openssl_failed_steps.txt"


CFLAGS = ["linux-x86_64","-O0", "-g"]

def run_cmd(cmd, cwd=OPENSSL_DIR, env=None):
    """지정된 디렉터리에서 셸 명령어를 실행합니다."""
    print(f"[*] 실행 중: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
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

    # 3. Configure test/build.info 파일 수정
    build_info_path = os.path.join(OPENSSL_DIR, "test", "build.info")
    configure_path = os.path.join(OPENSSL_DIR, "Configure")
    # perl -pi -e 'if(/File::Glob/){ s/qw\s*[\(\/]\s*glob\s*[\)\/]/qw\/:glob\//g }' Configure test/build.info
    run_cmd(["perl", "-pi", "-e", 'if(/File::Glob/){ s/qw\\s*[\\(\\/]+\\s*glob\\s*[\\)\\/]+/qw\\/glob\\//g }', configure_path, build_info_path])

    # 4. ./Configure 설정
    configure_env = os.environ.copy()
    configure_env["CC"] = GCC_BIN
    configure_env["CXX"] = GPP_BIN
    print(f"[*] 실행 중: ./Configure {' '.join(CFLAGS)} (CC={GCC_BIN}, CXX={GPP_BIN})")
    configure_ok, configure_err = run_cmd(["./Configure", *CFLAGS], env=configure_env)
    if not configure_ok:
        record_failure(failures, cve_id, state, "configure", configure_err)
        return

    # 5. make -j$(nproc)
    make_ok, make_err = run_cmd(["make", "-j$(nproc)"])
    if not make_ok:
        record_failure(failures, cve_id, state, "make", make_err)
        return

    # 6. libcrypto.so*와 libssl.so*를 찾고, 존재하면 ../ 디렉터리에 복사
    # 복사 시 파일명은 {cve_id}_{state}_gcc_O0_crypto.so나 {cve_id}_{state}_gcc_O0_ssl.so 형태로 저장
    for lib in ["libcrypto.so", "libssl.so"]:
        lib_path = os.path.join(OPENSSL_DIR, "lib", lib)
        if os.path.exists(lib_path):
            output_name = f"{cve_id}_{state}_gcc_O0_{lib}"
            output_path = os.path.join("..", output_name)
            copy_ok, copy_err = run_cmd(["cp", lib_path, output_path], cwd=OPENSSL_DIR)
            if copy_ok:
                print(f"[+] 성공적으로 복사됨: {output_path}")
            else:
                record_failure(failures, cve_id, state, f"copy {lib}", copy_err)
        else:
            print(f"[!] 라이브러리 파일이 존재하지 않음: {lib_path}")
            record_failure(failures, cve_id, state, f"copy {lib}", "library file not found")

    # 7. make distclean (다음 빌드 꼬임 방지용 초기화)
    distclean_ok, distclean_err = run_cmd(["make", "distclean"])
    if not distclean_ok:
        record_failure(failures, cve_id, state, "distclean", distclean_err)

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