import os
import csv
import subprocess

# 기본 경로 및 명령어 설정
OPENSSL_DIR = "/home/user/openssl"
CLANG_BIN = "/home/user/BinForge/tools/clang/clang-14.0.6/bin/clang"
CSV_FILE = "openssl_our.csv"

# 아주 긴 Clang 컴파일 옵션 (동적으로 주입할 최적화 옵션 -O0 / -O3 는 여기서 제외)
BASE_CLANG_FLAGS = [
    "-I.", "-Icrypto/include", "-Iinclude", "-fPIC", "-pthread", "-m64",
    "-Qunused-arguments", "-Wall", "-DOPENSSL_USE_NODELETE",
    "-DL_ENDIAN", "-DOPENSSL_PIC", "-DOPENSSL_CPUID_OBJ", "-DOPENSSL_IA32_SSE2",
    "-DOPENSSL_BN_ASM_MONT", "-DOPENSSL_BN_ASM_MONT5", "-DOPENSSL_BN_ASM_GF2m",
    "-DSHA1_ASM", "-DSHA256_ASM", "-DSHA512_ASM", "-DRC4_ASM", "-DMD5_ASM",
    "-DAES_ASM", "-DVPAES_ASM", "-DBSAES_ASM", "-DGHASH_ASM", "-DECP_NISTZ256_ASM",
    "-DX25519_ASM", "-DPADLOCK_ASM", "-DPOLY1305_ASM",
    '-DOPENSSLDIR="/usr/local/ssl"', '-DENGINESDIR="/usr/local/lib/engines-1.1"',
    "-DNDEBUG", "-emit-llvm", "-c"  # 핵심: -c 추가 (비트코드 목적 파일 생성)
]

def run_cmd(cmd, cwd=OPENSSL_DIR):
    """지정된 디렉터리에서 셸 명령어를 실행합니다."""
    print(f"[*] 실행 중: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"[!] 에러 발생: {result.stderr}")
        return False
    return True

def process_commit(commit_url, cve_id, target_file, state):
    """특정 커밋으로 이동하여 -O0 및 -O3 버전을 각각 추출합니다."""
    # 2. 커밋 해시 추출 (URL의 마지막 부분)
    commit_hash = commit_url.strip().split('/')[-1]
    print(f"\n--- [ {cve_id} / {state} ] 커밋 {commit_hash} 처리 시작 ---")

    # 2. git checkout
    if not run_cmd(["git", "checkout", "-f", commit_hash]):
        return

    # 3. ./config 설정
    print(f"[*] 실행 중: CC={CLANG_BIN} ./config")
    subprocess.run(f"CC={CLANG_BIN} ./config", shell=True, cwd=OPENSSL_DIR, stdout=subprocess.DEVNULL)

    # 4. make build_generated (헤더 생성)
    if not run_cmd(["make", "build_generated"]):
        return

    # 5. clang으로 -O0와 -O3 버전 각각 .bc 추출
    for opt in ["-O0", "-O3"]:
        # 파일명 생성 예: ../CVE-2018-0732_patch_O0.bc
        opt_suffix = opt.strip('-')  # "-O0" -> "O0"
        if opt == "-O3":
            output_bc = f"../{cve_id}_{state}_{opt_suffix}.bc"
        else:
            output_bc = f"../{cve_id}_{state}.bc"

        # 컴파일 명령어 조립: 기본 옵션 + 최적화 옵션 + 입력 파일 + 출력 파일
        compile_cmd = [CLANG_BIN] + BASE_CLANG_FLAGS + [opt, target_file, "-o", output_bc]
        
        if run_cmd(compile_cmd):
            print(f"[+] 성공적으로 생성됨: {output_bc}")

    # 6. make distclean (다음 빌드 꼬임 방지용 초기화)
    run_cmd(["make", "distclean"])

def main():
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
            process_commit(patch_commit_url, cve_id, target_file, "patch")

            # 패치 이전 취약버전 (vuln) 처리
            process_commit(vuln_commit_url, cve_id, target_file, "vuln")

    print("\n[🎉] 모든 작업이 완료되었습니다!")

if __name__ == "__main__":
    main()