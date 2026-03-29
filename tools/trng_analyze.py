#!/usr/bin/env python3
"""
HTS TRNG Raw 데이터 기초 통계 분석
NIST SP 800-90B Statistical Test Suite 실행 전 사전 검증

사용법:
  1. STM32 보드에서 UART로 100만 바이트 Raw 데이터 수집
     $ stty -F /dev/ttyUSB0 115200 raw
     $ dd if=/dev/ttyUSB0 of=trng_raw.bin bs=1 count=1000000
  2. 이 스크립트로 기초 분석
     $ python3 trng_analyze.py trng_raw.bin
  3. NIST 도구 실행
     $ ./ea_non_iid trng_raw.bin 8
     (8 = bits per sample)

[분석 항목]
  1. 바이트 분포 균등성 (Chi-squared)
  2. 엔트로피 추정 (Shannon / Min-entropy)
  3. 연속 동일 바이트 최대 길이 (RCT 시뮬레이션)
  4. 바이트별 출현 빈도 히스토그램
  5. 비트 균형 (0/1 비율)
"""

import sys
import math
from collections import Counter


def analyze_trng(filepath: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    n = len(data)
    print(f"\n{'='*60}")
    print(f"  HTS TRNG Raw 데이터 분석")
    print(f"  파일: {filepath}")
    print(f"  크기: {n:,} bytes")
    print(f"{'='*60}\n")

    if n < 1000:
        print("  [경고] 최소 1,000,000 바이트 권장 (현재 부족)")

    # 1. 바이트 분포 (Chi-squared)
    freq = Counter(data)
    expected = n / 256.0
    chi2 = sum((freq.get(i, 0) - expected) ** 2 / expected for i in range(256))
    # Chi-squared with 255 df: critical value at p=0.01 is ~310
    chi2_pass = chi2 < 350  # 약간 여유
    print(f"[1] Chi-squared 균등성 테스트")
    print(f"    chi² = {chi2:.2f} (기대값: ~255, 임계값: <350)")
    print(f"    결과: {'PASS' if chi2_pass else 'FAIL'}\n")

    # 2. 엔트로피 추정
    shannon = 0.0
    min_entropy = 8.0
    for i in range(256):
        p = freq.get(i, 0) / n
        if p > 0:
            shannon -= p * math.log2(p)
            min_e = -math.log2(p)
            min_entropy = min(min_entropy, min_e)
    print(f"[2] 엔트로피 추정")
    print(f"    Shannon: {shannon:.4f} bits/byte (이상적: 8.0)")
    print(f"    Min-entropy: {min_entropy:.4f} bits/byte")
    print(f"    결과: {'PASS' if shannon > 7.5 else 'WARN'}\n")

    # 3. RCT 시뮬레이션 (최대 연속 동일 바이트)
    max_run = 1
    current_run = 1
    for i in range(1, n):
        if data[i] == data[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    rct_pass = max_run < 16  # NIST RCT cutoff
    print(f"[3] RCT 시뮬레이션 (연속 동일 바이트)")
    print(f"    최대 연속 길이: {max_run}")
    print(f"    RCT cutoff: 16")
    print(f"    결과: {'PASS' if rct_pass else 'FAIL'}\n")

    # 4. 비트 균형
    total_bits = n * 8
    ones = sum(bin(b).count('1') for b in data)
    zeros = total_bits - ones
    ratio = ones / total_bits
    bit_pass = 0.49 < ratio < 0.51
    print(f"[4] 비트 균형 (0/1 비율)")
    print(f"    1-bits: {ones:,} ({ratio:.4f})")
    print(f"    0-bits: {zeros:,} ({1-ratio:.4f})")
    print(f"    결과: {'PASS' if bit_pass else 'WARN'}\n")

    # 5. 상위/하위 5개 바이트
    most = freq.most_common(5)
    least = freq.most_common()[-5:]
    print(f"[5] 바이트 빈도 분포")
    print(f"    기대치: {expected:.1f} / 바이트값")
    print(f"    최다: {', '.join(f'0x{v:02X}({c})' for v,c in most)}")
    print(f"    최소: {', '.join(f'0x{v:02X}({c})' for v,c in least)}")

    # 종합
    print(f"\n{'='*60}")
    print(f"  Chi²:     {'PASS' if chi2_pass else 'FAIL'}")
    print(f"  Shannon:  {shannon:.4f}/8.0")
    print(f"  RCT:      {'PASS' if rct_pass else 'FAIL'}")
    print(f"  비트균형: {'PASS' if bit_pass else 'WARN'}")
    print(f"{'='*60}")
    print(f"\n  다음 단계: NIST SP 800-90B ea_non_iid 실행")
    print(f"  $ ./ea_non_iid {filepath} 8\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"사용법: {sys.argv[0]} <trng_raw.bin>")
        sys.exit(1)
    analyze_trng(sys.argv[1])
