#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#ifndef _UTILS_CPU_INFO_H
#define _UTILS_CPU_INFO_H

typedef struct {
	unsigned char mmx;
	unsigned char sse;
	unsigned char sse2;
	unsigned char sse3;
	
	unsigned char pclmul;
	unsigned char ssse3;
	unsigned char sse41;
	unsigned char sse42;
	unsigned char aes;
	
	unsigned char avx;
	unsigned char fma3;
	
	unsigned char rdrand;
	
	unsigned char avx2;
	
	unsigned char bmi1;
	unsigned char bmi2;
	unsigned char adx;
	unsigned char sha;
	unsigned char prefetchwt1;
	
	unsigned char avx512f;
	unsigned char avx512cd;
	unsigned char avx512pf;
	unsigned char avx512er;
	unsigned char avx512vl;
	unsigned char avx512bw;
	unsigned char avx512dq;
	unsigned char avx512ifma;
	unsigned char avx512vbmi;
	
	unsigned char x64;
	unsigned char abm;
	unsigned char sse4a;
	unsigned char fma4;
	unsigned char xop;
} info_ia32;

typedef struct{
	unsigned char neon;
	
	unsigned char aes;
	unsigned char sha1;
	unsigned char sha256;
	unsigned char pmull;
} info_arm;

void get_ia32_cpuinfo(info_ia32* pInfo, unsigned char check_os_support);
void get_arm_cpuinfo(info_arm* pInfo);
#endif


