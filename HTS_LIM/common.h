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
//
//  [양산/보안 정책 요약 — 상세 구현은 Layer 1(부트·WDT)·5(키)·15(OTA/스토리지) 등]
//  · Secure Provisioning: 공정 초기(Unprovisioned: JTAG/SWD·루트키 주입 허용)과
//    양산 완료(Sealed: RDP/옵션·퓨즈 등)를 HW+부트 FSM으로 분리해 런타임 핫플러깅
//    자폭 정책과 공정 주입을 모순 없이 병치.
//  · Flash 수명: 동일 섹터 ping-pong만 반복 시 마모 — EEPROM 에뮬/카운터 갱신에는
//    웨어 레벨링 또는 쓰기 횟수 추적(HW 카운터 포함) 검토.
//  · Watchdog: HSE/HSI 정지 시 SW 타이머 무력화 — LSI 기반 IWDG 등 독립 클럭
//    하드웨어 리셋 경로를 보드·부트 설계에 명시.
//

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTION 1
#define DECRYPTION 2

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct _blk {
	u8* msg;
	u32 size;
} blk;

/* 시프트 폭 0·32(64)에서의 UB 방지: (c)&31 / (0-rot)&31 패턴 (항⑨, MISRA 시프트) */
#if defined(__cplusplus)
#define LROT(x,c) \
	((static_cast<u32>(x) << (((unsigned)(c)) & 31u)) | \
	 (static_cast<u32>(x) >> ((0u - (((unsigned)(c)) & 31u)) & 31u)))
#define ROTR(x,c) \
	((static_cast<u32>(x) >> (((unsigned)(c)) & 31u)) | \
	 (static_cast<u32>(x) << ((0u - (((unsigned)(c)) & 31u)) & 31u)))
#define SHR(x,c) \
	((((unsigned)(c)) >= 32u) ? 0u : (static_cast<u32>(x) >> ((unsigned)(c))))
#define LROT64(x, c) \
	((static_cast<u64>(x) << (((unsigned)(c)) & 63u)) | \
	 (static_cast<u64>(x) >> ((0u - (((unsigned)(c)) & 63u)) & 63u)))
#define RROT64(x, c) \
	((static_cast<u64>(x) >> (((unsigned)(c)) & 63u)) | \
	 (static_cast<u64>(x) << ((0u - (((unsigned)(c)) & 63u)) & 63u)))
#else
#define LROT(x,c) \
	((((u32)(x)) << (((unsigned)(c)) & 31u)) | \
	 (((u32)(x)) >> ((0u - (((unsigned)(c)) & 31u)) & 31u)))
#define ROTR(x,c) \
	((((u32)(x)) >> (((unsigned)(c)) & 31u)) | \
	 (((u32)(x)) << ((0u - (((unsigned)(c)) & 31u)) & 31u)))
#define SHR(x,c) \
	((((unsigned)(c)) >= 32u) ? 0u : (((u32)(x)) >> ((unsigned)(c))))
#define LROT64(x, c) \
	((((u64)(x)) << (((unsigned)(c)) & 63u)) | \
	 (((u64)(x)) >> ((0u - (((unsigned)(c)) & 63u)) & 63u)))
#define RROT64(x, c) \
	((((u64)(x)) >> (((unsigned)(c)) & 63u)) | \
	 (((u64)(x)) << ((0u - (((unsigned)(c)) & 63u)) & 63u)))
#endif

#endif /* _COMMON_H_ */