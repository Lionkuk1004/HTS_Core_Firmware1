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

#ifndef _KISA_HMAC_H_
#define _KISA_HMAC_H_

#include "common.h"
#include "KISA_SHA256.h"

void HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);
int Verify_HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);

#else
#endif