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

#define LROT(x,c) (((x) << (c)) | ((x) >> (32 - (c))))
#define ROTR(x,c) (((x) >> (c)) ^ ((x) << (32 - (c))))
#define SHR(x,c)  ((x) >> (c))
#define LROT64(x, c) (((u64)(x) << (c)) | ((u64)(x) >> (64 - (c))))
#define RROT64(x, c) LROT64((u64)(x), 64 - (c))

#endif /* _COMMON_H_ */