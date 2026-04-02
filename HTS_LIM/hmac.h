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

/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 */

#ifndef _SIMD_HMAC_H_
#define _SIMD_HMAC_H_

#include "lsh_def.h"
#include "lsh.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC 계산을 위한 내부 상태 구조체
 */
struct LSH_ALIGNED_(32) HMAC_LSH_Context{
	LSH_ALIGNED_(32) union LSH_Context hash_ctx;
	LSH_ALIGNED_(32) lsh_u8 opad[LSH512_MSG_BLK_BYTE_LEN];
};

/**
 * HMAC의 내부 상태를 초기화 한다.
 *
 * @param [in] ctx HMAC 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] key 키
 * @param [in] keybytelen 키 길이 (바이트 단위)
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_lsh_init(struct HMAC_LSH_Context * ctx, lsh_type algtype, const lsh_u8 * key, size_t keybytelen);

/**
 * 주어진 데이터에 대해 HMAC의 내부 상태를 업데이트 한다.
 *
 * @param [in] ctx HMAC 내부 상태 구조체
 * @param [in] data 데이터
 * @param [in] databytelen 데이터 길이 (바이트 단위)
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_lsh_update(struct HMAC_LSH_Context * ctx, const lsh_u8* data, size_t databytelen);

/**
 * 최종 HMAC을 계산한다.
 *
 * @param [in] ctx HMAC 내부 상태 구조체
 * @param [out] digest HMAC 출력 버퍼
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_lsh_final(struct HMAC_LSH_Context * ctx, lsh_u8* digest);

/**
 * init, update, final 과정을 한번에 수행하여 HMAC을 계산한다.
 *
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] key 키
 * @param [in] keybytelen 키 길이 (바이트 단위)
 * @param [in] data 데이터
 * @param [in] databytelen 데이터 길이 (바이트 단위)
 * @param [out] digest HMAC 출력 버퍼
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_lsh_digest(lsh_type algtype, const lsh_u8* key, size_t keybytelen, const lsh_u8* data, size_t databytelen, lsh_u8* digest);

#ifdef __cplusplus
}
#endif

#endif