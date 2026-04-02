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

#ifndef _SIMD_LSH_H_
#define _SIMD_LSH_H_

#include "lsh_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4324)
#endif

/**
 * LSH256 내부 상태를 저장하기 위한 구조체
 */
struct LSH_ALIGNED_(32) LSH256_Context{
	LSH_ALIGNED_(16) lsh_type algtype;
	LSH_ALIGNED_(16) lsh_uint remain_databitlen;
	LSH_ALIGNED_(32) lsh_u32 cv_l[8];
	LSH_ALIGNED_(32) lsh_u32 cv_r[8];
	LSH_ALIGNED_(32) lsh_u8 last_block[LSH256_MSG_BLK_BYTE_LEN];
};

/**
 * LSH512 내부 상태를 저장하기 위한 구조체
 */
struct LSH_ALIGNED_(32) LSH512_Context{
	LSH_ALIGNED_(16) lsh_type algtype;
	LSH_ALIGNED_(16) lsh_uint remain_databitlen;
	LSH_ALIGNED_(32) lsh_u64 cv_l[8];
	LSH_ALIGNED_(32) lsh_u64 cv_r[8];
	LSH_ALIGNED_(32) lsh_u8 last_block[LSH512_MSG_BLK_BYTE_LEN];
};

/**
 * LSH 내부 상태를 저장하기 위한 유니온
 */
union LSH_ALIGNED_(32) LSH_Context{
	LSH_ALIGNED_(32) struct LSH256_Context ctx256;
	LSH_ALIGNED_(32) struct LSH512_Context ctx512;
	LSH_ALIGNED_(16) lsh_type algtype;
};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

/**
 * LSH 해시 내부 상태를 초기화한다.
 *
 * @param [in] ctx 해시 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 * @return LSH_ERR_NULL_PTR ctx나 hashval이 NULL인 경우 
 * @return LSH_ERR_INVALID_STATE 해시 내부 상태값에 오류가 있는 경우
 * @return LSH_ERR_INVALID_DATABITLEN 이전에 입력된 데이터의 길이가 8의 배수가 아닌 경우
 */
lsh_err lsh_init(union LSH_Context * ctx, const lsh_type algtype);

/**
 * LSH 해시 내부 상태를 업데이트한다.
 *
 * @param [inout] ctx 해시 내부 상태 구조체
 * @param [in] data 해시를 계산할 데이터
 * @param [in] databitlen 데이터 길이 (비트단위)
 *
 * @return LSH_SUCCESS 업데이트 성공
 * @return LSH_ERR_NULL_PTR ctx나 hashval이 NULL인 경우 
 * @return LSH_ERR_INVALID_STATE 해시 내부 상태값에 오류가 있는 경우
 * @return LSH_ERR_INVALID_DATABITLEN 이전에 입력된 데이터의 길이가 8의 배수가 아닌 경우
 */
lsh_err lsh_update(union LSH_Context * ctx, const lsh_u8 * data, size_t databitlen);

/**
 * LSH 해시를 계산한다.
 *
 * @param [in] ctx 해시 내부 상태 구조체
 * @param [out] hashval 해시가 저장될 버퍼, alignment가 맞아야한다.
 *
 * @return LSH_SUCCESS 해시 계산 성공
 * @return LSH_ERR_NULL_PTR ctx나 hashval이 NULL인 경우
 * @return LSH_ERR_INVALID_STATE 해시 내부 상태값에 오류가 있는 경우
 */
lsh_err lsh_final(union LSH_Context * ctx, lsh_u8 * hashval);

/**
 * LSH 해시를 계산한다.
 *
 * @param [in] algtype 알고리즘 명세
 * @param [in] data 데이터
 * @param [in] databitlen 데이터 길이 (비트단위)
 * @param [out] hashval 해시가 저장될 버퍼, alignment가 맞아야한다.
 *
 * @return LSH_SUCCESS 해시 계산 성공
 */
lsh_err lsh_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

/**
 * NEON지원 여부를 확인하여 SIMD 사용 여부를 결정한다.
 */
void lsh_init_simd();

/**
 * 현재 활성화된 구현의 이름을 반환한다.
 *
 * @return 활성화된 구현의 이름, ndef 혹은 neon
 */
const char * lsh_get_simd_type();

#ifdef __cplusplus
}
#endif

#endif