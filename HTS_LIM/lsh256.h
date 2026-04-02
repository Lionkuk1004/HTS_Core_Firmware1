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
 * * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _REF_LSH256_H_
#define _REF_LSH256_H_

#include "lsh.h"
#include "lsh_def.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * LSH256 해시 내부 상태를 초기화한다.
	 *
	 * @param [in] ctx 해시 내부 상태 구조체
	 * @param [in] algtype LSH 알고리즘 명세
	 *
	 * @return LSH_SUCCESS 내부 상태 초기화 성공
	 * @return LSH_ERR_NULL_PTR ctx나 hashval이 NULL인 경우
	 * @return LSH_ERR_INVALID_STATE 해시 내부 상태값에 오류가 있는 경우
	 * @return LSH_ERR_INVALID_DATABITLEN 이전에 입력된 데이터의 길이가 8의 배수가 아닌 경우
	 */
	lsh_err lsh256_init(struct LSH256_Context* ctx, const lsh_type algtype);

	/**
	 * LSH256 해시 내부 상태를 업데이트한다.
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
	lsh_err lsh256_update(struct LSH256_Context* ctx, const lsh_u8* data, size_t databitlen);

	/**
	 * LSH256 해시를 계산한다.
	 *
	 * @param [in] ctx 해시 내부 상태 구조체
	 * @param [out] hashval 해시가 저장될 버퍼
	 *
	 * @return LSH_SUCCESS 해시 계산 성공
	 * @return LSH_ERR_NULL_PTR ctx나 hashval이 NULL인 경우
	 * @return LSH_ERR_INVALID_STATE 해시 내부 상태값에 오류가 있는 경우
	 */
	lsh_err lsh256_final(struct LSH256_Context* ctx, lsh_u8* hashval);

	/**
	 * LSH256 해시를 계산한다.
	 *
	 * @param [in] algtype 알고리즘 명세
	 * @param [in] data 데이터
	 * @param [in] databitlen 데이터 길이 (비트단위)
	 * @param [out] hashval 해시가 저장될 버퍼
	 *
	 * @return LSH_SUCCESS 해시 계산 성공
	 */
	lsh_err lsh256_digest(const lsh_type algtype, const lsh_u8* data, size_t databitlen, lsh_u8* hashval);

#ifdef __cplusplus
}
#endif

#endif