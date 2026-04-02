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

#include "lea.h"
#include "lea_locl.h"

void MAKE_FUNC(ecb_enc)(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const LEA_KEY *key)
{
	unsigned int remainBlock = pt_len >> 4;

	if (!key){
		return;
	}

	if (pt_len > 0 && (!pt || !ct)){
		return;
	}

	if (pt_len & 0xf){
		return;
	}

#if MAX_BLK >= 8
	for (; remainBlock >= 8; remainBlock -= 8, pt += 0x80, ct += 0x80){
		lea_encrypt_8block(ct, pt, key);
	}
#endif
#if MAX_BLK >= 4
	for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
		lea_encrypt_4block(ct, pt, key);
	}
#endif

	for (; remainBlock >= 1; remainBlock -= 1, pt += 0x10, ct += 0x10){
		lea_encrypt_1block(ct, pt, key);
	}

}

void MAKE_FUNC(ecb_dec)(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const LEA_KEY *key)
{
	unsigned int remainBlock = ct_len >> 4;

	if (!key){
		return;
	}

	if (ct_len > 0 && (!pt || !ct)){
		return;
	}

	if (ct_len & 0xf){
		return;
	}

#if MAX_BLK >= 8
	for (; remainBlock >= 8; remainBlock -= 8, pt += 0x80, ct += 0x80){
		lea_decrypt_8block(pt, ct, key);
	}
#endif
#if MAX_BLK >= 4
	for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
		lea_decrypt_4block(pt, ct, key);
	}
#endif
	for (; remainBlock >= 1; remainBlock -= 1, pt += 0x10, ct += 0x10){
		lea_decrypt_1block(pt, ct, key);
	}

}


