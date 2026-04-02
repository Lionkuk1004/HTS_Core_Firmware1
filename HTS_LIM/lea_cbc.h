#pragma once
#include <stddef.h> /* NULL — C 및 C++03 호환 (nullptr는 C++11 전용) */
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

void MAKE_FUNC(cbc_enc)(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const unsigned char *iv, const LEA_KEY *key)
{
#ifdef USE_OWN_FUNC
	_lea_cbc_enc(ct,pt,pt_len,iv,key);
#else
	unsigned int nBlock1 = pt_len >> 4, i;
	const unsigned char *iv_ptr = iv;

	if (!ct)
		return;
	else if (!pt)
		return;
	else if ((pt_len == 0) || (pt_len & 0xf))
		return;
	else if (!iv)
		return;
	else if (!key)
		return;

	for(i = 0; i < nBlock1; i++, pt += 16, ct += 16)
	{
		XOR8x16(ct, pt, iv_ptr);
		lea_encrypt_1block(ct, ct, key);

		iv_ptr = ct;
	}
#endif
}

void MAKE_FUNC(cbc_dec)(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const unsigned char *iv, const LEA_KEY *key)
{
	unsigned int remainBlock = ct_len >> 4;
	const unsigned char *pIv = iv;
#if MAX_BLK >= 8 || MAX_BLK >= 4
	unsigned char tmp[128];
#endif

	if (!pt)
		return;
	else if (!ct)
		return;
	else if ((ct_len == 0) || (ct_len & 0xf))
		return;
	else if (!iv)
		return;
	else if (!key)
		return;

	pt += ct_len;
	ct += ct_len;

#if MAX_BLK >= 8
	while (remainBlock > 8){
		pt -= 0x80;
		ct -= 0x80;

		lea_decrypt_8block(tmp, ct, key);
		XOR8x128r(pt, tmp, ct - 16);

		remainBlock -= 8;
	}
#endif

#if MAX_BLK >= 4
	while (remainBlock > 4){
		pt -= 0x40;
		ct -= 0x40;

		lea_decrypt_4block(tmp, ct, key);
		XOR8x64r(pt, tmp, ct - 16);

		remainBlock -= 4;
	}
#endif

	while (remainBlock > 1){ // > 1, not >= 1.
		pt -= 0x10;
		ct -= 0x10;
		pIv = ct - 16;

		lea_decrypt_1block(pt, ct, key);

		XOR8x16(pt, pt, pIv);

		remainBlock -= 1;
	}
	
	pt -= 0x10;
	ct -= 0x10;
	lea_decrypt_1block(pt, ct, key);

	XOR8x16(pt, pt, iv);

}


