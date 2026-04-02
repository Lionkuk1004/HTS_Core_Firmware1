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

void MAKE_FUNC(ofb_enc)(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, unsigned char *iv, const LEA_KEY *key)
{

	//unsigned char iv_tmp[16];
	unsigned int numBlock1 = pt_len >> 4, i;

	if (!iv || !key){
		return;
	}

	if (pt_len > 0 && (!ct || !pt)){
		return;
	}

#if defined(USE_OWN_FUNC)
	_lea_ofb_enc(ct,pt,pt_len,iv,key);
	if(numBlock1 > 0 && pt_len & 0xf){
	}
#else
	//CPY8x16(iv_tmp, iv);

	for(i = 0; i < numBlock1; i++, pt += 0x10, ct += 0x10)
	{
		lea_encrypt_1block(iv, iv, key);

		XOR8x16(ct, pt, iv);
	}
#endif
	if((numBlock1 << 4) != pt_len)
	{
		lea_encrypt_1block(iv, iv, key);

		for(i = 0; i < pt_len - (numBlock1 << 4); i++)
			ct[i] = iv[i] ^ pt[i];
	}

}

void MAKE_FUNC(ofb_dec)(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, unsigned char *iv, const LEA_KEY *key)
{
	MAKE_FUNC(ofb_enc)(pt, ct, ct_len, iv, key);
}


