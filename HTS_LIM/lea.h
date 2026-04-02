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

#ifndef _LEA_HEADER_
#define _LEA_HEADER_

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Auto-initialized. Use this function if your compiler is not MSVC or GCC.
EXPORT void init_simd();

typedef struct lea_key_st
{
	unsigned int rk[192];
	unsigned int round;
} LEA_KEY;

EXPORT void lea_set_key(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);

EXPORT void lea_ecb_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const LEA_KEY *key);
EXPORT void lea_ecb_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const LEA_KEY *key);

EXPORT void lea_cbc_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const unsigned char *iv, const LEA_KEY *key);
EXPORT void lea_cbc_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const unsigned char *iv, const LEA_KEY *key);

EXPORT void lea_ctr_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, unsigned char *ctr, const LEA_KEY *key);
EXPORT void lea_ctr_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, unsigned char *ctr, const LEA_KEY *key);

EXPORT void lea_ofb_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, unsigned char *iv, const LEA_KEY *key);
EXPORT void lea_ofb_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, unsigned char *iv, const LEA_KEY *key);

EXPORT void lea_cfb128_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const unsigned char *iv, const LEA_KEY *key);
EXPORT void lea_cfb128_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const unsigned char *iv, const LEA_KEY *key);

#define LEA_ECB_NOPAD_ENC		0x401031
#define LEA_ECB_NOPAD_DEC		0x401032
#define LEA_ECB_PKCS5PAD_ENC	0x401121
#define LEA_ECB_PKCS5PAD_DEC	0x401172
#define LEA_CBC_NOPAD_ENC		0x402011
#define LEA_CBC_NOPAD_DEC		0x402012
#define LEA_CBC_PKCS5PAD_ENC	0x402101
#define LEA_CBC_PKCS5PAD_DEC	0x402152
#define LEA_CTR_ENC				0x403001
#define LEA_CTR_DEC				0x403002
#define LEA_OFB_ENC				0x404001
#define	LEA_OFB_DEC				0x404002
#define LEA_CFB128_ENC			0x405001
#define LEA_CFB128_DEC			0x405002

typedef struct lea_online_ctx{
	unsigned char iv[16];
	unsigned char last_block[16];
	LEA_KEY key;

	int nlast_block;
	unsigned int encType;

} LEA_ONLINE_CTX;

EXPORT int lea_online_init(LEA_ONLINE_CTX *ctx, unsigned int encType, const unsigned char * iv, const unsigned char *mk, int mk_len);
EXPORT int lea_online_init_ex(LEA_ONLINE_CTX *ctx, unsigned int encType, const unsigned char * iv, const LEA_KEY* key);
EXPORT int lea_online_update(LEA_ONLINE_CTX *ctx, unsigned char * out, unsigned char *in, int in_len);
EXPORT int lea_online_final(LEA_ONLINE_CTX *ctx, unsigned char * out);


typedef struct lea_cmac_ctx
{
	unsigned char k1[16];
	unsigned char k2[16];
	unsigned char tbl[16];
	unsigned char last_block[16];
	LEA_KEY key;

	int nlast_block;
} LEA_CMAC_CTX;

EXPORT void lea_cmac_init(LEA_CMAC_CTX *ctx, const unsigned char *mk, int mk_len);
EXPORT void lea_cmac_update(LEA_CMAC_CTX *ctx, const unsigned char *data, int data_len);
EXPORT void lea_cmac_final(LEA_CMAC_CTX *ctx, unsigned char *cmac, int cmac_len);

EXPORT int lea_ccm_enc(unsigned char *ct, unsigned char *T, const unsigned char *pt, unsigned int pt_len, unsigned int Tlen,
						 const unsigned char *N, unsigned int Nlen, const unsigned char *A, unsigned int Alen, const LEA_KEY *key);
EXPORT int lea_ccm_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const unsigned char *T, unsigned int tag_bytes,
						 const unsigned char *N, unsigned int Nlen, const unsigned char *A, unsigned int Alen, const LEA_KEY *key);


typedef struct lea_gcm_ctx
{
	unsigned char h[256][16];
	unsigned char ctr[16];
	unsigned char ek0[16];
	unsigned char tbl[16];	/* tag block */
	unsigned char yn[16];	/* last encrypted block */
	LEA_KEY key;

	int yn_used, aad_len, ct_len;
	int is_encrypt;
} LEA_GCM_CTX;

EXPORT void lea_gcm_init(LEA_GCM_CTX *ctx, const unsigned char *mk, int mk_len);
EXPORT void lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const unsigned char *iv, int iv_len);
EXPORT void lea_gcm_set_aad(LEA_GCM_CTX *ctx, const unsigned char *aad, int aad_len);
EXPORT void lea_gcm_enc(LEA_GCM_CTX *ctx, unsigned char *ct, const unsigned char *pt, int pt_len);
EXPORT void lea_gcm_dec(LEA_GCM_CTX *ctx, unsigned char *pt, const unsigned char *ct, int ct_len);
EXPORT int lea_gcm_final(LEA_GCM_CTX *ctx, unsigned char *tag, int tag_len);

EXPORT const char * get_simd_type();

#ifdef __cplusplus
}
#endif

#endif


