#include "KISA_HMAC.h"


void HMAC_SHA256(const u8 *message, u32 mlen, const u8 *key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN])
{
	SHA256_INFO hash_ctx;
	u8 ipad = 0x36, opad = 0x5c;
	u32 i = 0;
	u8 tk[SHA256_DIGEST_VALUELEN], tb[SHA256_DIGEST_BLOCKLEN];
	
	if (klen > SHA256_DIGEST_BLOCKLEN)
	{
		SHA256_Encrpyt(key, klen, tk);
		klen = SHA256_DIGEST_VALUELEN;
		key = tk;
	}

	for (i = 0; i < klen; i++)	tb[i] = ipad ^ key[i];
	for (i = klen; i < SHA256_DIGEST_BLOCKLEN; i++)	tb[i] = ipad ^ 0;

	SHA256_Init(&hash_ctx);
	SHA256_Process(&hash_ctx, tb, SHA256_DIGEST_BLOCKLEN);
	SHA256_Process(&hash_ctx, message, mlen);
	SHA256_Close(&hash_ctx, hmac);

	for (i = 0; i < klen; i++)	tb[i] = opad ^ key[i];
	for (i = klen; i < SHA256_DIGEST_BLOCKLEN; i++)	tb[i] = opad ^ 0;

	SHA256_Init(&hash_ctx);
	SHA256_Process(&hash_ctx, tb, SHA256_DIGEST_BLOCKLEN);
	SHA256_Process(&hash_ctx, hmac, SHA256_DIGEST_VALUELEN);
	SHA256_Close(&hash_ctx, hmac);
}

int Verify_HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN])
{
	SHA256_INFO hash_ctx;
	u8 ipad = 0x36, opad = 0x5c;
	u32 i = 0;
	u8 tk[SHA256_DIGEST_VALUELEN], tb[SHA256_DIGEST_BLOCKLEN], cmp_hmac[SHA256_DIGEST_VALUELEN];

	if (klen > SHA256_DIGEST_BLOCKLEN)
	{
		SHA256_Encrpyt(key, klen, tk);
		klen = SHA256_DIGEST_VALUELEN;
		key = tk;
	}

	for (i = 0; i < klen; i++)	tb[i] = ipad ^ key[i];
	for (i = klen; i < SHA256_DIGEST_BLOCKLEN; i++)	tb[i] = ipad ^ 0;

	SHA256_Init(&hash_ctx);
	SHA256_Process(&hash_ctx, tb, SHA256_DIGEST_BLOCKLEN);
	SHA256_Process(&hash_ctx, message, mlen);
	SHA256_Close(&hash_ctx, cmp_hmac);

	for (i = 0; i < klen; i++)	tb[i] = opad ^ key[i];
	for (i = klen; i < SHA256_DIGEST_BLOCKLEN; i++)	tb[i] = opad ^ 0;

	SHA256_Init(&hash_ctx);
	SHA256_Process(&hash_ctx, tb, SHA256_DIGEST_BLOCKLEN);
	SHA256_Process(&hash_ctx, cmp_hmac, SHA256_DIGEST_VALUELEN);
	SHA256_Close(&hash_ctx, cmp_hmac);

	for (i = 0; i < SHA256_DIGEST_VALUELEN; i++)
		if (hmac[i] != cmp_hmac[i])
			return 1;

	return 0;
}
