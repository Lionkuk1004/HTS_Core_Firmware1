#ifndef _KISA_HMAC_H_
#define _KISA_HMAC_H_

#include "common.h"
#include "KISA_SHA256.h"

void HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);
int Verify_HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);

#else
#endif