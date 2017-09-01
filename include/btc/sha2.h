/**
 * Copyright (c) 2000-2001 Aaron D. Gifford
 * Copyright (c) 2013 Pavol Rusnak
 * Copyright (c) 2015 Jonas Schnelli
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __LIBBTC_SHA2_H__
#define __LIBBTC_SHA2_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "btc.h"

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64
#define SHA512_DIGEST_STRING_LENGTH (SHA512_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;
typedef struct _SHA512_CTX {
    uint64_t state[8];
    uint64_t bitcount[2];
    uint8_t buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;

/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-256: */
static const uint32_t K256[64] = {
    0x428a2f98UL,
    0x71374491UL,
    0xb5c0fbcfUL,
    0xe9b5dba5UL,
    0x3956c25bUL,
    0x59f111f1UL,
    0x923f82a4UL,
    0xab1c5ed5UL,
    0xd807aa98UL,
    0x12835b01UL,
    0x243185beUL,
    0x550c7dc3UL,
    0x72be5d74UL,
    0x80deb1feUL,
    0x9bdc06a7UL,
    0xc19bf174UL,
    0xe49b69c1UL,
    0xefbe4786UL,
    0x0fc19dc6UL,
    0x240ca1ccUL,
    0x2de92c6fUL,
    0x4a7484aaUL,
    0x5cb0a9dcUL,
    0x76f988daUL,
    0x983e5152UL,
    0xa831c66dUL,
    0xb00327c8UL,
    0xbf597fc7UL,
    0xc6e00bf3UL,
    0xd5a79147UL,
    0x06ca6351UL,
    0x14292967UL,
    0x27b70a85UL,
    0x2e1b2138UL,
    0x4d2c6dfcUL,
    0x53380d13UL,
    0x650a7354UL,
    0x766a0abbUL,
    0x81c2c92eUL,
    0x92722c85UL,
    0xa2bfe8a1UL,
    0xa81a664bUL,
    0xc24b8b70UL,
    0xc76c51a3UL,
    0xd192e819UL,
    0xd6990624UL,
    0xf40e3585UL,
    0x106aa070UL,
    0x19a4c116UL,
    0x1e376c08UL,
    0x2748774cUL,
    0x34b0bcb5UL,
    0x391c0cb3UL,
    0x4ed8aa4aUL,
    0x5b9cca4fUL,
    0x682e6ff3UL,
    0x748f82eeUL,
    0x78a5636fUL,
    0x84c87814UL,
    0x8cc70208UL,
    0x90befffaUL,
    0xa4506cebUL,
    0xbef9a3f7UL,
    0xc67178f2UL};

/* Initial hash value H for SHA-256: */
static const uint32_t sha256_initial_hash_value[8] = {
    0x6a09e667UL,
    0xbb67ae85UL,
    0x3c6ef372UL,
    0xa54ff53aUL,
    0x510e527fUL,
    0x9b05688cUL,
    0x1f83d9abUL,
    0x5be0cd19UL};

/* Hash constant words K for SHA-384 and SHA-512: */
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,
    0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL,
    0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL,
    0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,
    0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,
    0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL,
    0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL,
    0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,
    0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL,
    0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,
    0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,
    0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL,
    0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL,
    0xf40e35855771202aULL,
    0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,
    0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,
    0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL,
    0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,
    0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL,
    0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL,
    0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL,
    0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,
    0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,
    0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL,
    0x6c44198c4a475817ULL};

/* Initial hash value H for SHA-512 */
static const uint64_t sha512_initial_hash_value[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL};

LIBBTC_API void sha256_Init(SHA256_CTX*);
LIBBTC_API void sha256_Update(SHA256_CTX*, const uint8_t*, size_t);
LIBBTC_API void sha256_Final(uint8_t[SHA256_DIGEST_LENGTH], SHA256_CTX*);
LIBBTC_API void sha256_Raw(const uint8_t*, size_t, uint8_t[SHA256_DIGEST_LENGTH]);

LIBBTC_API void sha512_Init(SHA512_CTX*);
LIBBTC_API void sha512_Update(SHA512_CTX*, const uint8_t*, size_t);
LIBBTC_API void sha512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
LIBBTC_API void sha512_Raw(const uint8_t*, size_t, uint8_t[SHA512_DIGEST_LENGTH]);

LIBBTC_API void hmac_sha256(const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);
LIBBTC_API void hmac_sha512(const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBTC_SHA2_H__ */