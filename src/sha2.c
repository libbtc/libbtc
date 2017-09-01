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

#include <btc/sha2.h>
#include <stdint.h>
#include <string.h>

/*
 * ASSERT NOTE:
 * Some sanity checking code is included using assert().  On my FreeBSD
 * system, this additional code can be removed by compiling with NDEBUG
 * defined.  Check your own systems manpage on assert() to see how to
 * compile WITHOUT the sanity checking code on your system.
 *
 * UNROLLED TRANSFORM LOOP NOTE:
 * You can define SHA2_UNROLL_TRANSFORM to use the unrolled transform
 * loop version for the hash transform rounds (defined using macros
 * later in this file).  Either define on the command line, for example:
 *
 *   cc -DSHA2_UNROLL_TRANSFORM -o sha2 sha2.c sha2prog.c
 *
 * or define below:
 *
 *   #define SHA2_UNROLL_TRANSFORM
 *
 */


/*** SHA-256/384/512 Machine Architecture Definitions *****************/
/*
 * BYTE_ORDER NOTE:
 *
 * Please make sure that your system defines BYTE_ORDER.  If your
 * architecture is little-endian, make sure it also defines
 * LITTLE_ENDIAN and that the two (BYTE_ORDER and LITTLE_ENDIAN) are
 * equivilent.
 *
 * If your system does not define the above, then you can do so by
 * hand like this:
 *
 *   #define LITTLE_ENDIAN 1234
 *   #define BIG_ENDIAN    4321
 *
 * And for little-endian machines, add:
 *
 *   #define BYTE_ORDER LITTLE_ENDIAN
 *
 * Or for big-endian machines:
 *
 *   #define BYTE_ORDER BIG_ENDIAN
 *
 * The FreeBSD machine this was written on defines BYTE_ORDER
 * appropriately by including <sys/types.h> (which in turn includes
 * <machine/endian.h> where the appropriate definitions are actually
 * made).
 */

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#endif

typedef uint8_t sha2_byte;    /* Exactly 1 byte */
typedef uint32_t sha2_word32; /* Exactly 4 bytes */
typedef uint64_t sha2_word64; /* Exactly 8 bytes */

/*** SHA-256/384/512 Various Length Definitions ***********************/
/* NOTE: Most of these are in sha2.h */
#define SHA256_SHORT_BLOCK_LENGTH (SHA256_BLOCK_LENGTH - 8)
#define SHA512_SHORT_BLOCK_LENGTH (SHA512_BLOCK_LENGTH - 16)


/*** ENDIAN REVERSAL MACROS *******************************************/
#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w, x)                                                  \
    {                                                                    \
        sha2_word32 tmp = (w);                                           \
        tmp = (tmp >> 16) | (tmp << 16);                                 \
        (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
    }
#define REVERSE64(w, x)                                                                      \
    {                                                                                        \
        sha2_word64 tmp = (w);                                                               \
        tmp = (tmp >> 32) | (tmp << 32);                                                     \
        tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | ((tmp & 0x00ff00ff00ff00ffULL) << 8);   \
        (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | ((tmp & 0x0000ffff0000ffffULL) << 16); \
    }
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

/*
 * Macro for incrementally adding the unsigned 64-bit integer n to the
 * unsigned 128-bit integer (represented using a two-element array of
 * 64-bit words):
 */
#define ADDINC128(w, n)             \
    {                               \
        (w)[0] += (sha2_word64)(n); \
        if ((w)[0] < (n)) {         \
            (w)[1]++;               \
        }                           \
    }

#define MEMSET_BZERO(p, l) memset((p), 0, (l))
#define MEMCPY_BCOPY(d, s, l) memcpy((d), (s), (l))

/*** THE SIX LOGICAL FUNCTIONS ****************************************/
/*
 * Bit shifting and rotation (used by the six SHA-XYZ logical functions:
 *
 *   NOTE:  The naming of R and S appears backwards here (R is a SHIFT and
 *   S is a ROTATION) because the SHA-256/384/512 description document
 *   (see http://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf) uses this
 *   same "backwards" definition.
 */
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b, x) ((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define S32(b, x) (((x) >> (b)) | ((x) << (32 - (b))))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define S64(b, x) (((x) >> (b)) | ((x) << (64 - (b))))

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x) (S32(2, (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x) (S32(6, (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x) (S32(7, (x)) ^ S32(18, (x)) ^ R(3, (x)))
#define sigma1_256(x) (S32(17, (x)) ^ S32(19, (x)) ^ R(10, (x)))

/* Four of six logical functions used in SHA-384 and SHA-512: */
#define Sigma0_512(x) (S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x) (S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x) (S64(1, (x)) ^ S64(8, (x)) ^ R(7, (x)))
#define sigma1_512(x) (S64(19, (x)) ^ S64(61, (x)) ^ R(6, (x)))

/*** INTERNAL FUNCTION PROTOTYPES *************************************/
/* NOTE: These should not be accessed directly from outside this
 * library -- they are intended for private internal visibility/use
 * only.
 */
void sha512_Last(SHA512_CTX*);
void sha256_Transform(SHA256_CTX*, const sha2_word32*);
void sha512_Transform(SHA512_CTX*, const sha2_word64*);

/*** SHA-256: *********************************************************/
void sha256_Init(SHA256_CTX* context)
{
    if (context == (SHA256_CTX*)0) {
        return;
    }
    MEMCPY_BCOPY(context->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
    MEMSET_BZERO(context->buffer, SHA256_BLOCK_LENGTH);
    context->bitcount = 0;
}

#ifdef SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-256 round macros: */

#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND256_0_TO_15(a, b, c, d, e, f, g, h)                      \
    REVERSE32(*data++, W256[j]);                                      \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + W256[j]; \
    (d) += T1;                                                        \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c));                    \
    j++


#else /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND256_0_TO_15(a, b, c, d, e, f, g, h)                                  \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + (W256[j] = *data++); \
    (d) += T1;                                                                    \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c));                                \
    j++

#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND256(a, b, c, d, e, f, g, h)                                                                         \
    s0 = W256[(j + 1) & 0x0f];                                                                                   \
    s0 = sigma0_256(s0);                                                                                         \
    s1 = W256[(j + 14) & 0x0f];                                                                                  \
    s1 = sigma1_256(s1);                                                                                         \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + (W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0); \
    (d) += T1;                                                                                                   \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c));                                                               \
    j++

void sha256_Transform(SHA256_CTX* context, const sha2_word32* data)
{
    sha2_word32 a, b, c, d, e, f, g, h, s0, s1;
    sha2_word32 T1, *W256;
    int j;

    W256 = (sha2_word32*)context->buffer;

    /* Initialize registers with the prev. intermediate value */
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    j = 0;
    do {
        /* Rounds 0 to 15 (unrolled): */
        ROUND256_0_TO_15(a, b, c, d, e, f, g, h);
        ROUND256_0_TO_15(h, a, b, c, d, e, f, g);
        ROUND256_0_TO_15(g, h, a, b, c, d, e, f);
        ROUND256_0_TO_15(f, g, h, a, b, c, d, e);
        ROUND256_0_TO_15(e, f, g, h, a, b, c, d);
        ROUND256_0_TO_15(d, e, f, g, h, a, b, c);
        ROUND256_0_TO_15(c, d, e, f, g, h, a, b);
        ROUND256_0_TO_15(b, c, d, e, f, g, h, a);
    } while (j < 16);

    /* Now for the remaining rounds to 64: */
    do {
        ROUND256(a, b, c, d, e, f, g, h);
        ROUND256(h, a, b, c, d, e, f, g);
        ROUND256(g, h, a, b, c, d, e, f);
        ROUND256(f, g, h, a, b, c, d, e);
        ROUND256(e, f, g, h, a, b, c, d);
        ROUND256(d, e, f, g, h, a, b, c);
        ROUND256(c, d, e, f, g, h, a, b);
        ROUND256(b, c, d, e, f, g, h, a);
    } while (j < 64);

    /* Compute the current intermediate hash value */
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

void sha256_Transform(SHA256_CTX* context, const sha2_word32* data)
{
    sha2_word32 a, b, c, d, e, f, g, h, s0, s1;
    sha2_word32 T1, T2, *W256;
    int j;

    W256 = (sha2_word32*)context->buffer;

    /* Initialize registers with the prev. intermediate value */
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    j = 0;
    do {
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Copy data while converting to host byte order */
        REVERSE32(*data++, W256[j]);
        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
#else  /* BYTE_ORDER == LITTLE_ENDIAN */
        /* Apply the SHA-256 compression function to update a..h with copy */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W256[(j + 1) & 0x0f];
        s0 = sigma0_256(s0);
        s1 = W256[(j + 14) & 0x0f];
        s1 = sigma1_256(s1);

        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
             (W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0);
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 64);

    /* Compute the current intermediate hash value */
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void sha256_Update(SHA256_CTX* context, const sha2_byte* data, size_t len)
{
    unsigned int freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            MEMCPY_BCOPY(&context->buffer[usedspace], data, freespace);
            context->bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
            sha256_Transform(context, (sha2_word32*)context->buffer);
        } else {
            /* The buffer is not yet full */
            MEMCPY_BCOPY(&context->buffer[usedspace], data, len);
            context->bitcount += len << 3;
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        sha256_Transform(context, (const sha2_word32*)data);
        context->bitcount += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        MEMCPY_BCOPY(context->buffer, data, len);
        context->bitcount += len << 3;
    }
    /* Clean up: */
    usedspace = freespace = 0;
}

void sha256_Final(sha2_byte digest[], SHA256_CTX* context)
{
    sha2_word32* d = (sha2_word32*)digest;
    unsigned int usedspace;
    sha2_word64* t;

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != (sha2_byte*)0) {
        usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host byte order */
        REVERSE64(context->bitcount, context->bitcount);
#endif
        if (usedspace > 0) {
            /* Begin padding with a 1 bit: */
            context->buffer[usedspace++] = 0x80;

            if (usedspace <= SHA256_SHORT_BLOCK_LENGTH) {
                /* Set-up for the last transform: */
                MEMSET_BZERO(&context->buffer[usedspace], SHA256_SHORT_BLOCK_LENGTH - usedspace);
            } else {
                if (usedspace < SHA256_BLOCK_LENGTH) {
                    MEMSET_BZERO(&context->buffer[usedspace], SHA256_BLOCK_LENGTH - usedspace);
                }
                /* Do second-to-last transform: */
                sha256_Transform(context, (sha2_word32*)context->buffer);

                /* And set-up for the last transform: */
                MEMSET_BZERO(context->buffer, SHA256_SHORT_BLOCK_LENGTH);
            }
        } else {
            /* Set-up for the last transform: */
            MEMSET_BZERO(context->buffer, SHA256_SHORT_BLOCK_LENGTH);

            /* Begin padding with a 1 bit: */
            *context->buffer = 0x80;
        }
        /* Set the bit count: */
        t = (sha2_word64*)&context->buffer[SHA256_SHORT_BLOCK_LENGTH];
        *t = context->bitcount;

        /* Final transform: */
        sha256_Transform(context, (sha2_word32*)context->buffer);

#if BYTE_ORDER == LITTLE_ENDIAN
        {
            /* Convert TO host byte order */
            int j;
            for (j = 0; j < 8; j++) {
                REVERSE32(context->state[j], context->state[j]);
                *d++ = context->state[j];
            }
        }
#else
        MEMCPY_BCOPY(d, context->state, SHA256_DIGEST_LENGTH);
#endif
    }

    /* Clean up state data: */
    MEMSET_BZERO(context, sizeof(SHA256_CTX));
    usedspace = 0;
}

void sha256_Raw(const sha2_byte* data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, data, len);
    sha256_Final(digest, &context);
}


/*** SHA-512: *********************************************************/
void sha512_Init(SHA512_CTX* context)
{
    if (context == (SHA512_CTX*)0) {
        return;
    }
    MEMCPY_BCOPY(context->state, sha512_initial_hash_value, SHA512_DIGEST_LENGTH);
    MEMSET_BZERO(context->buffer, SHA512_BLOCK_LENGTH);
    context->bitcount[0] = context->bitcount[1] = 0;
}

#ifdef SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-512 round macros: */
#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND512_0_TO_15(a, b, c, d, e, f, g, h)                      \
    REVERSE64(*data++, W512[j]);                                      \
    T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + K512[j] + W512[j]; \
    (d) += T1,                                                        \
        (h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)),                \
        j++


#else /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND512_0_TO_15(a, b, c, d, e, f, g, h)                                  \
    T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + K512[j] + (W512[j] = *data++); \
    (d) += T1;                                                                    \
    (h) = T1 + Sigma0_512(a) + Maj((a), (b), (c));                                \
    j++

#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND512(a, b, c, d, e, f, g, h)                                                                         \
    s0 = W512[(j + 1) & 0x0f];                                                                                   \
    s0 = sigma0_512(s0);                                                                                         \
    s1 = W512[(j + 14) & 0x0f];                                                                                  \
    s1 = sigma1_512(s1);                                                                                         \
    T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + K512[j] + (W512[j & 0x0f] += s1 + W512[(j + 9) & 0x0f] + s0); \
    (d) += T1;                                                                                                   \
    (h) = T1 + Sigma0_512(a) + Maj((a), (b), (c));                                                               \
    j++

void sha512_Transform(SHA512_CTX* context, const sha2_word64* data)
{
    sha2_word64 a, b, c, d, e, f, g, h, s0, s1;
    sha2_word64 T1, *W512 = (sha2_word64*)context->buffer;
    int j;

    /* Initialize registers with the prev. intermediate value */
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    j = 0;
    do {
        ROUND512_0_TO_15(a, b, c, d, e, f, g, h);
        ROUND512_0_TO_15(h, a, b, c, d, e, f, g);
        ROUND512_0_TO_15(g, h, a, b, c, d, e, f);
        ROUND512_0_TO_15(f, g, h, a, b, c, d, e);
        ROUND512_0_TO_15(e, f, g, h, a, b, c, d);
        ROUND512_0_TO_15(d, e, f, g, h, a, b, c);
        ROUND512_0_TO_15(c, d, e, f, g, h, a, b);
        ROUND512_0_TO_15(b, c, d, e, f, g, h, a);
    } while (j < 16);

    /* Now for the remaining rounds up to 79: */
    do {
        ROUND512(a, b, c, d, e, f, g, h);
        ROUND512(h, a, b, c, d, e, f, g);
        ROUND512(g, h, a, b, c, d, e, f);
        ROUND512(f, g, h, a, b, c, d, e);
        ROUND512(e, f, g, h, a, b, c, d);
        ROUND512(d, e, f, g, h, a, b, c);
        ROUND512(c, d, e, f, g, h, a, b);
        ROUND512(b, c, d, e, f, g, h, a);
    } while (j < 80);

    /* Compute the current intermediate hash value */
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

void sha512_Transform(SHA512_CTX* context, const sha2_word64* data)
{
    sha2_word64 a, b, c, d, e, f, g, h, s0, s1;
    sha2_word64 T1, T2, *W512 = (sha2_word64*)context->buffer;
    int j;

    /* Initialize registers with the prev. intermediate value */
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    j = 0;
    do {
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        REVERSE64(*data++, W512[j]);
        /* Apply the SHA-512 compression function to update a..h */
        T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j];
#else  /* BYTE_ORDER == LITTLE_ENDIAN */
        /* Apply the SHA-512 compression function to update a..h with copy */
        T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + (W512[j] = *data++);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
        T2 = Sigma0_512(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W512[(j + 1) & 0x0f];
        s0 = sigma0_512(s0);
        s1 = W512[(j + 14) & 0x0f];
        s1 = sigma1_512(s1);

        /* Apply the SHA-512 compression function to update a..h */
        T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] +
             (W512[j & 0x0f] += s1 + W512[(j + 9) & 0x0f] + s0);
        T2 = Sigma0_512(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 80);

    /* Compute the current intermediate hash value */
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void sha512_Update(SHA512_CTX* context, const sha2_byte* data, size_t len)
{
    unsigned int freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA512_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            MEMCPY_BCOPY(&context->buffer[usedspace], data, freespace);
            ADDINC128(context->bitcount, freespace << 3);
            len -= freespace;
            data += freespace;
            sha512_Transform(context, (sha2_word64*)context->buffer);
        } else {
            /* The buffer is not yet full */
            MEMCPY_BCOPY(&context->buffer[usedspace], data, len);
            ADDINC128(context->bitcount, len << 3);
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA512_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        sha512_Transform(context, (const sha2_word64*)data);
        ADDINC128(context->bitcount, SHA512_BLOCK_LENGTH << 3);
        len -= SHA512_BLOCK_LENGTH;
        data += SHA512_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        MEMCPY_BCOPY(context->buffer, data, len);
        ADDINC128(context->bitcount, len << 3);
    }
    /* Clean up: */
    usedspace = freespace = 0;
}

void sha512_Last(SHA512_CTX* context)
{
    unsigned int usedspace;
    sha2_word64* t;

    usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;
#if BYTE_ORDER == LITTLE_ENDIAN
    /* Convert FROM host byte order */
    REVERSE64(context->bitcount[0], context->bitcount[0]);
    REVERSE64(context->bitcount[1], context->bitcount[1]);
#endif
    if (usedspace > 0) {
        /* Begin padding with a 1 bit: */
        context->buffer[usedspace++] = 0x80;

        if (usedspace <= SHA512_SHORT_BLOCK_LENGTH) {
            /* Set-up for the last transform: */
            MEMSET_BZERO(&context->buffer[usedspace], SHA512_SHORT_BLOCK_LENGTH - usedspace);
        } else {
            if (usedspace < SHA512_BLOCK_LENGTH) {
                MEMSET_BZERO(&context->buffer[usedspace], SHA512_BLOCK_LENGTH - usedspace);
            }
            /* Do second-to-last transform: */
            sha512_Transform(context, (sha2_word64*)context->buffer);

            /* And set-up for the last transform: */
            MEMSET_BZERO(context->buffer, SHA512_BLOCK_LENGTH - 2);
        }
    } else {
        /* Prepare for final transform: */
        MEMSET_BZERO(context->buffer, SHA512_SHORT_BLOCK_LENGTH);

        /* Begin padding with a 1 bit: */
        *context->buffer = 0x80;
    }
    /* Store the length of input data (in bits): */
    t = (sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH];
    *t = context->bitcount[1];
    t = (sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH + 8];
    *t = context->bitcount[0];

    /* Final transform: */
    sha512_Transform(context, (sha2_word64*)context->buffer);
}

void sha512_Final(sha2_byte digest[], SHA512_CTX* context)
{
    sha2_word64* d = (sha2_word64*)digest;

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != (sha2_byte*)0) {
        sha512_Last(context);

/* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
        {
            /* Convert TO host byte order */
            int j;
            for (j = 0; j < 8; j++) {
                REVERSE64(context->state[j], context->state[j]);
                *d++ = context->state[j];
            }
        }
#else
        MEMCPY_BCOPY(d, context->state, SHA512_DIGEST_LENGTH);
#endif
    }

    /* Zero out state data */
    MEMSET_BZERO(context, sizeof(SHA512_CTX));
}

void sha512_Raw(const sha2_byte* data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH])
{
    SHA512_CTX context;
    sha512_Init(&context);
    sha512_Update(&context, data, len);
    sha512_Final(digest, &context);
}

void hmac_sha256(const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac)
{
    int i;
    uint8_t buf[SHA256_BLOCK_LENGTH], o_key_pad[SHA256_BLOCK_LENGTH],
        i_key_pad[SHA256_BLOCK_LENGTH];
    SHA256_CTX ctx;

    memset(buf, 0, SHA256_BLOCK_LENGTH);
    if (keylen > SHA256_BLOCK_LENGTH) {
        sha256_Raw(key, keylen, buf);
    } else {
        memcpy(buf, key, keylen);
    }

    for (i = 0; i < SHA256_BLOCK_LENGTH; i++) {
        o_key_pad[i] = buf[i] ^ 0x5c;
        i_key_pad[i] = buf[i] ^ 0x36;
    }

    sha256_Init(&ctx);
    sha256_Update(&ctx, i_key_pad, SHA256_BLOCK_LENGTH);
    sha256_Update(&ctx, msg, msglen);
    sha256_Final(buf, &ctx);

    sha256_Init(&ctx);
    sha256_Update(&ctx, o_key_pad, SHA256_BLOCK_LENGTH);
    sha256_Update(&ctx, buf, SHA256_DIGEST_LENGTH);
    sha256_Final(hmac, &ctx);
}

void hmac_sha512(const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac)
{
    int i;
    uint8_t buf[SHA512_BLOCK_LENGTH], o_key_pad[SHA512_BLOCK_LENGTH],
        i_key_pad[SHA512_BLOCK_LENGTH];
    SHA512_CTX ctx;

    memset(buf, 0, SHA512_BLOCK_LENGTH);
    if (keylen > SHA512_BLOCK_LENGTH) {
        sha512_Raw(key, keylen, buf);
    } else {
        memcpy(buf, key, keylen);
    }

    for (i = 0; i < SHA512_BLOCK_LENGTH; i++) {
        o_key_pad[i] = buf[i] ^ 0x5c;
        i_key_pad[i] = buf[i] ^ 0x36;
    }

    sha512_Init(&ctx);
    sha512_Update(&ctx, i_key_pad, SHA512_BLOCK_LENGTH);
    sha512_Update(&ctx, msg, msglen);
    sha512_Final(buf, &ctx);

    sha512_Init(&ctx);
    sha512_Update(&ctx, o_key_pad, SHA512_BLOCK_LENGTH);
    sha512_Update(&ctx, buf, SHA512_DIGEST_LENGTH);
    sha512_Final(hmac, &ctx);
}
