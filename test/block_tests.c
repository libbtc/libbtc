/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/block.h>

#include <logdb/cstr.h>
#include <btc/ecc_key.h>
#include <logdb/utils.h>

struct blockheadertest {
    char hexheader[160];
    char hexhash[64];
    int32_t version;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};

static const struct blockheadertest block_header_tests[] =
        {
                {"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", 1, 1231006505, 486604799, 2083236893},
                {"04000000db716ecedcc0eabee8f8a333aeaca8d020c10b7d6c851baf1f97442d68397d6e376353ed67b819ae38f8e821a8f3bc51f28e57973e11ceff0191353a07b68285fac6ca56ffff7f2002000000", "0eba32fd89d25ff24ae4eb9c9f7dccd5032cbbaa5fedfd06c9d5b75e5edb7f2f", 4, 1456129786, 545259519, 2}
        };

void test_block_header()
{
    int outlen;
    char hexbuf[161];
    unsigned int i;
    for (i = 0; i < (sizeof(block_header_tests) / sizeof(block_header_tests[0])); i++) {
        cstring* serialized = cstr_new_sz(80);
        const struct blockheadertest* test = &block_header_tests[i];
        uint8_t header_data[80];
        uint8_t hash_data[32];

        utils_hex_to_bin(test->hexheader, header_data, 160, &outlen);
        utils_hex_to_bin(test->hexhash, hash_data, 32, &outlen);

        btc_block_header* header = btc_block_header_new();
        btc_block_header_deserialize(header_data, 80, header);

        // Check the copies are the same
        btc_block_header* header_copy = btc_block_header_new();
        btc_block_header_copy(header_copy, header);
        assert(memcmp(header_copy, header, sizeof(*header_copy)) == 0);

        // Check the serialized form matches
        btc_block_header_serialize(serialized, header);
        utils_bin_to_hex((unsigned char*) serialized->str, serialized->len, hexbuf);
        assert(memcmp(hexbuf, test->hexheader, 160) == 0);

        // Check the block hash
        uint8_t blockhash[32];
        btc_block_header_hash(header, blockhash);

        utils_bin_to_hex(blockhash, 32, hexbuf);
        utils_reverse_hex(hexbuf, 64);
        assert(memcmp(hexbuf, test->hexhash, 64) == 0);

        // Check version, ts, bits, nonce
        assert(header->version == test->version);
        assert(header->timestamp == test->timestamp);
        assert(header->bits == test->bits);
        assert(header->nonce == test->nonce);

        btc_block_header_free(header);
        btc_block_header_free(header_copy);
        cstr_free(serialized, true);
    }
}
