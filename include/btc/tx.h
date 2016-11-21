/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


#ifndef __LIBBTC_TX_H__
#define __LIBBTC_TX_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include <btc/chainparams.h>
#include <btc/cstr.h>
#include <btc/hash.h>
#include <btc/script.h>
#include <btc/vector.h>


typedef struct btc_script_ {
    int* data;
    size_t limit;   // Total size of the vector
    size_t current; //Number of vectors in it at present
} btc_script;

typedef struct btc_tx_outpoint_ {
    uint256 hash;
    uint32_t n;
} btc_tx_outpoint;

typedef struct btc_tx_in_ {
    btc_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
} btc_tx_in;

typedef struct btc_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} btc_tx_out;

typedef struct btc_tx_ {
    int32_t version;
    vector* vin;
    vector* vout;
    uint32_t locktime;
} btc_tx;


//!create a new tx input
LIBBTC_API btc_tx_in* btc_tx_in_new();
LIBBTC_API void btc_tx_in_free(btc_tx_in* tx_in);
LIBBTC_API void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src);

//!create a new tx output
LIBBTC_API btc_tx_out* btc_tx_out_new();
LIBBTC_API void btc_tx_out_free(btc_tx_out* tx_out);
LIBBTC_API void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src);

//!create a new tx input
LIBBTC_API btc_tx* btc_tx_new();
LIBBTC_API void btc_tx_free(btc_tx* tx);
LIBBTC_API void btc_tx_copy(btc_tx* dest, const btc_tx* src);

//!deserialize/parse a p2p serialized bitcoin transaction
LIBBTC_API int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t *consumed_length);

//!serialize a lbc bitcoin data structure into a p2p serialized buffer
LIBBTC_API void btc_tx_serialize(cstring* s, const btc_tx* tx);

LIBBTC_API void btc_tx_hash(const btc_tx* tx, uint8_t* hashout);

LIBBTC_API btc_bool btc_tx_sighash(const btc_tx* tx_to, const cstring* fromPubKey, unsigned int in_num, int hashtype, uint8_t* hash);

LIBBTC_API btc_bool btc_tx_add_address_out(btc_tx* tx, const btc_chainparams* chain, int64_t amount, const char* address);
LIBBTC_API btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint8_t* hash160);
LIBBTC_API btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint8_t* hash160);
LIBBTC_API btc_bool btc_tx_add_p2pkh_out(btc_tx* tx, int64_t amount, const btc_pubkey* pubkey);

LIBBTC_API btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx);
LIBBTC_API btc_bool btc_tx_is_coinbase(btc_tx* tx);
#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_TX_H__
