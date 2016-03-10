/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

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

#ifndef __LIBBTC_WALLET_H__
#define __LIBBTC_WALLET_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "logdb.h"
#include "bip32.h"
#include "tx.h"

#include <stdint.h>
#include <stddef.h>

/** single key/value record */
typedef struct btc_wallet {
    btc_log_db *db;
    btc_hdnode *masterkey;
    uint32_t next_childindex; //cached next child index
    const btc_chain* chain;
    uint32_t bestblockheight;
    vector *spends;
} btc_wallet;

typedef struct btc_wtx_ {
    uint32_t height;
    btc_tx *tx;
} btc_wtx;

LIBBTC_API btc_wallet* btc_wallet_new();
LIBBTC_API void btc_wallet_free(btc_wallet *wallet);

/** load the wallet, sets masterkey, sets next_childindex */
LIBBTC_API btc_bool btc_wallet_load(btc_wallet *wallet, const char *file_path, enum btc_logdb_error *error);

/** writes the wallet state to disk */
LIBBTC_API btc_bool btc_wallet_flush(btc_wallet *wallet);

/** set the master key of new created wallet
 consuming app needs to ensure that we don't override exiting masterkeys */
LIBBTC_API void btc_wallet_set_master_key_copy(btc_wallet *wallet, btc_hdnode *masterkey);

/** derives the next child hdnode (allocs, needs to be freed!) with the new key */
LIBBTC_API btc_hdnode* btc_wallet_next_key_new(btc_wallet *wallet);

/** writes all available addresses (P2PKH) to the addr_out vector */
LIBBTC_API void btc_wallet_get_addresses(btc_wallet *wallet, vector *addr_out);

/** searches after a hdnode by given P2PKH (base58(hash160)) address */
LIBBTC_API void btc_wallet_find_hdnode_byaddr(btc_wallet *wallet, const char *search_addr, btc_hdnode *node_out);

LIBBTC_API btc_wtx* btc_wallet_wtx_new();
LIBBTC_API void btc_wallet_wtx_free(btc_wtx* wtx);
LIBBTC_API btc_bool btc_wallet_wtx_deserialize(btc_wtx* wtx, struct const_buffer* buf);

/** adds transaction to the wallet */
LIBBTC_API btc_bool btc_wallet_add_wtx(btc_wallet *wallet, btc_wtx *wtx);

/** gets credit from given transaction */
LIBBTC_API int64_t btc_wallet_wtx_get_credit(btc_wallet *wallet, btc_wtx *wtx);

/** checks if a transaction outpoint is owned by the wallet */
LIBBTC_API btc_bool btc_wallet_txout_is_mine(btc_wallet *wallet, btc_tx_out *tx_out);

LIBBTC_API void btc_wallet_add_to_spent(btc_wallet *wallet, btc_wtx *wtx);
LIBBTC_API btc_bool btc_wallet_is_spent(btc_wallet *wallet, uint256 hash, uint32_t n);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_WALLET_H__
