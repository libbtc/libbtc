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

#include "btc/wallet.h"
#include "btc/base58.h"
#include "serialize.h"

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define COINBASE_MATURITY 100

static const char *hdkey_key = "hdkey";
static const char *hdmasterkey_key = "mstkey";
static const char *tx_key = "tx";

btc_wallet* btc_wallet_new()
{
    btc_wallet* wallet;
    wallet = calloc(1, sizeof(*wallet));
    wallet->db = btc_logdb_new();
    wallet->masterkey = NULL;
    wallet->chain = &btc_chain_main;
    wallet->spends = vector_new(10, free);
    return wallet;
}

void btc_wallet_free(btc_wallet *wallet)
{
    if (!wallet)
        return;

    if (wallet->db)
    {
        btc_logdb_free(wallet->db);
        wallet->db = NULL;
    }

    if (wallet->spends)
    {
        vector_free(wallet->spends, true);
        wallet->spends = NULL;
    }

    if (wallet->masterkey)
        free(wallet->masterkey);

    free(wallet);
}

btc_bool btc_wallet_load(btc_wallet *wallet, const char *file_path, enum btc_logdb_error *error)
{
    if (!wallet)
        return false;

    if (!wallet->db)
        return false;

    if (wallet->db->file)
    {
        *error = LOGDB_ERROR_FILE_ALREADY_OPEN;
        return false;
    }

    struct stat buffer;
    btc_bool create = true;
    if (stat(file_path, &buffer) == 0)
        create = false;

    enum btc_logdb_error db_error = 0;
    if (!btc_logdb_load(wallet->db, file_path, create, &db_error))
    {
        *error = db_error;
        return false;
    }

    btc_logdb_record *rec = wallet->db->head;
    btc_bool child_cache_set = false;
    while (rec)
    {
        if (wallet->masterkey == NULL && rec->mode == RECORD_TYPE_WRITE && rec->key->len > strlen(hdmasterkey_key) && memcmp(rec->key->str, hdmasterkey_key, strlen(hdmasterkey_key)) == 0)
        {
            wallet->masterkey = btc_hdnode_new();
            btc_hdnode_deserialize(rec->value->str, wallet->chain, wallet->masterkey);
        }
        if (child_cache_set == false && rec->key->len > strlen(hdkey_key) && memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0)
        {
            btc_hdnode node;
            btc_hdnode_deserialize(rec->value->str, wallet->chain, &node);
            wallet->next_childindex = node.child_num+1;
            child_cache_set = true;
        }
        if (rec->key->len == strlen(tx_key)+SHA256_DIGEST_LENGTH && memcmp(rec->key->str, tx_key, strlen(tx_key)) == 0)
        {
            btc_wtx *wtx = btc_wallet_wtx_new();
            struct const_buffer buf = {rec->value->str, rec->value->len};
            btc_wallet_wtx_deserialize(wtx, &buf);
            btc_wallet_add_to_spent(wallet, wtx);
            btc_wallet_wtx_free(wtx);
        }
        rec = rec->prev;
    }

    return true;
}

btc_bool btc_wallet_flush(btc_wallet *wallet)
{
    return btc_logdb_flush(wallet->db);
}

void btc_wallet_set_master_key_copy(btc_wallet *wallet, btc_hdnode *masterkey)
{
    if (!masterkey)
        return;

    if (wallet->masterkey != NULL)
    {
        //changing the master key should not be done,...
        //anyways, we are going to accept that at this point
        //consuming application needs to take care about that
        btc_hdnode_free(wallet->masterkey);
        wallet->masterkey = NULL;
    }
    wallet->masterkey = btc_hdnode_copy(masterkey);

    //serialize and store node
    char str[128];
    btc_hdnode_serialize_private(wallet->masterkey, wallet->chain, str, sizeof(str));

    uint8_t key[strlen(hdmasterkey_key)+SHA256_DIGEST_LENGTH];
    memcpy(key, hdmasterkey_key, strlen(hdmasterkey_key));
    btc_hash(wallet->masterkey->public_key, BTC_ECKEY_COMPRESSED_LENGTH, key+strlen(hdmasterkey_key));

    struct buffer buf_key = {key, sizeof(key)};
    struct buffer buf_val = {str, strlen(str)};
    btc_logdb_append(wallet->db, &buf_key, &buf_val);
}

btc_hdnode* btc_wallet_next_key_new(btc_wallet *wallet)
{
    if (!wallet && !wallet->masterkey)
        return NULL;

    //for now, only m/k is possible
    btc_hdnode *node = btc_hdnode_copy(wallet->masterkey);
    btc_hdnode_private_ckd(node, wallet->next_childindex);

    //serialize and store node
    char str[128];
    btc_hdnode_serialize_public(node, wallet->chain, str, sizeof(str));

    uint8_t key[strlen(hdkey_key)+20];
    memcpy(key, hdkey_key, strlen(hdkey_key)); //set the key prefix for the kv store
    btc_hdnode_get_hash160(node, key+strlen(hdkey_key)); //append the hash160

    struct buffer buf_key = {key, sizeof(key)};
    struct buffer buf_val = {str, strlen(str)};
    btc_logdb_append(wallet->db, &buf_key, &buf_val);
    btc_logdb_flush(wallet->db);

    //increase the in-memory counter (cache)
    wallet->next_childindex++;

    return node;
}

void btc_wallet_get_addresses(btc_wallet *wallet, vector *addr_out)
{
    btc_logdb_record *rec = wallet->db->head;

    //keep a pointer to the keys already added
    vector *keys_added = vector_new(32, NULL);

    //move to the bottom of the records list
    while (rec->prev)
        rec = rec->prev;

    //TODO: avoid old/deleted records
    while (rec)
    {
        if (rec->mode == RECORD_TYPE_WRITE &&
            rec->key &&
            vector_find(keys_added, rec->key) == -1 && //<-- only if key was not already added to the vector
            rec->key->len > strlen(hdkey_key) &&
            memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0) //<-- only hdkey records
        {
            uint8_t hash160[21];
            hash160[0] = wallet->chain->b58prefix_pubkey_address;
            memcpy(hash160+1, rec->key->str+strlen(hdkey_key), 20);

            size_t addrsize = 98;
            char *addr = calloc(1, addrsize);
            btc_base58_encode_check(hash160, 21, addr, addrsize);
            vector_add(addr_out, addr);
            vector_add(keys_added, rec->key);
        }

        rec = rec->next;
    }

    vector_free(keys_added, true);
}

void btc_wallet_find_hdnode_byaddr(btc_wallet *wallet, const char *search_addr, btc_hdnode *node_out)
{
    if (!wallet || !search_addr)
        return;

    btc_logdb_record *rec = wallet->db->head;

    //move to the bottom of the records list
    while (rec->prev)
    {
        if (rec->mode == RECORD_TYPE_WRITE && rec->key && rec->key->len > strlen(hdkey_key))
        {
            //generate base58(hash160)
            uint8_t hash160[21];
            hash160[0] = wallet->chain->b58prefix_pubkey_address;
            memcpy(hash160+1, rec->key->str+strlen(hdkey_key), 20);

            size_t addrsize = 98;
            char addr[addrsize];
            btc_base58_encode_check(hash160, 21, addr, addrsize);
            if (strcmp(search_addr, addr) == 0)
            {
                //found, deserialize
                btc_hdnode_deserialize(rec->value->str, wallet->chain, node_out);
                return;
            }
        }
        rec = rec->prev;
    }

    //not found
    node_out = NULL;
}

btc_wtx* btc_wallet_wtx_new()
{
    btc_wtx* wtx;
    wtx = calloc(1, sizeof(*wtx));
    wtx->height = 0;
    wtx->tx = btc_tx_new();

    return wtx;
}

void btc_wallet_wtx_free(btc_wtx* wtx)
{
    btc_tx_free(wtx->tx);
    free(wtx);
}

void btc_wallet_wtx_serialize(cstring* s, const btc_wtx* wtx)
{
    ser_u32(s, wtx->height);
    btc_tx_serialize(s, wtx->tx);
}

btc_bool btc_wallet_wtx_deserialize(btc_wtx* wtx, struct const_buffer* buf)
{
    deser_u32(&wtx->height, buf);
    return btc_tx_deserialize(buf->p, buf->len, wtx->tx);
}

btc_bool btc_wallet_add_wtx(btc_wallet *wallet, btc_wtx *wtx)
{
    if (!wallet || !wtx)
        return false;

    cstring* txser = cstr_new_sz(1024);
    btc_wallet_wtx_serialize(txser, wtx);

    uint8_t key[strlen(tx_key)+SHA256_DIGEST_LENGTH];
    memcpy(key, tx_key, strlen(tx_key));
    btc_hash((const uint8_t*)txser->str, txser->len, key+strlen(tx_key));

    struct buffer buf_key = {key, sizeof(key)};
    struct buffer buf_val = {txser->str, txser->len};
    btc_logdb_append(wallet->db, &buf_key, &buf_val);

    //add to spends
    btc_wallet_add_to_spent(wallet, wtx);

    cstr_free(txser, true);

    return true;
}

btc_bool btc_wallet_have_key(btc_wallet *wallet, uint8_t *hash160)
{
    if (!wallet)
        return false;

    btc_logdb_record *rec = wallet->db->head;
    while (rec)
    {
        if (rec->mode == RECORD_TYPE_WRITE &&
            rec->key &&
            rec->key->len == strlen(hdkey_key)+20 &&
            memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0 &&
            memcmp(rec->key->str+strlen(hdkey_key), hash160, 20) == 0)
        {
            //key found
            return true;
        }
        rec = rec->prev;
    }
    return false;
}

int64_t btc_wallet_wtx_get_credit(btc_wallet *wallet, btc_wtx *wtx)
{
    int64_t credit = 0;

    if (btc_tx_is_coinbase(wtx->tx) &&
        ( wallet->bestblockheight < COINBASE_MATURITY || wtx->height > wallet->bestblockheight - COINBASE_MATURITY )
        )
        return credit;

    uint256 hash;
    btc_tx_hash(wtx->tx, hash);
    unsigned int i = 0;
    if (wtx->tx->vout) {
        for (i = 0; i < wtx->tx->vout->len; i++) {
            btc_tx_out* tx_out;
            tx_out = vector_idx(wtx->tx->vout, i);

            if (!btc_wallet_is_spent(wallet, hash, i))
            {
                if (btc_wallet_txout_is_mine(wallet, tx_out))
                    credit += tx_out->value;
            }
        }
    }
    return credit;
}

btc_bool btc_wallet_txout_is_mine(btc_wallet *wallet, btc_tx_out *tx_out)
{
    btc_bool ismine = false;

    vector *vec = vector_new(3, free);
    enum btc_tx_out_type type2 = btc_script_classify(tx_out->script_pubkey, vec);

    //TODO: Multisig, etc.
    if (type2 == BTC_TX_PUBKEYHASH)
    {
        //TODO: find a better format for vector elements (not a pure pointer)
        uint8_t *hash160 = vector_idx(vec, 0);
        if (btc_wallet_have_key(wallet, hash160))
            ismine = true;
    }

    vector_free(vec, true);

    return ismine;
}

void btc_wallet_add_to_spent(btc_wallet *wallet, btc_wtx *wtx)
{
    if (!wallet || !wtx)
        return;

    if (btc_tx_is_coinbase(wtx->tx))
        return;
    
    unsigned int i = 0;
    if (wtx->tx->vin) {
        for (i = 0; i < wtx->tx->vin->len; i++) {
            btc_tx_in* tx_in = vector_idx(wtx->tx->vin, i);

            //add to spends
            btc_tx_outpoint *outpoint = calloc(1, sizeof(btc_tx_outpoint));
            memcpy(outpoint, &tx_in->prevout, sizeof(btc_tx_outpoint));
            vector_add(wallet->spends, outpoint);
        }
    }
}

btc_bool btc_wallet_is_spent(btc_wallet *wallet, uint256 hash, uint32_t n)
{
    if (!wallet)
        return false;

    unsigned int i = 0;
    for (i = wallet->spends->len ; i > 0; i--)
    {
        btc_tx_outpoint *outpoint = vector_idx(wallet->spends, i-1);
        if (memcmp(outpoint->hash, hash, SHA256_DIGEST_LENGTH) == 0 && n == outpoint->n)
            return true;
    }
    return false;
}
