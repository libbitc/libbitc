/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <stdlib.h>
#include <string.h>
#include <bitc/crypto/ripemd160.h>
#include <bitc/key.h>
#include <bitc/buffer.h>
#include <bitc/util.h>

void bitc_keyset_init(struct bitc_keyset *ks)
{
	memset(ks, 0, sizeof(*ks));

	ks->pub = bitc_hashtab_new_ext(buffer_hash, buffer_equal,
				     (bitc_freefunc) buffer_free, NULL);
	ks->pubhash = bitc_hashtab_new_ext(buffer_hash, buffer_equal,
					 (bitc_freefunc) buffer_free, NULL);
}

bool bitc_keyset_add(struct bitc_keyset *ks, struct bitc_key *key)
{
	void *pubkey = NULL;
	size_t pk_len = 0;

	if (!bitc_pubkey_get(key, &pubkey, &pk_len))
		return false;

	struct buffer *buf_pk = malloc(sizeof(struct buffer));
	buf_pk->p = pubkey;
	buf_pk->len = pk_len;

	unsigned char md160[RIPEMD160_DIGEST_LENGTH];
	bu_Hash160(md160, pubkey, pk_len);

	struct buffer *buf_pkhash = buffer_copy(md160, RIPEMD160_DIGEST_LENGTH);

	bitc_hashtab_put(ks->pub, buf_pk, buf_pk);
	bitc_hashtab_put(ks->pubhash, buf_pkhash, buf_pkhash);

	return true;
}

bool bitc_keyset_lookup(const struct bitc_keyset *ks, const void *data, size_t data_len,
		 bool is_pubkeyhash)
{
	struct const_buffer buf = { data, data_len };
	struct bitc_hashtab *ht;

	if (is_pubkeyhash)
		ht = ks->pubhash;
	else
		ht = ks->pub;

	return bitc_hashtab_get_ext(ht, &buf, NULL, NULL);
}

void bitc_keyset_free(struct bitc_keyset *ks)
{
	bitc_hashtab_unref(ks->pub);
	bitc_hashtab_unref(ks->pubhash);
}

