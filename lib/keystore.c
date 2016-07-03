/* Copyright 2012 exMULTI, Inc.
 * Copyright (c) 2009-2012 The Bitcoin developers
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/key.h>
#include <bitc/util.h>
#include <bitc/script.h>

static void bitc_key_free__(void *data)
{
	struct bitc_key *key = data;

	if (!key)
		return;

	bitc_key_free(key);
	free(key);
}

void bkeys_init(struct bitc_keystore *ks)
{
	memset(ks, 0, sizeof(*ks));

	ks->keys = bitc_hashtab_new_ext(bu160_hash, bu160_equal_,
				      free, bitc_key_free__);
}

void bkeys_free(struct bitc_keystore *ks)
{
	if (!ks || !ks->keys)
		return;

	bitc_hashtab_unref(ks->keys);
	ks->keys = NULL;
}

bool bkeys_add(struct bitc_keystore *ks, struct bitc_key *key)
{
	bu160_t *hash;

	void *pubkey = NULL;
	size_t pk_len = 0;

	if (!bitc_pubkey_get(key, &pubkey, &pk_len))
		return false;

	hash = malloc(sizeof(*hash));
	bu_Hash160((unsigned char *)hash, pubkey, pk_len);
	free(pubkey);

	bitc_hashtab_put(ks->keys, hash, key);

	return true;
}

bool bkeys_key_get(struct bitc_keystore *ks, const bu160_t *key_id,
		   struct bitc_key *key_out)
{
	struct bitc_key *tmp = bitc_hashtab_get(ks->keys, key_id);
	if (!tmp)
		return false;

	memcpy(key_out, tmp, sizeof(*tmp));
	return true;
}

bool bkeys_pubkey_append(struct bitc_keystore *ks, const bu160_t *key_id,
			 cstring *scriptSig)
{
	struct bitc_key key;
	bitc_key_init(&key);

	if (!bkeys_key_get(ks, key_id, &key))
		return false;

	void *pubkey = NULL;
	size_t pk_len = 0;

	if (!bitc_pubkey_get(&key, &pubkey, &pk_len))
		return false;

	bsp_push_data(scriptSig, pubkey, pk_len);

	free(pubkey);

	/* no bitc_key_free(&key), as bkeys_key_get() returns a ref */
	return true;
}

