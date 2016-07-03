/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/crypto/ripemd160.h>
#include <bitc/address.h>
#include <bitc/base58.h>
#include <bitc/util.h>
#include <bitc/cstr.h>

cstring *bitc_pubkey_get_address(const struct bitc_key *key, unsigned char addrtype)
{
	void *pubkey = NULL;
	size_t pk_len = 0;

	bitc_pubkey_get(key, &pubkey, &pk_len);

	unsigned char md160[RIPEMD160_DIGEST_LENGTH];

	bu_Hash160(md160, pubkey, pk_len);

	free(pubkey);

	cstring *btc_addr = base58_encode_check(addrtype, true,
						md160, sizeof(md160));

	return btc_addr;
}

cstring *bitc_privkey_get_address(const struct bitc_key *key, unsigned char addrtype)
{
	// secret (32 bytes), 0x01 (compressed)
	unsigned char priv [33];
	if (bitc_key_secret_get(&priv[0], 32, key))
	{
		priv[32] = 0x01;
		return base58_encode_check(addrtype, true, &priv[0], 33);
	}
	return NULL;
}
