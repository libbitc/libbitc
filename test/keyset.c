/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <assert.h>                     // for assert
#include <string.h>                     // for NULL, memset

#include <bitc/crypto/ripemd160.h>     // for RIPEMD160_DIGEST_LENGTH
#include <bitc/crypto/sha2.h>          // for sha256_Raw
#include <bitc/key.h>                  // for bpks_lookup, bp_key, etc
#include <bitc/util.h>                 // for ARRAY_SIZE, bu_Hash160
#include "libtest.h"

static void keytest_secp256k1()
{
	secp256k1_context *secp_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN
	);

	{
		uint8_t test_private_key[32];
		memset(test_private_key, 0, sizeof(test_private_key));
		assert(!secp256k1_ec_seckey_verify(secp_ctx, test_private_key));

		test_private_key[31] = 0x1;
		assert(secp256k1_ec_seckey_verify(secp_ctx, test_private_key));
	}

	secp256k1_context_destroy(secp_ctx);
}

static void keytest()
{
	{
		struct bitc_key k;
		bitc_key_init(&k);
		bitc_key_free(&k);
	}

	// Signature

	{
		const uint8_t test_secret[32] = { 0x1 };
		const uint8_t test_data[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
		bu256_t hash;
		sha256_Raw(test_data, sizeof(test_data), (uint8_t *)&hash);

		void *pub = NULL;
		size_t publen = 0;
		void *sig = NULL;
		size_t siglen = 0;

		struct bitc_key k;
		bitc_key_init(&k);
		assert(bitc_key_secret_set(&k, test_secret, sizeof(test_secret)));
		assert(bitc_pubkey_get(&k, &pub, &publen));
		assert(NULL != pub);
		assert(0 != publen);

		assert(bitc_sign(&k, (uint8_t *)&hash, sizeof(hash), &sig, &siglen));
		assert(NULL != sig);
		assert(0 != siglen);
		bitc_key_free(&k);

		struct bitc_key pubk;
		bitc_key_init(&k);
		assert(bitc_pubkey_set(&pubk, pub, publen));
		assert(bitc_verify(&pubk, (uint8_t *)&hash, sizeof(hash), sig, siglen));

		bitc_key_free(&k);
		free(pub);
		free(sig);
	}
}

static void runtest(void)
{
	unsigned int i;
	struct bitc_key keys[4];

	/* generate keys */
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		struct bitc_key *key = &keys[i];
		bitc_key_init(key);
		assert(bitc_key_generate(key) == true);
	}

	struct bitc_keyset ks;

	bitc_keyset_init(&ks);

	/* add all but one to keyset */
	for (i = 0; i < (ARRAY_SIZE(keys) - 1); i++)
		assert(bitc_keyset_add(&ks, &keys[i]) == true);

	/* verify all-but-one are in keyset */
	for (i = 0; i < (ARRAY_SIZE(keys) - 1); i++) {
		unsigned char md160[RIPEMD160_DIGEST_LENGTH];
		void *pubkey;
		size_t pklen;

		assert(bitc_pubkey_get(&keys[i], &pubkey, &pklen) == true);

		bu_Hash160(md160, pubkey, pklen);

		assert(bitc_keyset_lookup(&ks, pubkey, pklen, true) == false);
		assert(bitc_keyset_lookup(&ks, pubkey, pklen, false) == true);

		assert(bitc_keyset_lookup(&ks, md160, sizeof(md160), true) == true);
		assert(bitc_keyset_lookup(&ks, md160, sizeof(md160), false) == false);

		free(pubkey);
	}

	/* verify last key not in keyset */
	{
		unsigned char md160[RIPEMD160_DIGEST_LENGTH];
		void *pubkey;
		size_t pklen;

		struct bitc_key *key = &keys[ARRAY_SIZE(keys) - 1];
		assert(bitc_pubkey_get(key, &pubkey, &pklen) == true);

		bu_Hash160(md160, pubkey, pklen);

		assert(bitc_keyset_lookup(&ks, pubkey, pklen, true) == false);
		assert(bitc_keyset_lookup(&ks, pubkey, pklen, false) == false);

		assert(bitc_keyset_lookup(&ks, md160, sizeof(md160), true) == false);
		assert(bitc_keyset_lookup(&ks, md160, sizeof(md160), false) == false);

		free(pubkey);
	}

	bitc_keyset_free(&ks);

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		struct bitc_key *key = &keys[i];
		bitc_key_free(key);
	}
}

int main (int argc, char *argv[])
{
	keytest_secp256k1();
	keytest();
	runtest();

	bitc_key_static_shutdown();
	return 0;
}
