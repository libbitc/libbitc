#ifndef __LIBBITC_KEY_H__
#define __LIBBITC_KEY_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>

#include <secp256k1.h>

#include <bitc/buint.h>
#include <bitc/hashtab.h>
#include <bitc/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bitc_key {
	uint8_t 		secret[32];
	secp256k1_pubkey	pubkey;
};

/// Frees any internally allocated static data.
extern void bitc_key_static_shutdown();

extern void bitc_key_init(struct bitc_key *key);
extern void bitc_key_free(struct bitc_key *key);
extern bool bitc_key_generate(struct bitc_key *key);
extern bool bitc_privkey_set(struct bitc_key *key, const void *privkey, size_t pk_len);
extern bool bitc_pubkey_set(struct bitc_key *key, const void *pubkey, size_t pk_len);
extern bool bitc_key_secret_set(struct bitc_key *key, const void *privkey_, size_t pk_len);
extern bool bitc_privkey_get(const struct bitc_key *key, void **privkey, size_t *pk_len);
extern bool bitc_pubkey_get(const struct bitc_key *key, void **pubkey, size_t *pk_len);
extern bool bitc_key_secret_get(void *p, size_t len, const struct bitc_key *key);
extern bool bitc_sign(const struct bitc_key *key, const void *data, size_t data_len,
	     void **sig_, size_t *sig_len_);
extern bool bitc_verify(const struct bitc_key *key, const void *data, size_t data_len,
	       const void *sig, size_t sig_len);
extern bool bitc_key_add_secret(struct bitc_key *out,
			      const struct bitc_key *key,
			      const uint8_t *tweak32);


bool pubkey_checklowS(const void *sig, size_t sig_len);

struct bitc_keyset {
	struct bitc_hashtab	*pub;
	struct bitc_hashtab	*pubhash;
};

extern void bitc_keyset_init(struct bitc_keyset *ks);
extern bool bitc_keyset_add(struct bitc_keyset *ks, struct bitc_key *key);
extern bool bitc_keyset_lookup(const struct bitc_keyset *ks, const void *data, size_t data_len,
		 bool is_pubkeyhash);
extern void bitc_keyset_free(struct bitc_keyset *ks);

struct bitc_keystore {
	struct bitc_hashtab	*keys;
};

extern void bkeys_init(struct bitc_keystore *ks);
extern void bkeys_free(struct bitc_keystore *ks);
extern bool bkeys_add(struct bitc_keystore *ks, struct bitc_key *key);
extern bool bkeys_key_get(struct bitc_keystore *ks, const bu160_t *key_id,
		      struct bitc_key *key);
extern bool bkeys_pubkey_append(struct bitc_keystore *ks, const bu160_t *key_id,
			cstring *scriptSig);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_KEY_H__ */
