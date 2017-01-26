/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include "wallet.h"
#include "bitsy.h"                      // for cur_wallet, chain, setting

#include <bitc/address.h>               // for bitc_pubkey_get_address
#include <bitc/base58.h>                // for base58_encode
#include <bitc/buffer.h>                // for const_buffer
#include <bitc/coredefs.h>              // for chain_info
#include <bitc/crypto/aes_util.h>       // for read_aes_file, etc
#include <bitc/crypto/prng.h>           // for prng_get_random_bytes
#include <bitc/hdkeys.h>                // for hd_extended_key_free, etc
#include <bitc/hexcode.h>               // for encode_hex
#include <bitc/json/cJSON.h>            // for cJSON_CreateString, cJSON, etc
#include <bitc/key.h>                   // for bitc_privkey_get, etc
#include <bitc/wallet/wallet.h>         // for wallet, wallet_free, etc
#include <bitc/compat.h>                // for parr_new

#include <assert.h>                     // for assert
#include <fcntl.h>                      // for open
#include <stdio.h>                      // for fprintf, printf, stderr, etc
#include <stdlib.h>                     // for free, calloc, getenv
#include <string.h>                     // for strlen, memset
#include <stdbool.h>                    // for true, bool, false
#include <unistd.h>                     // for access, close, read, F_OK

struct hd_extended_key_serialized {
	uint8_t data[78 + 1];	// 78 + NUL (the latter not written)
};

static bool write_ek_ser_prv(struct hd_extended_key_serialized *out,
			     const struct hd_extended_key *ek)
{
	cstring s = { (char *)(out->data), 0, sizeof(out->data) };
	return hd_extended_key_ser_priv(ek, &s);
}

static char *wallet_filename(void)
{
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
	return filename;
}

static struct wallet *load_wallet(void)
{
	char *passphrase = getenv("BITSY_PASSPHRASE");
	if (!passphrase) {
		fprintf(stderr, "missing BITSY_PASSPHRASE\n");
		return NULL;
	}

	char *filename = wallet_filename();
	if (!filename) {
		fprintf(stderr, "wallet: no filename\n");
		return NULL;
	}

	cstring *data = read_aes_file(filename, passphrase, strlen(passphrase),
				      100 * 1024 * 1024);
	if (!data) {
		fprintf(stderr, "wallet: missing or invalid\n");
		return NULL;
	}

	struct wallet *wlt = calloc(1, sizeof(*wlt));
	if (!wlt) {
		fprintf(stderr, "wallet: failed to allocate wallet\n");
		cstr_free(data, true);
		return NULL;
	}

	if (!wallet_init(wlt, chain)) {
		free(wlt);
		cstr_free(data, true);
		return NULL;
	}

	struct const_buffer buf = { data->str, data->len };

	if (!deser_wallet(wlt, &buf)) {
		fprintf(stderr, "wallet: deserialization failed\n");
		goto err_out;
	}

	if (chain != wlt->chain) {
		fprintf(stderr, "wallet root: foreign chain detected, aborting load.  Try 'chain-set' first.\n");
		goto err_out;
	}

	return wlt;

err_out:
	fprintf(stderr, "wallet: invalid data found\n");
	wallet_free(wlt);
	cstr_free(data, true);
	return NULL;
}

static bool store_wallet(struct wallet *wlt)
{
	char *passphrase = getenv("BITSY_PASSPHRASE");
	if (!passphrase) {
		fprintf(stderr, "wallet: Missing BITSY_PASSPHRASE for AES crypto\n");
		return false;
	}

	char *filename = wallet_filename();
	if (!filename)
		return false;

	cstring *plaintext = ser_wallet(wlt);
	if (!plaintext)
		return false;

	bool rc = write_aes_file(filename, passphrase, strlen(passphrase),
				 plaintext->str, plaintext->len);

	memset(plaintext->str, 0, plaintext->len);
	cstr_free(plaintext, true);

	return rc;
}

static bool cur_wallet_load(void)
{
	if (!cur_wallet)
		cur_wallet = load_wallet();
	if (!cur_wallet) {
		fprintf(stderr, "wallet: no wallet loaded\n");
		return false;
	}

	return true;
}

void cur_wallet_new_address(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	cstring *btc_addr;

	btc_addr = wallet_new_address(wlt);

	store_wallet(wlt);

	printf("%s\n", btc_addr->str);

	cstr_free(btc_addr, true);
}

void cur_wallet_free(void)
{
	if (!cur_wallet)
		return;

	wallet_free(cur_wallet);
	cur_wallet = NULL;
}

static void cur_wallet_update(struct wallet *wlt)
{
	if (!cur_wallet) {
		cur_wallet = wlt;
		return;
	}
	if (cur_wallet == wlt)
		return;

	cur_wallet_free();
	cur_wallet = wlt;
}

void cur_wallet_create(void)
{
	char *filename = wallet_filename();
	if (!filename) {
		fprintf(stderr, "wallet: no filename\n");
		return;
	}

	if (access(filename, F_OK) == 0) {
		fprintf(stderr, "wallet: already exists, aborting\n");
		return;
	}

	char seed[256];
	if (prng_get_random_bytes((unsigned char *) &seed[0], sizeof(seed)) < 0) {
		fprintf(stderr, "wallet: no random data available\n");
		return;
	}

	char seed_str[(sizeof(seed) * 2) + 1];
	encode_hex(seed_str, seed, sizeof(seed));
	printf("Record this HD seed (it will only be shown once):\n"
	       "%s\n", seed_str);

	struct wallet *wlt = calloc(1, sizeof(*wlt));

	if (!wlt) {
		fprintf(stderr, "wallet: failed to allocate wallet\n");
		return;
	}

	if (!wallet_init(wlt, chain)) {
		fprintf(stderr, "wallet: failed to initialize wallet\n");
		free(wlt);
		return;
	}

	cur_wallet_update(wlt);

	if (!wallet_create(wlt, seed, sizeof(seed))) {
		fprintf(stderr, "wallet: failed to create new wallet\n");
		free(wlt);
		return;
	}

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store %s\n", filename);
		wallet_free(wlt);
		free(wlt);
		return;
	}
}

void cur_wallet_addresses(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	struct bitc_key *key;
	unsigned int i;

	printf("[\n");

	wallet_for_each_key_numbered(wlt, key, i) {
		cstring *btc_addr;

		btc_addr = bitc_pubkey_get_address(key, chain->addr_pubkey);

		printf("  \"%s\"%s\n",
		       btc_addr->str,
		       i == (wlt->keys->len - 1) ? "" : ",");

		cstr_free(btc_addr, true);
	}

	printf("]\n");
}

void cur_wallet_info(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	printf("{\n");

	printf("\t\"version\":\t%u,\n", wlt->version);
	printf("\t\"n_privkeys\":\t%zu,\n", wlt->keys ? wlt->keys->len : 0);
	printf("\t\"n_hd_extkeys\":\t%zu,\n", wlt->hdmaster ? wlt->hdmaster->len : 0);
	printf("\t\"netmagic\":\t%02x%02x%02x%02x\n",
	       wlt->chain->netmagic[0],
	       wlt->chain->netmagic[1],
	       wlt->chain->netmagic[2],
	       wlt->chain->netmagic[3]);

	printf("}\n");
}

static void wallet_dump_keys(cJSON *keys_a, struct wallet *wlt)
{
	struct bitc_key *key;
	cJSON *o = NULL;

	wallet_for_each_key(wlt, key) {

		cJSON_AddItemToArray(keys_a, o = cJSON_CreateObject());

		void *privkey = NULL;
		size_t priv_len = 0;
		if (bitc_privkey_get(key, &privkey, &priv_len)) {
			cstring *privkey_str = str2hex(privkey, priv_len);
			cJSON_AddStringToObject(o, "privkey", privkey_str->str);
			cstr_free(privkey_str, true);
			free(privkey);
			privkey = NULL;
		}

		void *pubkey = NULL;
		size_t pub_len = 0;
		if (!bitc_pubkey_get(key, &pubkey, &pub_len)) {
			cJSON_Delete(o);
			continue;
		}

		if (pubkey) {
			cstring *pubkey_str = str2hex(pubkey, pub_len);
			cJSON_AddStringToObject(o, "pubkey", pubkey_str->str);
			cstr_free(pubkey_str, true);

			cstring *btc_addr = bitc_pubkey_get_address(key, chain->addr_pubkey);
			cJSON_AddStringToObject(o, "address", btc_addr->str);

			cstr_free(btc_addr, true);

			free(pubkey);
		}
	}
}

static void wallet_dump_hdkeys(cJSON *hdkeys_a, struct wallet *wlt)
{
	struct hd_extended_key *hdkey;
	cJSON *o = NULL;

	wallet_for_each_mkey(wlt, hdkey) {
		cJSON_AddItemToArray(hdkeys_a, o = cJSON_CreateObject());

		struct hd_extended_key_serialized hdraw;
		bool rc = write_ek_ser_prv(&hdraw, hdkey);
		assert(rc == true);

		cstring *hdstr = base58_encode(hdraw.data, sizeof(hdraw.data)-1);
		assert(hdstr != NULL);

		cJSON_AddStringToObject(o, "address", hdstr->str);

		cstr_free(hdstr, true);
	}
}

static void wallet_dump_accounts(cJSON *accounts, struct wallet *wlt)
{
	struct wallet_account *acct;
	cJSON *o = NULL;
	unsigned int i;

	for (i = 0; i < wlt->accounts->len; i++) {
		acct = parr_idx(wlt->accounts, i);

		cJSON_AddItemToArray(accounts, o = cJSON_CreateObject());

		cJSON_AddStringToObject(o, "name", acct->name->str);
		cJSON_AddNumberToObject(o, "acct_idx", acct->acct_idx);
		cJSON_AddNumberToObject(o, "next_key_idx", acct->next_key_idx);
	}
}

void cur_wallet_dump(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	cJSON *o = cJSON_CreateObject();

	cJSON_AddNumberToObject(o, "version", wlt->version);
	cJSON_AddStringToObject(o, "def_acct", wlt->def_acct->str);

	char nmstr[32];
	sprintf(nmstr, "%02x%02x%02x%02x",
	       wlt->chain->netmagic[0],
	       wlt->chain->netmagic[1],
	       wlt->chain->netmagic[2],
	       wlt->chain->netmagic[3]);

	cJSON_AddStringToObject(o, "netmagic", nmstr);

	cJSON *keys_a = cJSON_CreateArray();
	wallet_dump_keys(keys_a, wlt);
	cJSON_AddItemToObject(o, "keys", keys_a);

	cJSON *hdkeys_a = cJSON_CreateArray();
	wallet_dump_hdkeys(hdkeys_a, wlt);
	cJSON_AddItemToObject(o, "hdmaster", hdkeys_a);

	cJSON *accounts = cJSON_CreateArray();
	wallet_dump_accounts(accounts, wlt);
	cJSON_AddItemToObject(o, "accounts", accounts);

	fprintf(stdout, "%s", cJSON_Print(o));

	cJSON_Delete(o);

	printf("\n");
}

void cur_wallet_createAccount(const char *acct_name)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	if (!wallet_createAccount(wlt, acct_name)) {
		fprintf(stderr, "wallet: creation of account %s failed\n", acct_name);
		return;
	}

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store\n");
		return;
	}
}

void cur_wallet_defaultAccount(const char *acct_name)
{
	if (!wallet_valid_name(acct_name)) {
		fprintf(stderr, "Invalid account name %s\n", acct_name);
		return;
	}

	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	struct wallet_account *acct = account_byname(wlt, acct_name);
	if (!acct) {
		fprintf(stderr, "wallet: unknown account %s\n", acct_name);
		return;
	}

	cstr_free(wlt->def_acct, true);
	wlt->def_acct = cstr_new(acct_name);

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store\n");
		return;
	}
}

