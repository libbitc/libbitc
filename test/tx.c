/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_equal, bu256_hex, etc
#include <bitc/core.h>                  // for bitc_tx, etc
#include <bitc/cstr.h>                  // for cstring, cstr_free, etc
#include <bitc/json/cJSON.h>            // for cJSON, cJSON_GetObjectItem, etc
#include <bitc/key.h>                   // for bitc_key_static_shutdown
#include <bitc/parr.h>                  // for parr
#include <bitc/util.h>                  // for bu_read_file
#include "libtest.h"                    // for test_filename

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool
#include <stddef.h>                     // for size_t
#include <stdio.h>                      // for fprintf, NULL, stderr
#include <stdlib.h>                     // for free
#include <string.h>                     // for strcmp, memcmp

static void runtest(const char *json_base_fn, const char *ser_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	cJSON *meta = read_json(json_fn);
	assert(meta != NULL);
	assert((meta->type & 0xFF) == cJSON_Object);

	char *ser_fn = test_filename(ser_base_fn);

	void *data = NULL;
	size_t data_len = 0;

	bool rc = bu_read_file(ser_fn, &data, &data_len, 100 * 1024 * 1024);
	assert(rc);

	const char *hashstr = cJSON_GetObjectItem(meta, "hash")->valuestring;
	assert(hashstr != NULL);

	unsigned int size = cJSON_GetObjectItem(meta, "size")->valueint;
	assert(data_len == size);

	struct bitc_tx tx;
	bitc_tx_init(&tx);

	struct const_buffer buf = { data, data_len };

	rc = deser_bitc_tx(&tx, &buf);
	assert(rc);

	cstring *gs = cstr_new_sz(10000);
	ser_bitc_tx(gs, &tx);

	if (gs->len != data_len) {
		fprintf(stderr, "gs->len %ld, data_len %lu\n",
			(long)gs->len, data_len);
		assert(gs->len == data_len);
	}
	assert(memcmp(gs->str, data, data_len) == 0);

	bitc_tx_calc_sha256(&tx);

	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &tx.sha256);

	if (strcmp(hexstr, hashstr)) {
		fprintf(stderr, "tx: wanted hash %s,\n    got    hash %s\n",
			hashstr, hexstr);
		assert(!strcmp(hexstr, hashstr));
	}

	assert(tx.vin->len == 1);
	assert(tx.vout->len == 2);

	struct bitc_tx tx_copy;
	bitc_tx_init(&tx_copy);

	bitc_tx_copy(&tx_copy, &tx);
	bitc_tx_calc_sha256(&tx_copy);
	assert(bu256_equal(&tx_copy.sha256, &tx.sha256) == true);

	bitc_tx_free(&tx);
	bitc_tx_free(&tx_copy);
	cstr_free(gs, true);
	free(data);
	free(json_fn);
	free(ser_fn);
	cJSON_Delete(meta);
}

int main (int argc, char *argv[])
{
	runtest("data/tx3e0dc3da.json", "data/tx3e0dc3da.ser");

	bitc_key_static_shutdown();
	return 0;
}
