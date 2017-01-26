/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_hex, BU256_STRSZ
#include <bitc/core.h>                  // for bitc_block, etc
#include <bitc/cstr.h>                  // for cstring, cstr_free, etc
#include <bitc/json/cJSON.h>            // for cJSON, cJSON_GetObjectItem, etc
#include <bitc/key.h>                   // for bitc_key_static_shutdown
#include <bitc/mbr.h>                   // for fread_message
#include <bitc/message.h>               // for p2p_message, etc
#include <bitc/util.h>                  // for file_seq_open
#include "libtest.h"                    // for test_filename, read_json

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for bool, false, true
#include <stdio.h>                      // for fprintf, perror, stderr, etc
#include <stdlib.h>                     // for free, exit
#include <string.h>                     // for strcmp, memcmp, strncmp
#include <unistd.h>                     // for close

static void runtest(const char *json_base_fn, const char *ser_fn_base)
{
	char *json_fn = test_filename(json_base_fn);
	cJSON *meta = read_json(json_fn);
	assert((meta->type & 0xFF) == cJSON_Object);

	char *ser_fn = test_filename(ser_fn_base);
	int fd = file_seq_open(ser_fn);
	if (fd < 0) {
		perror(ser_fn);
		exit(1);
	}

	struct p2p_message msg = {};
	bool read_ok = false;
	bool rc = fread_message(fd, &msg, &read_ok);
	assert(rc);
	assert(read_ok);
	assert(!strncmp(msg.hdr.command, "block", 12));

	close(fd);

	const char *hashstr = cJSON_GetObjectItem(meta, "hash")->valuestring;
	assert(hashstr != NULL);

	unsigned int size =cJSON_GetObjectItem(meta, "size")->valueint;
	assert((24 + msg.hdr.data_len) == size);

	struct bitc_block block;
	bitc_block_init(&block);

	struct const_buffer buf = { msg.data, msg.hdr.data_len };

	rc = deser_bitc_block(&block, &buf);
	assert(rc);

	cstring *gs = cstr_new_sz(100000);
	ser_bitc_block(gs, &block);

	if (gs->len != msg.hdr.data_len) {
		fprintf(stderr, "gs->len %ld, msg.hdr.data_len %u\n",
			(long)gs->len, msg.hdr.data_len);
		assert(gs->len == msg.hdr.data_len);
	}
	assert(memcmp(gs->str, msg.data, msg.hdr.data_len) == 0);

	bitc_block_calc_sha256(&block);

	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &block.sha256);

	if (strcmp(hexstr, hashstr)) {
		fprintf(stderr, "block: wanted hash %s,\n       got    hash %s\n",
			hashstr, hexstr);
		assert(!strcmp(hexstr, hashstr));
	}

	rc = bitc_block_valid(&block);
	assert(rc);

	bitc_block_free(&block);
	cstr_free(gs, true);
	free(msg.data);
	free(json_fn);
	free(ser_fn);
	cJSON_Delete(meta);
}

int main (int argc, char *argv[])
{
	runtest("blk0.json", "blk0.ser");
	runtest("blk120383.json", "blk120383.ser");

	bitc_key_static_shutdown();
	return 0;
}
