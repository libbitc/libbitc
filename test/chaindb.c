/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for hex_bu256, bu256_copy, etc
#include <bitc/db/chaindb.h>            // for blkinfo, blkdb, blkdb_reorg, etc
#include <bitc/db/db.h>                 // for blockdb_init, etc
#include <bitc/core.h>                  // for bitc_block_calc_sha256, etc
#include <bitc/coredefs.h>              // for chain_info, chain_metadata, etc
#include <bitc/key.h>                   // for bitc_key_static_shutdown
#include <bitc/log.h>                   // for logging
#include <bitc/util.h>                  // for file_seq_open
#include "libtest.h"                    // for test_filename

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool
#include <stdlib.h>                     // for free, NULL
#include <unistd.h>                     // for close, read

static void add_header(struct chaindb *db, char *raw)
{
	struct const_buffer buf = { raw, 80 };

	struct blkinfo *bi = bi_new();
	assert(bi != NULL);

	assert(deser_bitc_block(&bi->hdr, &buf) == true);

	bitc_block_calc_sha256(&bi->hdr);

	bu256_copy(&bi->hash, &bi->hdr.sha256);

	struct chaindb_reorg reorg;

	assert(chaindb_add(db, bi, &reorg) == true);

	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);
}

static void read_headers(const char *ser_base_fn, struct chaindb *db)
{
	char *filename = test_filename(ser_base_fn);
	int fd = file_seq_open(filename);
	assert(fd >= 0);

	char hdrbuf[80];

	while (read(fd, hdrbuf, 80) == 80) {
		add_header(db, hdrbuf);
	}

	close(fd);
	free(filename);
}

static void test_blkinfo_prev(struct chaindb *db)
{
	struct blkinfo *tmp = db->best_chain;
	int height = db->best_chain->height;

	while (tmp) {
		assert(height == tmp->height);

		height--;
		tmp = tmp->prev;
	}

	assert(height == -1);
}

static void runtest(const char *ser_base_fn, const struct chain_info *chain,
		    unsigned int check_height, const char *check_hash)
{
	struct chaindb db;

	bu256_t block0;
	bool rc = hex_bu256(&block0, chain->genesis_hash);
	assert(rc);

	rc = chaindb_init(&db, chain->netmagic, &block0);
	assert(rc);

	read_headers(ser_base_fn, &db);

	assert(db.best_chain->height == check_height);

	bu256_t best_block;
	rc = hex_bu256(&best_block, check_hash);

	assert(bu256_equal(&db.best_chain->hash, &best_block));

	test_blkinfo_prev(&db);

	chaindb_free(&db);
}

int main (int argc, char *argv[])
{
	log_state = calloc(0, sizeof(struct logging));

	log_state->stream = stderr;
	log_state->logtofile = false;
	log_state->debug = true;

	assert(metadb_init(chain_metadata[CHAIN_BITCOIN].netmagic, (const bu256_t *)chain_metadata[CHAIN_BITCOIN].genesis_hash));
	assert(blockdb_init());
	assert(blockheightdb_init());
	runtest("data/hdr50000.ser", &chain_metadata[CHAIN_BITCOIN], 50000,
	    "000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a");

	assert(metadb_init(chain_metadata[CHAIN_TESTNET3].netmagic, (const bu256_t *)chain_metadata[CHAIN_TESTNET3].genesis_hash));
	assert(blockdb_init());
	assert(blockheightdb_init());
	runtest("data/tn_hdr25000.ser", &chain_metadata[CHAIN_TESTNET3], 25000,
	    "0000000022b23de294af24d922fb3f1ed21521a8b3bd7716861dcb5310b1b525");

	bitc_key_static_shutdown();
	free(log_state);
	return 0;
}
