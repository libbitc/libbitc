/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/clist.h>                 // for clist, clist_append, etc
#include <bitc/cstr.h>                  // for cstring, cstr_equal, etc
#include <bitc/key.h>                   // for bitc_key_static_shutdown
#include <bitc/mbr.h>                   // for fread_message
#include <bitc/message.h>               // for p2p_message, etc
#include <bitc/primitives/block.h>      // for bitc_block
#include <bitc/script/script.h>         // for bscript_op, GetOpName, etc
#include <bitc/util.h>                  // for file_seq_open, memdup
#include <bitc/compat.h>                // for parr_new
#include "libtest.h"                    // for test_filename

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for bool, false, true
#include <stdio.h>                      // for perror
#include <stdlib.h>                     // for free, exit
#include <string.h>                     // for strcmp, strncmp, NULL
#include <unistd.h>                     // for close


static void test_txout(const struct bitc_txout *txout)
{
	struct const_buffer buf = { txout->scriptPubKey->str,
				    txout->scriptPubKey->len };

	struct bscript_parser bsp;
	struct bscript_op op;
	clist *ops = NULL;

	/*
	 * parse script
	 */

	bsp_start(&bsp, &buf);

	while (bsp_getop(&op, &bsp)) {
		struct bscript_op *op_p;

		op_p = memdup(&op, sizeof(op));
		ops = clist_append(ops, op_p);
	}

	assert(!bsp.error);

	/*
	 * build script
	 */

	clist *tmp = ops;
	cstring *s = cstr_new_sz(256);
	while (tmp) {
		struct bscript_op *op_p;

		op_p = tmp->data;
		tmp = tmp->next;

		if (is_bsp_pushdata(op_p->op)) {
			bsp_push_data(s, op_p->data.p, op_p->data.len);
		} else {
			bsp_push_op(s, op_p->op);
		}
	}

	clist_free_ext(ops, free);

	/* byte-compare original and newly created scripts */
	assert(cstr_equal(s, txout->scriptPubKey));

	cstr_free(s, true);
}

static void runtest(const char *ser_fn_base)
{
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

	struct bitc_block block;
	bitc_block_init(&block);

	struct const_buffer buf = { msg.data, msg.hdr.data_len };

	rc = deser_bitc_block(&block, &buf);
	assert(rc);

	unsigned int n_tx, n_out;
	for (n_tx = 0; n_tx < block.vtx->len; n_tx++) {
		struct bitc_tx *tx = parr_idx(block.vtx, n_tx);

		for (n_out = 0; n_out < tx->vout->len; n_out++) {
			struct bitc_txout *txout;

			txout = parr_idx(tx->vout, n_out);
			test_txout(txout);
		}
	}

	bitc_block_free(&block);
	free(msg.data);
	free(ser_fn);
}

int main (int argc, char *argv[])
{
	const char *opn = GetOpName(OP_PUBKEY);
	assert(!strcmp(opn, "OP_PUBKEY"));

	opn = GetOpName(OP_INVALIDOPCODE);
	assert(!strcmp(opn, "OP_UNKNOWN"));

	runtest("data/blk120383.ser");

	bitc_key_static_shutdown();
	return 0;
}
