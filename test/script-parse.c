/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <bitc/util.h>
#include <bitc/script.h>
#include <bitc/core.h>
#include <bitc/mbr.h>
#include <bitc/message.h>
#include <bitc/compat.h>
#include "libtest.h"

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
	assert(!strcmp(opn, "<unknown>"));

	runtest("blk120383.ser");

	bitc_key_static_shutdown();
	return 0;
}
