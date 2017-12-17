/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"             // for PACKAGE_VERSION

#include <bitc/addr_match.h>            // for bitc_tx_match
#include <bitc/base58.h>                // for base58_decode_check, etc
#include <bitc/buffer.h>                // for const_buffer, buffer_copy, etc
#include <bitc/coredefs.h>
#include <bitc/crypto/ripemd160.h>      // for RIPEMD160_DIGEST_LENGTH
#include <bitc/hashtab.h>               // for bitc_hashtab_put, etc
#include <bitc/key.h>                   // for bitc_keyset, etc
#include <bitc/mbr.h>                   // for fread_block
#include <bitc/message.h>               // for p2p_message, etc
#include <bitc/script/script.h>         // for bscript_addr, etc
#include <bitc/util.h>                  // for VALSTR_SZ, btc_decimal, etc

#include <argp.h>                       // for error_t, argp_parse, etc
#include <ctype.h>                      // for isspace
#include <stdbool.h>                    // for bool, false, true
#include <stdint.h>                     // for uint64_t
#include <stdio.h>                      // for fprintf, printf, perror, etc
#include <stdlib.h>                     // for exit, free, malloc
#include <string.h>                     // for strlen, strerror
#include <unistd.h>                     // for lseek, off_t, close


const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "addresses", 'a', "FILE", 0,
	  "Load bitcoin addresses from text FILE.  Default filename \"blocks.dat\"." },
	{ "blocks", 'b', "FILE", 0,
	  "Load blockchain data from mkbootstrap-produced FILE.  Default filename \"addresses.txt\"." },

	{ "no-decimal", 'N', NULL, 0,
	  "Print values as integers (satoshis), not decimal numbers" },

	{ "quiet", 'q', NULL, 0,
	  "Silence informational messages" },

	{ }
};

static const char doc[] =
"blkscan - command line interface to scan blocks";

static char *blocks_fn = "blocks.dat";
static char *address_fn = "addresses.txt";
static bool opt_quiet = false;
static bool opt_decimal = true;

static struct bitc_keyset bitc_ks;
static struct bitc_hashtab *tx_idx = NULL;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 'a':
		address_fn = arg;
		break;
	case 'b':
		blocks_fn = arg;
		break;
	case 'N':
		opt_decimal = false;
		break;
	case 'q':
		opt_quiet = true;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void load_address(unsigned int line_no, const char *line)
{
	unsigned char addrtype;
	cstring *s = base58_decode_check(&addrtype, line);

	if (!s || addrtype != PUBKEY_ADDRESS) {
		fprintf(stderr, "Invalid address on line %d: %s\n", line_no, line);
		exit(1);
	}

	if (s->len != RIPEMD160_DIGEST_LENGTH) {
		fprintf(stderr, "Invalid decoded address length %u on line %d: %s\n",
			(unsigned int) s->len, line_no, line);
		exit(1);
	}

	struct buffer *buf_pkhash = buffer_copy(s->str,RIPEMD160_DIGEST_LENGTH);
	bitc_hashtab_put(bitc_ks.pubhash, buf_pkhash, buf_pkhash);

	cstr_free(s, true);
}

static void load_addresses(void)
{
	char line[512];

	FILE *f = fopen(address_fn, "r");
	if (!f) {
		perror(address_fn);
		exit(1);
	}

	unsigned int line_no = 0;

	while (fgets(line, sizeof(line), f) != NULL) {
		line_no++;

		/* trim trailing whitespace */
		while (line[0] && isspace(line[strlen(line) - 1]))
			line[strlen(line) - 1] = 0;

		/* skip blanks and comments */
		if (line[0] == '#' || line[0] == 0)
			continue;

		load_address(line_no, line);
	}

	fclose(f);

	if (!opt_quiet)
		fprintf(stderr, "%d addresses loaded\n",
			bitc_hashtab_size(bitc_ks.pubhash));
}

/* file pos -> block lookup */
static bool reload_block(int fd, uint64_t fpos, struct bitc_block *block)
{
	off_t save_ofs = lseek(fd, 0, SEEK_CUR);
	if (save_ofs == (off_t)-1) {
		perror("lseek 1");
		return false;
	}

	if (lseek(fd, (off_t) fpos, SEEK_SET) != (off_t) fpos) {
		perror("lseek 2");
		return false;
	}

	struct p2p_message msg = {};
	bool read_ok = false;

	if (!fread_block(fd, &msg, &read_ok)) {
		fprintf(stderr, "reload_block fread_block fail\n");
		goto err_out;
	}

	struct const_buffer buf = { msg.data, msg.hdr.data_len };

	bool rc = deser_bitc_block(block, &buf);
	if (!rc) {
		fprintf(stderr, "reload_block deser_block fail\n");
		goto err_out;
	}

	if (lseek(fd, save_ofs, SEEK_SET) != save_ofs)
		perror("lseek restore true");
	free(msg.data);
	return true;

err_out:
	if (lseek(fd, save_ofs, SEEK_SET) != save_ofs)
		perror("lseek restore false");
	free(msg.data);
	return false;
}

/* search for tx_hash within given block; return full tx */
static bool tx_from_block(struct bitc_tx *dest, bu256_t *tx_hash,
			  const struct bitc_block *block)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bitc_tx *tx;

		tx = parr_idx(block->vtx, n);

		bitc_tx_calc_sha256(tx);

		if (bu256_equal(&tx->sha256, tx_hash)) {
			bitc_tx_copy(dest, tx);
			return true;
		}
	}

	return false;
}

static bool tx_from_fpos(struct bitc_tx *dest, bu256_t *tx_hash,
			 int fd, uint64_t fpos)
{
	struct bitc_block block;
	bool rc = false;

	bitc_block_init(&block);

	if (!reload_block(fd, fpos, &block))
		goto out;

	if (!tx_from_block(dest, tx_hash, &block))
		goto out;

	rc = true;

out:
	bitc_block_free(&block);
	return rc;
}

static int block_fd = -1;

static void print_txout(bool show_from, unsigned int i, struct bitc_txout *txout)
{
	char valstr[VALSTR_SZ];
	if (opt_decimal)
		btc_decimal(valstr, VALSTR_SZ, txout->nValue);
	else
		snprintf(valstr, sizeof(valstr), "%lld",
			 (long long) txout->nValue);

	printf("\t%s %u: %s",
		show_from ? "\tFrom" : "Output",
		i, valstr);

	struct bscript_addr addrs;
	if (!bsp_addr_parse(&addrs, txout->scriptPubKey->str,
			    txout->scriptPubKey->len)) {
		printf(" UNPARSEABLE-ADDRESS!\n");
		return;
	}

	if (addrs.pub)
		printf(" SOME-PUBKEYS!");

	struct const_buffer *buf;
	clist *tmp = addrs.pubhash;
	bool is_mine;
	while (tmp) {
		buf = tmp->data;
		tmp = tmp->next;

		is_mine = bitc_keyset_lookup(&bitc_ks, buf->p, buf->len, true);

		cstring *addr = base58_encode_check(PUBKEY_ADDRESS, true,
						    buf->p, buf->len);
		if (!addr) {
			printf(" ENCODE-FAILED!\n");
			goto out;
		}

		printf(" %s%s%s",
		       is_mine ? "*" : "",
		       addr->str,
		       is_mine ? "*" : "");

		cstr_free(addr, true);
	}

	printf("\n");

out:
        clist_free_ext(addrs.pub, buffer_freep);
        clist_free_ext(addrs.pubhash, buffer_freep);
}

static void print_txouts(struct bitc_tx *tx, int idx)
{
	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bitc_txout *txout;

		txout = parr_idx(tx->vout, i);

		if (idx < 0)
			print_txout(false, i, txout);
		else if (idx == i)
			print_txout(true, i, txout);
	}
}

static void print_txin(unsigned int i, struct bitc_txin *txin)
{
	char hexstr[BU256_STRSZ];

	bu256_hex(hexstr, &txin->prevout.hash);

	printf("\tInput %u: %s %u\n",
		i, hexstr, txin->prevout.n);

	uint64_t *fpos_p = bitc_hashtab_get(tx_idx, &txin->prevout.hash);
	if (!fpos_p) {
		printf("\t\tINPUT NOT FOUND!\n");
		return;
	}

	struct bitc_tx tx;
	bitc_tx_init(&tx);

	if (!tx_from_fpos(&tx, &txin->prevout.hash, block_fd, *fpos_p)) {
		printf("\t\tINPUT NOT READ!\n");
		goto out;
	}

	print_txouts(&tx, txin->prevout.n);

out:
	bitc_tx_free(&tx);
}

static void print_txins(struct bitc_tx *tx)
{
	unsigned int i;
	for (i = 0; i < tx->vin->len; i++) {
		struct bitc_txin *txin;

		txin = parr_idx(tx->vin, i);

		print_txin(i, txin);
	}
}

static void index_block(unsigned int height, struct bitc_block *block,
			uint64_t fpos)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bitc_tx *tx;
		uint64_t *fpos_copy;

		tx = parr_idx(block->vtx, n);

		bitc_tx_calc_sha256(tx);

		bu256_t *hash = bu256_new(&tx->sha256);

		fpos_copy = malloc(sizeof(fpos));
		if (fpos_copy)
			*fpos_copy = fpos;

		bitc_hashtab_put(tx_idx, hash, fpos_copy);
	}
}

static unsigned int tx_matches = 0;

static void scan_block(unsigned int height, struct bitc_block *block)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bitc_tx *tx;

		tx = parr_idx(block->vtx, n);

		if (bitc_tx_match(tx, &bitc_ks)) {
			char hashstr[BU256_STRSZ];
			bitc_tx_calc_sha256(tx);
			bu256_hex(hashstr, &tx->sha256);

			printf("%u, %s\n",
			       block->nTime,
			       hashstr);

			print_txins(tx);
			print_txouts(tx, -1);

			tx_matches++;
		}
	}
}

static void scan_decode_block(unsigned int height, struct p2p_message *msg,
			      uint64_t *fpos)
{
	struct bitc_block block;
	bitc_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };

	bool rc = deser_bitc_block(&block, &buf);
	if (!rc) {
		fprintf(stderr, "block deser failed at height %u\n", height);
		exit(1);
	}

	index_block(height, &block, *fpos);
	scan_block(height, &block);

	uint64_t pos_tmp = msg->hdr.data_len;
	*fpos += (pos_tmp + 8);

	bitc_block_free(&block);
}

static void scan_blocks(void)
{
	int fd = file_seq_open(blocks_fn);
	if (fd < 0) {
		perror(blocks_fn);
		exit(1);
	}

	struct p2p_message msg = {};
	bool read_ok = false;

	unsigned int height = 0;
	uint64_t fpos = 0;

	block_fd = fd;

	while (fread_block(fd, &msg, &read_ok)) {
		scan_decode_block(height, &msg, &fpos);
		height++;

		if ((height % 10000 == 0) && (!opt_quiet))
			fprintf(stderr, "Scanned %u transactions at height %u\n",
				bitc_hashtab_size(tx_idx),
				height);
	}

	block_fd = -1;

	if (!read_ok) {
		fprintf(stderr, "block read %s failed\n", blocks_fn);
		exit(1);
	}

	close(fd);
	free(msg.data);

	if (!opt_quiet) {
		fprintf(stderr, "Scanned to height %u\n", height);
		fprintf(stderr, "TX matches: %u\n", tx_matches);
	}
}

int main (int argc, char *argv[])
{
	error_t aprc;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	bitc_keyset_init(&bitc_ks);

	tx_idx = bitc_hashtab_new_ext(bu256_hash, bu256_equal_,
				    bu256_freep, free);

	load_addresses();
	scan_blocks();

	return 0;
}


