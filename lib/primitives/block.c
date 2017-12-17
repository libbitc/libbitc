/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_t, bu256_new, etc
#include <bitc/core.h>                  // for bitc_valid_value
#include <bitc/coredefs.h>              // for ::MAX_BLOCK_WEIGHT, etc
#include <bitc/cstr.h>                  // for cstring, cstr_free, etc
#include <bitc/parr.h>                  // for parr, parr_idx, parr_add, etc
#include <bitc/primitives/block.h>      // for bitc_block
#include <bitc/primitives/transaction.h>  // for bitc_tx, bitc_txin, etc
#include <bitc/serialize.h>             // for deser_u32, ser_u32, etc
#include <bitc/util.h>                  // for bu_Hash_, MIN, bu_Hash

#include <gmp.h>                        // for mpz_clear, mpz_init, mpz_t, etc

#include <stdbool.h>                    // for false, true, bool
#include <stdint.h>                     // for int64_t, uint32_t
#include <stdlib.h>                     // for free, calloc
#include <string.h>                     // for memset, NULL
#include <time.h>                       // for time, time_t



void bitc_block_init(struct bitc_block *block)
{
	memset(block, 0, sizeof(*block));
}

bool deser_bitc_block(struct bitc_block *block, struct const_buffer *buf)
{
	bitc_block_free(block);

	if (!deser_u32(&block->nVersion, buf)) return false;
	if (!deser_u256(&block->hashPrevBlock, buf)) return false;
	if (!deser_u256(&block->hashMerkleRoot, buf)) return false;
	if (!deser_u32(&block->nTime, buf)) return false;
	if (!deser_u32(&block->nBits, buf)) return false;
	if (!deser_u32(&block->nNonce, buf)) return false;

	/* permit header-only blocks */
	if (buf->len == 0)
		return true;

	block->vtx = parr_new(512, bitc_tx_freep);

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bitc_tx *tx;

		tx = calloc(1, sizeof(*tx));
		bitc_tx_init(tx);
		if (!deser_bitc_tx(tx, buf)) {
			free(tx);
			goto err_out;
		}

		parr_add(block->vtx, tx);
	}

	return true;

err_out:
	bitc_block_free(block);
	return false;
}

static void ser_bitc_block_hdr(cstring *s, const struct bitc_block *block)
{
	ser_u32(s, block->nVersion);
	ser_u256(s, &block->hashPrevBlock);
	ser_u256(s, &block->hashMerkleRoot);
	ser_u32(s, block->nTime);
	ser_u32(s, block->nBits);
	ser_u32(s, block->nNonce);
}

void ser_bitc_block(cstring *s, const struct bitc_block *block)
{
	ser_bitc_block_hdr(s, block);

	unsigned int i;
	if (block->vtx) {
		ser_varlen(s, block->vtx->len);

		for (i = 0; i < block->vtx->len; i++) {
			struct bitc_tx *tx;

			tx = parr_idx(block->vtx, i);
			ser_bitc_tx(s, tx);
		}
	}
}
void bitc_block_vtx_free(struct bitc_block *block)
{
	if (!block || !block->vtx)
		return;

	parr_free(block->vtx, true);
	block->vtx = NULL;
}

void bitc_block_free(struct bitc_block *block)
{
	if (!block)
		return;

	bitc_block_vtx_free(block);
}

void bitc_block_freep(void *p)
{
	struct bitc_block *block = p;
	if (!block)
		return;

	bitc_block_free(block);

	memset(block, 0, sizeof(*block));
	free(block);
}

void bitc_block_free_cb(void *data)
{
	if (!data)
		return;

	struct bitc_block *block = data;
	bitc_block_free(block);

	memset(block, 0, sizeof(*block));
	free(block);
}

void bitc_block_calc_sha256(struct bitc_block *block)
{
	if (block->sha256_valid)
		return;

	/* TODO: introduce hashing-only serialization mode */

	cstring *s = cstr_new_sz(10 * 1024);
	ser_bitc_block_hdr(s, block);

	bu_Hash((unsigned char *)&block->sha256, s->str, s->len);
	block->sha256_valid = true;

	cstr_free(s, true);
}

unsigned int bitc_block_ser_size(const struct bitc_block *block)
{
	unsigned int block_ser_size;

	/* TODO: introduce a counting-only serialization mode */

	cstring *s = cstr_new_sz(200 * 1024);
	ser_bitc_block(s, block);

	block_ser_size = s->len;

	cstr_free(s, true);

	return block_ser_size;
}

parr *bitc_block_merkle_tree(const struct bitc_block *block)
{
	if (!block->vtx || !block->vtx->len)
		return NULL;

	parr *arr = parr_new(0, bu256_freep);

	unsigned int i;
	for (i = 0; i < block->vtx->len; i++) {
		struct bitc_tx *tx;

		tx = parr_idx(block->vtx, i);
		bitc_tx_calc_sha256(tx);

		parr_add(arr, bu256_new(&tx->sha256));
	}

	unsigned int j = 0, nSize;
	for (nSize = block->vtx->len; nSize > 1; nSize = (nSize + 1) / 2) {
		for (i = 0; i < nSize; i += 2) {
			unsigned int i2 = MIN(i+1, nSize-1);
			bu256_t hash;
			bu_Hash_((unsigned char *) &hash,
			   parr_idx(arr, j+i), sizeof(bu256_t),
			   parr_idx(arr, j+i2),sizeof(bu256_t));

			parr_add(arr, bu256_new(&hash));
		}

		j += nSize;
	}

	return arr;
}

void bitc_block_merkle(bu256_t *vo, const struct bitc_block *block)
{
	memset(vo, 0, sizeof(*vo));

	if (!block->vtx || !block->vtx->len)
		return;

	parr *arr = bitc_block_merkle_tree(block);
	if (!arr)
		return;

	bu256_copy(vo, parr_idx(arr, arr->len - 1));

	parr_free(arr, true);
}

parr *bitc_block_merkle_branch(const struct bitc_block *block,
			       const parr *mrktree,
			       unsigned int txidx)
{
	if (!block || !block->vtx || !mrktree || (txidx >= block->vtx->len))
		return NULL;

	parr *ret = parr_new(0, bu256_freep);

	unsigned int j = 0, nSize;
	for (nSize = block->vtx->len; nSize > 1; nSize = (nSize + 1) / 2) {
		unsigned int i = MIN(txidx ^ 1, nSize - 1);
		parr_add(ret, bu256_new(parr_idx(mrktree, j+i)));
		txidx >>= 1;
		j += nSize;
	}

	return ret;
}

void bitc_check_merkle_branch(bu256_t *hash, const bu256_t *txhash_in,
			    const parr *mrkbranch, unsigned int txidx)
{
	bu256_copy(hash, txhash_in);

	unsigned int i;
	for (i = 0; i < mrkbranch->len; i++) {
		const bu256_t *otherside = parr_idx(mrkbranch, i);
		if (txidx & 1)
			bu_Hash_((unsigned char *)hash,
				 otherside, sizeof(bu256_t),
				 hash, sizeof(bu256_t));
		else
			bu_Hash_((unsigned char *)hash,
				 hash, sizeof(bu256_t),
				 otherside, sizeof(bu256_t));

		txidx >>= 1;
	}
}

static bool bitc_block_valid_target(struct bitc_block *block)
{
	mpz_t target, sha256;
	mpz_init(target);
	mpz_init(sha256);

	u256_from_compact(target, block->nBits);
	bu256_bn(sha256, &block->sha256);

	int cmp = mpz_cmp(sha256, target);

	mpz_clear(target);
	mpz_clear(sha256);

	if (cmp > 0)			/* sha256 > target */
		return false;

	return true;
}

static bool bitc_block_valid_merkle(struct bitc_block *block)
{
	bu256_t merkle;

	bitc_block_merkle(&merkle, block);

	return bu256_equal(&merkle, &block->hashMerkleRoot);
}

bool bitc_block_valid(struct bitc_block *block)
{
	bitc_block_calc_sha256(block);

	if (!block->vtx || !block->vtx->len)
		return false;

	if (block->vtx->len * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
		return false;

	if (bitc_block_ser_size(block) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
		return false;

	if (!bitc_block_valid_target(block)) return false;

	time_t now = time(NULL);
	if (block->nTime > (now + (2 * 60 * 60)))
		return false;

	if (!bitc_block_valid_merkle(block)) return false;

	unsigned int i;
	for (i = 0; i < block->vtx->len; i++) {
		struct bitc_tx *tx;

		tx = parr_idx(block->vtx, i);
		if (!bitc_tx_valid(tx))
			return false;

		bool is_coinbase_idx = (i == 0);
		bool is_coinbase = bitc_tx_coinbase(tx);

		if (is_coinbase != is_coinbase_idx)
			return false;
	}

	return true;
}

