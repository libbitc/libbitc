#ifndef __LIBBITC_PRIMITIVES_BLOCK_H__
#define __LIBBITC_PRIMITIVES_BLOCK_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_t
#include <bitc/coredefs.h>              // for ::COIN
#include <bitc/cstr.h>                  // for cstring
#include <bitc/parr.h>                  // for parr

#include <stdbool.h>                    // for bool
#include <stdint.h>                     // for uint32_t, int64_t
#include <string.h>                     // for memcpy, NULL

#ifdef __cplusplus
extern "C" {
#endif

struct bitc_block {
	/* serialized */
	uint32_t	nVersion;
	bu256_t		hashPrevBlock;
	bu256_t		hashMerkleRoot;
	uint32_t	nTime;
	uint32_t	nBits;
	uint32_t	nNonce;
	parr	*vtx;			/* of bitc_tx */

	/* used at runtime */
	bool		sha256_valid;
	bu256_t		sha256;
};

extern void bitc_block_init(struct bitc_block *block);
extern bool deser_bitc_block(struct bitc_block *block, struct const_buffer *buf);
extern void ser_bitc_block(cstring *s, const struct bitc_block *block);
extern void bitc_block_free(struct bitc_block *block);
extern void bitc_block_freep(void *bitc_block_p);
extern void bitc_block_vtx_free(struct bitc_block *block);
extern void bitc_block_calc_sha256(struct bitc_block *block);
extern void bitc_block_merkle(bu256_t *vo, const struct bitc_block *block);
extern parr *bitc_block_merkle_tree(const struct bitc_block *block);
extern parr *bitc_block_merkle_branch(const struct bitc_block *block,
			       const parr *mrktree,
			       unsigned int txidx);
extern void bitc_check_merkle_branch(bu256_t *hash, const bu256_t *txhash_in,
			    const parr *mrkbranch, unsigned int txidx);
extern bool bitc_block_valid(struct bitc_block *block);
extern unsigned int bitc_block_ser_size(const struct bitc_block *block);
extern void bitc_block_free_cb(void *data);

static inline void bitc_block_copy_hdr(struct bitc_block *dest,
				     const struct bitc_block *src)
{
	memcpy(dest, src, sizeof(*src));
	dest->vtx = NULL;
}

static inline int64_t bitc_block_value(unsigned int height, int64_t fees)
{
	int64_t subsidy = 50LL * COIN;
	subsidy >>= (height / 210000);
	return subsidy + fees;
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_PRIMITIVES_BLOCK_H__ */
