#ifndef __LIBBITC_ADDR_MATCH_H__
#define __LIBBITC_ADDR_MATCH_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/parr.h>                    // for parr
#include <bitc/primitives/block.h>        // for bitc_block
#include <bitc/primitives/transaction.h>  // for bitc_tx, bitc_txout, etc

#include <gmp.h>                          // for mpz_t

#include <stdbool.h>                      // for bool


#ifdef __cplusplus
extern "C" {
#endif

struct bitc_txout;
struct bitc_keyset;
struct bitc_tx;
struct bitc_block;

extern bool bitc_txout_match(const struct bitc_txout *txout,
		    const struct bitc_keyset *ks);
extern bool bitc_tx_match(const struct bitc_tx *tx, const struct bitc_keyset *ks);
extern bool bitc_tx_match_mask(mpz_t mask, const struct bitc_tx *tx,
		      const struct bitc_keyset *ks);

struct bitc_block_match {
	unsigned int	n;		/* block.vtx array index */
	mpz_t		mask;		/* bitmask of matched txout's */
	bool		self_alloc;	/* alloc'd by bbm_new? */
};

extern void bbm_init(struct bitc_block_match *match);
extern struct bitc_block_match *bbm_new(void);
extern void bbm_free(void *bitc_block_match_match);

extern parr *bitc_block_match(const struct bitc_block *block,
			    const struct bitc_keyset *ks);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_ADDR_MATCH_H__ */
