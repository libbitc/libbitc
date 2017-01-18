#ifndef __LIBBITC_CHAINDB_H__
#define __LIBBITC_CHAINDB_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buint.h>                 // for bu256_t
#include <bitc/core.h>                  // for bitc_block
#include <bitc/hashtab.h>               // for bitc_hashtab_get

#include <stdbool.h>                    // for bool
#include <stdint.h>                     // for int32_t, int64_t

#ifdef __cplusplus
extern "C" {
#endif

struct blkinfo;

struct blkinfo {
	bu256_t		hash;
	struct bitc_block	hdr;

	mpz_t		work;
	int		height;

	struct blkinfo	*prev;
};

struct chaindb_reorg {
	struct blkinfo	*old_best;	/* previous best_chain */
	unsigned int	conn;		/* # blocks connected (normally 1) */
	unsigned int	disconn;	/* # blocks disconnected (normally 0) */
};

struct chaindb {
	bu256_t		block0;

	struct bitc_hashtab *blocks;

	struct blkinfo	*best_chain;
};

extern struct blkinfo *bi_new(void);
extern void bi_free(struct blkinfo *bi);

extern bool chaindb_init(struct chaindb *db, const unsigned char *netmagic,
		       const bu256_t *genesis_block);
extern void chaindb_free(struct chaindb *db);
extern bool chaindb_read(struct chaindb *db, const char *idx_fn);
extern bool chaindb_add(struct chaindb *db, struct blkinfo *bi,
		      struct chaindb_reorg *reorg_info);
extern void chaindb_locator(struct chaindb *db, struct blkinfo *bi,
		   struct bitc_locator *locator);

static inline struct blkinfo *chaindb_lookup(struct chaindb *db,const bu256_t *hash)
{
	return (struct blkinfo *)bitc_hashtab_get(db->blocks, hash);
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_CHAINDB_H__ */
