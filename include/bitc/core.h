#ifndef __LIBBITC_CORE_H__
#define __LIBBITC_CORE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_t, bu256_equal, etc
#include <bitc/coredefs.h>              // for ::COIN
#include <bitc/cstr.h>                  // for cstring
#include <bitc/hashtab.h>               // for bitc_hashtab_get, etc
#include <bitc/parr.h>                  // for parr, parr_idx

#include <stdbool.h>                    // for bool, false, true
#include <stdint.h>                     // for uint32_t, int64_t, uint16_t, etc
#include <string.h>                     // for memcpy, memset, NULL

#ifdef __cplusplus
extern "C" {
#endif

enum service_bits {
	NODE_NETWORK	= (1 << 0),
};

enum {
	SEQUENCE_FINAL = 0xffffffff,
	SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31),
	SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22),
	SEQUENCE_LOCKTIME_MASK = 0x0000ffff,
};

static inline bool bitc_valid_value(int64_t nValue)
{
	if (nValue < 0 || nValue > 21000000LL * COIN)
		return false;
	return true;
}

struct bitc_address {
	uint32_t	nTime;
	uint64_t	nServices;
	unsigned char	ip[16];
	uint16_t	port;
};

static inline void bitc_addr_init(struct bitc_address *addr)
{
	memset(addr, 0, sizeof(*addr));
}

extern bool deser_bitc_addr(unsigned int protover,
		struct bitc_address *addr, struct const_buffer *buf);
extern void ser_bitc_addr(cstring *s, unsigned int protover, const struct bitc_address *addr);
static inline void bitc_addr_free(struct bitc_address *addr) {}
extern void bitc_addr_freep(void *p);

static inline void bitc_addr_copy(struct bitc_address *dest,
				const struct bitc_address *src)
{
	memcpy(dest, src, sizeof(*dest));
}

struct bitc_inv {
	uint32_t	type;
	bu256_t		hash;
};

extern void bitc_inv_init(struct bitc_inv *inv);
extern bool deser_bitc_inv(struct bitc_inv *inv, struct const_buffer *buf);
extern void ser_bitc_inv(cstring *s, const struct bitc_inv *inv);
static inline void bitc_inv_free(struct bitc_inv *inv) {}
extern void bitc_inv_freep(void *bitc_inv_p);

struct bitc_locator {
	uint32_t	nVersion;
	parr        *vHave;        /* of bu256_t */
};

static inline void bitc_locator_init(struct bitc_locator *locator)
{
	memset(locator, 0, sizeof(*locator));
}

extern bool deser_bitc_locator(struct bitc_locator *locator, struct const_buffer *buf);
extern void ser_bitc_locator(cstring *s, const struct bitc_locator *locator);
extern void bitc_locator_free(struct bitc_locator *locator);
extern void bitc_locator_push(struct bitc_locator *locator, const bu256_t *hash_in);

struct bitc_outpt {
	bu256_t		hash;
	uint32_t	n;
};

extern void bitc_outpt_init(struct bitc_outpt *outpt);
extern bool deser_bitc_outpt(struct bitc_outpt *outpt, struct const_buffer *buf);
extern void ser_bitc_outpt(cstring *s, const struct bitc_outpt *outpt);
static inline void bitc_outpt_free(struct bitc_outpt *outpt) {}

static inline bool bitc_outpt_null(const struct bitc_outpt *outpt)
{
	return bu256_is_zero(&outpt->hash) && outpt->n == 0xffffffff;
}

static inline bool bitc_outpt_equal(const struct bitc_outpt *a,
				  const struct bitc_outpt *b)
{
	return (a->n == b->n) && bu256_equal(&a->hash, &b->hash);
}

static inline void bitc_outpt_copy(struct bitc_outpt *dest,
				 const struct bitc_outpt *src)
{
	memcpy(dest, src, sizeof(*dest));
}

struct bitc_txin {
        struct bitc_outpt	prevout;
        parr*       scriptWitness;
        cstring     *scriptSig;
        uint32_t    nSequence;
};

extern void bitc_txin_init(struct bitc_txin *txin);
extern bool deser_bitc_txin(struct bitc_txin *txin, struct const_buffer *buf);
extern void ser_bitc_txin(cstring *s, const struct bitc_txin *txin);
extern void bitc_txin_free(struct bitc_txin *txin);
extern void bitc_txin_freep(void *data);
static inline bool bitc_txin_valid(const struct bitc_txin *txin) { return true; }
extern void bitc_txin_copy(struct bitc_txin *dest, const struct bitc_txin *src);

struct bitc_txout {
	int64_t		nValue;
	cstring		*scriptPubKey;
};

extern void bitc_txout_init(struct bitc_txout *txout);
extern bool deser_bitc_txout(struct bitc_txout *txout, struct const_buffer *buf);
extern void ser_bitc_txout(cstring *s, const struct bitc_txout *txout);
extern void bitc_txout_free(struct bitc_txout *txout);
extern void bitc_txout_freep(void *data);
extern void bitc_txout_set_null(struct bitc_txout *txout);
extern void bitc_txout_copy(struct bitc_txout *dest, const struct bitc_txout *src);

static inline bool bitc_txout_valid(const struct bitc_txout *txout)
{
	if (!txout || !txout->scriptPubKey)
		return false;
	if (!bitc_valid_value(txout->nValue))
		return false;
	return true;
}

struct bitc_tx {
	/* serialized */
	uint32_t	nVersion;
	parr	*vin;			/* of bitc_txin */
	parr	*vout;			/* of bitc_txout */
	uint32_t	nLockTime;

	/* used at runtime */
	bool		sha256_valid;
	bu256_t		sha256;
};

extern void bitc_tx_init(struct bitc_tx *tx);
extern bool deser_bitc_tx(struct bitc_tx *tx, struct const_buffer *buf);
extern void ser_bitc_tx(cstring *s, const struct bitc_tx *tx);
extern void bitc_tx_free_vout(struct bitc_tx *tx);
extern void bitc_tx_free(struct bitc_tx *tx);
extern void bitc_tx_freep(void *bitc_tx_p);
extern bool bitc_tx_valid(const struct bitc_tx *tx);
extern void bitc_tx_calc_sha256(struct bitc_tx *tx);
extern unsigned int bitc_tx_ser_size(const struct bitc_tx *tx);
extern void bitc_tx_copy(struct bitc_tx *dest, const struct bitc_tx *src);

static inline bool bitc_tx_coinbase(const struct bitc_tx *tx)
{
	if (!tx->vin || tx->vin->len != 1)
		return false;

	struct bitc_txin *txin = (struct bitc_txin *)parr_idx(tx->vin, 0);
	if (!bitc_outpt_null(&txin->prevout))
		return false;

	return true;
}

struct bitc_utxo {
	bu256_t		hash;

	bool		is_coinbase;
	uint32_t	height;

	uint32_t	version;
	parr	*vout;		/* of bitc_txout */
};

extern void bitc_utxo_init(struct bitc_utxo *coin);
extern void bitc_utxo_free(struct bitc_utxo *coin);
extern void bitc_utxo_freep(void *bitc_utxo_coin);
extern bool bitc_utxo_from_tx(struct bitc_utxo *coin, const struct bitc_tx *tx,
		     bool is_coinbase, unsigned int height);

struct bitc_utxo_set {
	struct bitc_hashtab	*map;
};

extern void bitc_utxo_set_init(struct bitc_utxo_set *uset);
extern void bitc_utxo_set_free(struct bitc_utxo_set *uset);
extern bool bitc_utxo_is_spent(struct bitc_utxo_set *uset, const struct bitc_outpt *outpt);
extern bool bitc_utxo_spend(struct bitc_utxo_set *uset, const struct bitc_outpt *outpt);

static inline void bitc_utxo_set_add(struct bitc_utxo_set *uset,
				   struct bitc_utxo *coin)
{
	bitc_hashtab_put(uset->map, &coin->hash, coin);
}

static inline struct bitc_utxo *bitc_utxo_lookup(struct bitc_utxo_set *uset,
					     const bu256_t *hash)
{
	return (struct bitc_utxo *)bitc_hashtab_get(uset->map, hash);
}


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

#endif /* __LIBBITC_CORE_H__ */
