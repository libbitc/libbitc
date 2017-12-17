#ifndef __LIBBITC_PRIMITIVES_TRANSACTION_H__
#define __LIBBITC_PRIMITIVES_TRANSACTION_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buint.h>                 // for bu256_t, bu256_equal, etc
#include <bitc/core.h>                  // for bitc_valid_value
#include <bitc/cstr.h>                  // for cstring
#include <bitc/hashtab.h>               // for bitc_hashtab_get, etc
#include <bitc/parr.h>                  // for parr, parr_idx

#include <stdbool.h>                    // for bool, false, true
#include <stdint.h>                     // for uint32_t, int64_t
#include <string.h>                     // for memcpy

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
	SEQUENCE_FINAL = 0xffffffff,

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, bitc_txin::nSequence is NOT interpreted as a
     * relative lock-time. */
	SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31),

    /* If bitc_txin::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
	SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22),

    /* If bitc_txin::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
	SEQUENCE_LOCKTIME_MASK = 0x0000ffff,
};

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


#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_PRIMITIVES_TRANSACTION_H__ */
