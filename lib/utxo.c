/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <string.h>
#include <bitc/core.h>
#include <bitc/compat.h>

void bitc_utxo_init(struct bitc_utxo *coin)
{
	memset(coin, 0, sizeof(*coin));
}

static void bitc_utxo_free_vout(struct bitc_utxo *coin)
{
	if (!coin || !coin->vout)
		return;

	parr_free(coin->vout, true);
	coin->vout = NULL;
}

void bitc_utxo_free(struct bitc_utxo *coin)
{
	if (!coin)
		return;

	bitc_utxo_free_vout(coin);
}

bool bitc_utxo_from_tx(struct bitc_utxo *coin, const struct bitc_tx *tx,
		     bool is_coinbase, unsigned int height)
{
	if (!tx || !coin || !tx->vout || !tx->sha256_valid)
		return false;

	bu256_copy(&coin->hash, &tx->sha256);
	coin->is_coinbase = is_coinbase;
	coin->height = height;
	coin->version = tx->nVersion;

	coin->vout = parr_new(tx->vout->len, bitc_txout_freep);
	unsigned int i;

	for (i = 0; i < tx->vout->len; i++) {
		struct bitc_txout *old_out, *new_out;

		old_out = parr_idx(tx->vout, i);
		new_out = malloc(sizeof(*new_out));
		bitc_txout_copy(new_out, old_out);
		parr_add(coin->vout, new_out);
	}

	return true;
}

static void utxo_free_ent(void *data_)
{
	struct bitc_utxo *coin = data_;
	if (!coin)
		return;

	bitc_utxo_free(coin);
	free(coin);
}

void bitc_utxo_set_init(struct bitc_utxo_set *uset)
{
	memset(uset, 0, sizeof(*uset));

	uset->map = bitc_hashtab_new_ext(bu256_hash, bu256_equal_,
				       NULL, utxo_free_ent);
}

void bitc_utxo_set_free(struct bitc_utxo_set *uset)
{
	if (!uset)
		return;

	if (uset->map) {
		bitc_hashtab_unref(uset->map);
		uset->map = NULL;
	}
}

bool bitc_utxo_is_spent(struct bitc_utxo_set *uset, const struct bitc_outpt *outpt)
{
	struct bitc_utxo *coin = bitc_utxo_lookup(uset, &outpt->hash);
	if (!coin || !coin->vout || !coin->vout->len ||
	    (outpt->n >= coin->vout->len))
		return true;

	struct bitc_txout *txout = parr_idx(coin->vout, outpt->n);
	if (!txout)
		return true;

	return false;
}

static bool bitc_utxo_null(const struct bitc_utxo *coin)
{
	if (!coin || !coin->vout || !coin->vout->len)
		return true;

	unsigned int i;
	for (i = 0; i < coin->vout->len; i++) {
		struct bitc_txout *txout;

		txout = parr_idx(coin->vout, i);
		if (txout)
			return false;
	}

	return true;
}

bool bitc_utxo_spend(struct bitc_utxo_set *uset, const struct bitc_outpt *outpt)
{
	struct bitc_utxo *coin = bitc_utxo_lookup(uset, &outpt->hash);
	if (!coin || !coin->vout || !coin->vout->len ||
	    (outpt->n >= coin->vout->len))
		return false;

	/* find txout, given index */
	struct bitc_txout *txout = parr_idx(coin->vout, outpt->n);
	if (!txout)
		return false;

	/* free txout, replace with NULL marker indicating spent-ness */
	coin->vout->data[outpt->n] = NULL;
	bitc_txout_free(txout);
	free(txout);

	/* if coin entirely spent, free it */
	if (bitc_utxo_null(coin))
		bitc_hashtab_del(uset->map, &coin->hash);

	return true;
}

