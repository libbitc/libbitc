/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/primitives/transaction.h>  // for bitc_tx, bitc_txin, etc
#include <bitc/serialize.h>             // for deser_u32, deser_varlen, etc
#include <bitc/util.h>                  // for bu_Hash

#include <string.h>                     // for memset, NULL


void bitc_outpt_init(struct bitc_outpt *outpt)
{
	memset(outpt, 0, sizeof(*outpt));
}

bool deser_bitc_outpt(struct bitc_outpt *outpt, struct const_buffer *buf)
{
	bitc_outpt_free(outpt);

	if (!deser_u256(&outpt->hash, buf)) return false;
	if (!deser_u32(&outpt->n, buf)) return false;
	return true;
}

void ser_bitc_outpt(cstring *s, const struct bitc_outpt *outpt)
{
	ser_u256(s, &outpt->hash);
	ser_u32(s, outpt->n);
}

void bitc_txin_init(struct bitc_txin *txin)
{
	memset(txin, 0, sizeof(*txin));
	bitc_outpt_init(&txin->prevout);
}

bool deser_bitc_txin(struct bitc_txin *txin, struct const_buffer *buf)
{
	bitc_txin_free(txin);

	if (!deser_bitc_outpt(&txin->prevout, buf)) return false;
	if (!deser_varstr(&txin->scriptSig, buf)) return false;
	if (!deser_u32(&txin->nSequence, buf)) return false;
	return true;
}

void ser_bitc_txin(cstring *s, const struct bitc_txin *txin)
{
	ser_bitc_outpt(s, &txin->prevout);
	ser_varstr(s, txin->scriptSig);
	ser_u32(s, txin->nSequence);
}

void bitc_txin_free(struct bitc_txin *txin)
{
	if (!txin)
		return;

	bitc_outpt_free(&txin->prevout);

	if (txin->scriptWitness) {
		parr_free(txin->scriptWitness, true);
		txin->scriptWitness = NULL;
	}

	if (txin->scriptSig) {
		cstr_free(txin->scriptSig, true);
		txin->scriptSig = NULL;
	}
}

void bitc_txin_freep(void *data)
{
	if (!data)
		return;

	struct bitc_txin *txin = data;
	bitc_txin_free(txin);

	memset(txin, 0, sizeof(*txin));
	free(txin);
}

void bitc_txin_copy(struct bitc_txin *dest, const struct bitc_txin *src)
{
	bitc_outpt_copy(&dest->prevout, &src->prevout);
	dest->nSequence = src->nSequence;

	if (!src->scriptWitness)
		dest->scriptWitness = NULL;
	else {
	    dest->scriptWitness = parr_new(src->scriptWitness->len, buffer_freep);
	    unsigned int i;
	    for (i = 0; i < src->scriptWitness->len; i++) {
	        struct buffer *witness_src = parr_idx(src->scriptWitness, i);
	        parr_add(dest->scriptWitness, buffer_copy(witness_src->p, witness_src->len));
	    }
	}
	if (!src->scriptSig)
		dest->scriptSig = NULL;
	else {
		dest->scriptSig = cstr_new_sz(src->scriptSig->len);
		cstr_append_buf(dest->scriptSig,
				    src->scriptSig->str, src->scriptSig->len);
	}
}

void bitc_txout_init(struct bitc_txout *txout)
{
	memset(txout, 0, sizeof(*txout));
}

bool deser_bitc_txout(struct bitc_txout *txout, struct const_buffer *buf)
{
	bitc_txout_free(txout);

	if (!deser_s64(&txout->nValue, buf)) return false;
	if (!deser_varstr(&txout->scriptPubKey, buf)) return false;
	return true;
}

void ser_bitc_txout(cstring *s, const struct bitc_txout *txout)
{
	ser_s64(s, txout->nValue);
	ser_varstr(s, txout->scriptPubKey);
}

void bitc_txout_free(struct bitc_txout *txout)
{
	if (!txout)
		return;

	if (txout->scriptPubKey) {
		cstr_free(txout->scriptPubKey, true);
		txout->scriptPubKey = NULL;
	}
}

void bitc_txout_freep(void *data)
{
	if (!data)
		return;

	struct bitc_txout *txout = data;
	bitc_txout_free(txout);

	memset(txout, 0, sizeof(*txout));
	free(txout);
}

void bitc_txout_set_null(struct bitc_txout *txout)
{
	bitc_txout_free(txout);

	txout->nValue = -1;
	txout->scriptPubKey = cstr_new("");
}

void bitc_txout_copy(struct bitc_txout *dest, const struct bitc_txout *src)
{
	dest->nValue = src->nValue;

	if (!src->scriptPubKey)
		dest->scriptPubKey = NULL;
	else {
		dest->scriptPubKey = cstr_new_sz(src->scriptPubKey->len);
		cstr_append_buf(dest->scriptPubKey,
				    src->scriptPubKey->str,
				    src->scriptPubKey->len);
	}
}

void bitc_tx_init(struct bitc_tx *tx)
{
	memset(tx, 0, sizeof(*tx));
	tx->nVersion = 1;
}

bool deser_bitc_tx(struct bitc_tx *tx, struct const_buffer *buf)
{
	bitc_tx_free(tx);

	if (!deser_u32(&tx->nVersion, buf)) return false;

	unsigned char flags = 0;
	tx->vin = parr_new(8, bitc_txin_freep);
	tx->vout = parr_new(8, bitc_txout_freep);

	/* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bitc_txin *txin;

		txin = calloc(1, sizeof(*txin));
		bitc_txin_init(txin);
		if (!deser_bitc_txin(txin, buf)) {
			free(txin);
			goto err_out;
		}

		parr_add(tx->vin, txin);
	}
    if (tx->vin->len == 0) {
        /* We read a dummy or an empty vin. */
        deser_bytes(&flags, buf, 1);
        if (flags != 0) {
            if (!deser_varlen(&vlen, buf)) return false;
            for (i = 0; i < vlen; i++) {
                struct bitc_txin *txin;

                txin = calloc(1, sizeof(*txin));
                bitc_txin_init(txin);
                if (!deser_bitc_txin(txin, buf)) {
                    free(txin);
                    goto err_out;
                }

            	parr_add(tx->vin, txin);
            }

            if (!deser_varlen(&vlen, buf)) return false;

        	for (i = 0; i < vlen; i++) {
        	    struct bitc_txout *txout;

        	    txout = calloc(1, sizeof(*txout));
        	    bitc_txout_init(txout);
        	    if (!deser_bitc_txout(txout, buf)) {
        	        free(txout);
        	        goto err_out;
        	    }

        	    parr_add(tx->vout, txout);
        	}
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        if (!deser_varlen(&vlen, buf)) return false;
        for (i = 0; i < vlen; i++) {
            struct bitc_txout *txout;

            txout = calloc(1, sizeof(*txout));
            bitc_txout_init(txout);
            if (!deser_bitc_txout(txout, buf)) {
                free(txout);
                goto err_out;
            }

            parr_add(tx->vout, txout);;
        }
    }
    if (flags & 1) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (i = 0; i < tx->vin->len; i++) {
            struct bitc_txin *txin = parr_idx(tx->vin, i);
            if (!deser_varlen_array(&txin->scriptWitness, buf))
                goto err_out;
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        goto err_out;
    }
	if (!deser_u32(&tx->nLockTime, buf)) return false;
	return true;

err_out:
	bitc_tx_free(tx);
	return false;
}

void ser_bitc_tx(cstring *s, const struct bitc_tx *tx)
{
	ser_u32(s, tx->nVersion);

	ser_varlen(s, tx->vin ? tx->vin->len : 0);

	unsigned int i;
	if (tx->vin) {
		for (i = 0; i < tx->vin->len; i++) {
			struct bitc_txin *txin;

			txin = parr_idx(tx->vin, i);
			ser_bitc_txin(s, txin);
		}
	}

	ser_varlen(s, tx->vout ? tx->vout->len : 0);

	if (tx->vout) {
		for (i = 0; i < tx->vout->len; i++) {
			struct bitc_txout *txout;

			txout = parr_idx(tx->vout, i);
			ser_bitc_txout(s, txout);
		}
	}

	ser_u32(s, tx->nLockTime);
}

void bitc_tx_free_vout(struct bitc_tx *tx)
{
	if (!tx || !tx->vout)
		return;

	parr_free(tx->vout, true);
	tx->vout = NULL;
}

void bitc_tx_free(struct bitc_tx *tx)
{
	if (!tx)
		return;

	if (tx->vin) {
		parr_free(tx->vin, true);
		tx->vin = NULL;
	}

	bitc_tx_free_vout(tx);

	tx->sha256_valid = false;
}

void bitc_tx_freep(void *p)
{
	struct bitc_tx *tx = p;
	if (!tx)
		return;

	bitc_tx_free(tx);

	memset(tx, 0, sizeof(*tx));
	free(tx);
}

void bitc_tx_calc_sha256(struct bitc_tx *tx)
{
	if (tx->sha256_valid)
		return;

	/* TODO: introduce hashing-only serialization mode */

	cstring *s = cstr_new_sz(512);
	ser_bitc_tx(s, tx);

	bu_Hash((unsigned char *) &tx->sha256, s->str, s->len);
	tx->sha256_valid = true;

	cstr_free(s, true);
}

unsigned int bitc_tx_ser_size(const struct bitc_tx *tx)
{
	unsigned int tx_ser_size;

	/* TODO: introduce a counting-only serialization mode */

	cstring *s = cstr_new_sz(512);
	ser_bitc_tx(s, tx);

	tx_ser_size = s->len;

	cstr_free(s, true);

	return tx_ser_size;
}

void bitc_tx_copy(struct bitc_tx *dest, const struct bitc_tx *src)
{
	dest->nVersion = src->nVersion;
	dest->nLockTime = src->nLockTime;
	dest->sha256_valid = src->sha256_valid;
	bu256_copy(&dest->sha256, &src->sha256);

	if (!src->vin)
		dest->vin = NULL;
	else {
		unsigned int i;

		dest->vin = parr_new(src->vin->len, bitc_txin_freep);

		for (i = 0; i < src->vin->len; i++) {
			struct bitc_txin *txin_old, *txin_new;

			txin_old = parr_idx(src->vin, i);
			txin_new = malloc(sizeof(*txin_new));
			bitc_txin_copy(txin_new, txin_old);
			parr_add(dest->vin, txin_new);
		}
	}

	if (!src->vout)
		dest->vout = NULL;
	else {
		unsigned int i;

		dest->vout = parr_new(src->vout->len, bitc_txout_freep);

		for (i = 0; i < src->vout->len; i++) {
			struct bitc_txout *txout_old, *txout_new;

			txout_old = parr_idx(src->vout, i);
			txout_new = malloc(sizeof(*txout_new));
			bitc_txout_copy(txout_new, txout_old);
			parr_add(dest->vout, txout_new);
		}
	}
}

static bool bitc_has_dup_inputs(const struct bitc_tx *tx)
{
	if (!tx->vin || !tx->vin->len || tx->vin->len == 1)
		return false;

	struct bitc_txin *txin, *txin_tmp;
	unsigned int i, j;
	for (i = 0; i < tx->vin->len; i++) {
		txin = parr_idx(tx->vin, i);
		for (j = 0; j < tx->vin->len; j++) {
			if (i == j)
				continue;
			txin_tmp = parr_idx(tx->vin, j);

			if (bitc_outpt_equal(&txin->prevout,
					   &txin_tmp->prevout))
				return true;
		}
	}

	return false;
}

bool bitc_tx_valid(const struct bitc_tx *tx)
{
	unsigned int i;

	// Basic checks
	if (!tx->vin || !tx->vin->len)
		return false;
	if (!tx->vout || !tx->vout->len)
		return false;

	// Size limits
	if (bitc_tx_ser_size(tx) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
		return false;

	// Check for negative or overflow output values
	int64_t value_total = 0;
	for (i = 0; i < tx->vout->len; i++) {
		struct bitc_txout *txout;

		txout = parr_idx(tx->vout, i);
		if (!bitc_txout_valid(txout))
			return false;

		value_total += txout->nValue;
	}

	if (!bitc_valid_value(value_total))
		return false;

	// Check for duplicate inputs
	if (bitc_has_dup_inputs(tx))
		return false;

	if (bitc_tx_coinbase(tx)) {
		struct bitc_txin *txin = parr_idx(tx->vin, 0);

		if (txin->scriptSig->len < 2 ||
		    txin->scriptSig->len > 100)
			return false;
	} else {
		for (i = 0; i < tx->vin->len; i++) {
			struct bitc_txin *txin;

			txin = parr_idx(tx->vin, i);
			if (bitc_outpt_null(&txin->prevout))
				return false;
		}
	}

	return true;
}

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

void bitc_utxo_freep(void *p)
{
	struct bitc_utxo *coin = p;
	if (!coin)
		return;

	bitc_utxo_free(coin);

	memset(coin, 0, sizeof(*coin));
	free(coin);
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

