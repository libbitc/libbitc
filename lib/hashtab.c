/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <bitc/hashtab.h>

struct bitc_hashtab *bitc_hashtab_new_ext(
	unsigned long (*hash_f)(const void *p),
	bool (*equal_f)(const void *a, const void *b),
	bitc_freefunc keyfree_f,
	bitc_freefunc valfree_f)
{
	// alloc container ds
	struct bitc_hashtab *ht = calloc(1, sizeof(*ht));
	if (!ht)
		return NULL;

	// alloc empty hash table
	ht->tab_size = BITC_HT_INIT_TAB_SZ;
	ht->tab = calloc(ht->tab_size, sizeof(struct bitc_ht_ent *));
	if (!ht->tab) {
		free(ht);
		return NULL;
	}

	// initialize remainder of ds
	ht->hash_f = hash_f;
	ht->equal_f = equal_f;
	ht->keyfree_f = keyfree_f;
	ht->valfree_f = valfree_f;
	ht->ref = 1;
	return ht;
}

static void bitc_ht_ent_cb(struct bitc_hashtab *ht, struct bitc_ht_ent *ent)
{
	// call destructors
	if (ht->keyfree_f)
		ht->keyfree_f(ent->key);
	if (ht->valfree_f)
		ht->valfree_f(ent->value);
}

static void bitc_ht_ent_free(struct bitc_hashtab *ht, struct bitc_ht_ent *ent)
{
	if (!ht || !ent)
		return;

	bitc_ht_ent_cb(ht, ent);
	memset(ent, 0, sizeof(*ent));
	free(ent);
}

static void bitc_hashtab_free_tab(struct bitc_hashtab *ht)
{
	if (!ht->tab)
		return;

	// iterate through entire table
	unsigned int i;
	for (i = 0; i < ht->tab_size; i++) {
		struct bitc_ht_ent *iter;

		// iterate for each entry in bucket
		iter = ht->tab[i];
		while (iter) {
			struct bitc_ht_ent *tmp = iter;
			iter = iter->next;

			// free & clear entry
			bitc_ht_ent_free(ht, tmp);
		}

		ht->tab[i] = NULL;
	}

	free(ht->tab);
	ht->tab = NULL;
	ht->tab_size = 0;
	ht->size = 0;
}

bool bitc_hashtab_clear(struct bitc_hashtab *ht)
{
	bitc_hashtab_free_tab(ht);

	ht->tab_size = BITC_HT_INIT_TAB_SZ;
	ht->tab = calloc(ht->tab_size, sizeof(struct bitc_ht_ent *));
	if (!ht->tab) {
		ht->tab_size = 0;
		return false;
	}

	return true;
}

void bitc_hashtab_unref(struct bitc_hashtab *ht)
{
	if (!ht)
		return;

	assert(ht->ref > 0);

	// deref
	ht->ref--;
	if (ht->ref)
		return;

	// clear table and buckets
	bitc_hashtab_free_tab(ht);

	// free & clear
	memset(ht, 0, sizeof(*ht));
	free(ht);
}

static bool bitc_hashtab_get_ent(struct bitc_hashtab *ht,
			       unsigned long hash,
			       const void *key,
			       unsigned int *bucket_out,
			       struct bitc_ht_ent **prev_out,
			       struct bitc_ht_ent **ent_out)
{
	// hash key (if needed), determine bucket
	if (!hash)
		hash = ht->hash_f(key);
	unsigned int bucket = hash % ht->tab_size;
	*bucket_out = bucket;

	*prev_out = NULL;
	*ent_out = NULL;

	// find desired bucket
	struct bitc_ht_ent *iter;
	iter = ht->tab[bucket];
	if (!iter)
		return false;

	// iterate through bucket, looking for exact match
	struct bitc_ht_ent *prev = NULL;
	while (iter) {
		if ((iter->hash == hash) &&
		    (ht->equal_f(iter->key, key))) {
			*prev_out = prev;
			*ent_out = iter;
			return true;
		}

		prev = iter;
		iter = iter->next;
	}

	return false;
}

bool bitc_hashtab_del(struct bitc_hashtab *ht, const void *key)
{
	// lookup key and bucket
	unsigned int bucket = 0;
	struct bitc_ht_ent *prev = NULL;
	struct bitc_ht_ent *ent = NULL;
	bool match = bitc_hashtab_get_ent(ht, 0, key, &bucket, &prev, &ent);
	if (!match)
		return false;

	// delete entry from linked list
	if (!prev)
		ht->tab[bucket] = ent->next;
	else
		prev->next = ent->next;

	// free & clear
	bitc_ht_ent_free(ht, ent);

	// adjust cached size
	ht->size--;

	return true;
}

bool bitc_hashtab_get_ext(struct bitc_hashtab *ht, const void *lookup_key,
		        void **orig_key, void **value)
{
	// lookup key
	unsigned int bucket = 0;
	struct bitc_ht_ent *prev = NULL;
	struct bitc_ht_ent *ent = NULL;
	bool match = bitc_hashtab_get_ent(ht, 0, lookup_key, &bucket, &prev,&ent);

	// if found, store original key and value
	if (match) {
		if (orig_key)
			*orig_key = ent->key;
		if (value)
			*value = ent->value;
	}

	return match;
}

static bool bitc_hashtab_grow(struct bitc_hashtab *ht)
{
	struct bitc_ht_ent **new_tab = NULL;
	unsigned int new_tab_size;

	// if table small, grow by larger factor
	if (ht->tab_size < 1024)
		new_tab_size = (ht->tab_size * 10) - 1;
	else
		new_tab_size = (ht->tab_size * 2) - 1;

	// alloc new table; our main failure point
	new_tab = calloc(new_tab_size, sizeof(struct bitc_ht_ent *));
	if (!new_tab)
		return false;

	// iterate through old table
	unsigned int i, new_buck;
	for (i = 0; i < ht->tab_size; i++) {
		struct bitc_ht_ent *tmp, *iter;

		// iterate through bucket, re-sorting into new table
		iter = ht->tab[i];
		while (iter) {
			tmp = iter;
			iter = iter->next;

			new_buck = tmp->hash % new_tab_size;
			tmp->next = new_tab[new_buck];
			new_tab[new_buck] = tmp;
		}

		// clear old bucket
		ht->tab[i] = NULL;
	}

	// free old table
	free(ht->tab);

	// point to new table
	ht->tab = new_tab;
	ht->tab_size = new_tab_size;

	return true;
}

bool bitc_hashtab_put(struct bitc_hashtab *ht, void *key, void *val)
{
	// lookup key and bucket
	unsigned long hash = ht->hash_f(key);
	unsigned int bucket = 0;
	struct bitc_ht_ent *prev = NULL;
	struct bitc_ht_ent *ent = NULL;
	bool match = bitc_hashtab_get_ent(ht, hash, key, &bucket, &prev, &ent);

	// if found, overwrite existing entry
	if (match) {
		bitc_ht_ent_cb(ht, ent);

		ent->key = key;
		ent->value = val;

		return true;
	}

	// construct new entry
	struct bitc_ht_ent *b = calloc(1, sizeof(*b));
	if (!b)
		return false;

	b->hash = hash;
	b->key = key;
	b->value = val;
	b->next = ht->tab[bucket];
	ht->tab[bucket] = b;

	// grow cached table size
	ht->size++;

	// if chain length greater than 1, possibly grow table
	if (b->next) {
		// count chain length
		unsigned int count = 0;
		struct bitc_ht_ent *tmp = b;
		while (tmp) {
			count++;
			tmp = tmp->next;
		}

		// if chain too long, grow table by one iteration
		if (count > BITC_HT_MAX_BUCKET_SZ)
			bitc_hashtab_grow(ht);
	}

	return true;
}

void bitc_hashtab_iter(struct bitc_hashtab *ht, bitc_kvu_func cb, void *priv)
{
	unsigned int bucket;
	for (bucket = 0; bucket < ht->tab_size; bucket++) {
		struct bitc_ht_ent *ent = ht->tab[bucket];
		while (ent) {
			cb(ent->key, ent->value, priv);
			ent = ent->next;
		}
	}
}

