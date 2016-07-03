#ifndef __LIBBITC_HASHTAB_H__
#define __LIBBITC_HASHTAB_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BP_HT_INIT_TAB_SZ	= 11,
	BP_HT_MAX_BUCKET_SZ	= 3,
};

typedef void (*bitc_freefunc)(void *);
typedef void (*bitc_kvu_func)(void *key, void *value, void *user_private);

struct bitc_ht_ent {
	unsigned long		hash;	// hash_f() of key
	void			*key;	// key pointer
	void			*value; // value pointer

	struct bitc_ht_ent	*next;	// next record in hash bucket
};

struct bitc_hashtab {
	unsigned int	ref;		// reference count
	unsigned int	size;		// table entry count

	struct bitc_ht_ent **tab;		// table buckets
	unsigned int	tab_size;	// bucket count

					// key comparison
	unsigned long	(*hash_f)(const void *p);
	bool		(*equal_f)(const void *a, const void *b);

					// key, value destruction

	bitc_freefunc	keyfree_f;
	bitc_freefunc	valfree_f;
};

extern struct bitc_hashtab *bitc_hashtab_new_ext(
	unsigned long (*hash_f)(const void *p),
	bool (*equal_f)(const void *a, const void *b),
	bitc_freefunc keyfree_f,
	bitc_freefunc valfree_f);

static inline struct bitc_hashtab *bitc_hashtab_new(
	unsigned long (*hash_f)(const void *p),
	bool (*equal_f)(const void *a, const void *b))
{
	return bitc_hashtab_new_ext(hash_f, equal_f, NULL, NULL);
}

extern void bitc_hashtab_unref(struct bitc_hashtab *);
extern bool bitc_hashtab_clear(struct bitc_hashtab *);

static inline void bitc_hashtab_ref(struct bitc_hashtab *ht)
{
	ht->ref++;
}

static inline unsigned int bitc_hashtab_size(const struct bitc_hashtab *ht)
{
	return ht->size;
}

extern bool bitc_hashtab_del(struct bitc_hashtab *ht, const void *key);
extern bool bitc_hashtab_put(struct bitc_hashtab *ht, void *key, void *val);
extern bool bitc_hashtab_get_ext(struct bitc_hashtab *ht, const void *lookup_key,
			       void **orig_key, void **value);

static inline void *bitc_hashtab_get(struct bitc_hashtab *ht, const void *key)
{
	void *ret_key = NULL;
	void *ret_val = NULL;
	bool rc = bitc_hashtab_get_ext(ht, key, &ret_key, &ret_val);
	if (!rc)
		return NULL;

	return ret_val;
}

extern void bitc_hashtab_iter(struct bitc_hashtab *ht, bitc_kvu_func f, void *priv);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_HASHTAB_H__ */
