#ifndef __LIBBITC_CHECKPOINTS_H__
#define __LIBBITC_CHECKPOINTS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <bitc/coredefs.h>
#include <bitc/buint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bitc_checkpoint {
	unsigned int	height;
	const char	*hashstr;
};

struct bitc_checkpoint_set {
	enum chains			chain;
	unsigned int			ckpt_len;
	const struct bitc_checkpoint	*ckpts;
};

extern const struct bitc_checkpoint_set bitc_ckpts[];
extern bool bitc_ckpt_block(enum chains chain, unsigned int height, const bu256_t *hash);
extern unsigned int bitc_ckpt_last(enum chains chain);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_CHECKPOINTS_H__ */
