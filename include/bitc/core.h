#ifndef __LIBBITC_CORE_H__
#define __LIBBITC_CORE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_t
#include <bitc/coredefs.h>              // for ::COIN
#include <bitc/cstr.h>                  // for cstring
#include <bitc/parr.h>                  // for parr

#include <stdbool.h>                    // for bool, false, true
#include <stdint.h>                     // for uint32_t, int64_t, uint16_t, etc
#include <string.h>                     // for memset, memcpy

#ifdef __cplusplus
extern "C" {
#endif

enum service_bits {
	NODE_NETWORK	= (1 << 0),
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

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_CORE_H__ */
