/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "libbitc-config.h"

#include <bitc/buint.h>                 // for bu256_new, bu256_t, etc
#include <bitc/core.h>                  // for bitc_locator, bitc_address, etc
#include <bitc/cstr.h>                  // for cstring
#include <bitc/net/version.h>           // for CADDR_TIME_VERSION
#include <bitc/parr.h>                  // for parr_add, parr_free, etc
#include <bitc/serialize.h>             // for deser_u32, ser_u32, etc

#include <stdbool.h>                    // for false, true, bool
#include <stdlib.h>                     // for free, NULL
#include <string.h>                     // for memset


bool deser_bitc_addr(unsigned int protover,
		struct bitc_address *addr, struct const_buffer *buf)
{
	bitc_addr_free(addr);

	if (protover >= CADDR_TIME_VERSION)
		if (!deser_u32(&addr->nTime, buf)) return false;
	if (!deser_u64(&addr->nServices, buf)) return false;
	if (!deser_bytes(&addr->ip, buf, 16)) return false;
	if (!deser_u16(&addr->port, buf)) return false;
	return true;
}

void ser_bitc_addr(cstring *s, unsigned int protover, const struct bitc_address *addr)
{
	if (protover >= CADDR_TIME_VERSION)
		ser_u32(s, addr->nTime);
	ser_u64(s, addr->nServices);
	ser_bytes(s, addr->ip, 16);
	ser_u16(s, addr->port);
}

void bitc_addr_freep(void *p)
{
	struct bitc_address *addr = p;

	if (!addr)
		return;

	bitc_addr_free(addr);

	memset(addr, 0, sizeof(*addr));
	free(addr);
}

void bitc_inv_init(struct bitc_inv *inv)
{
	memset(inv, 0, sizeof(*inv));
}

bool deser_bitc_inv(struct bitc_inv *inv, struct const_buffer *buf)
{
	bitc_inv_free(inv);

	if (!deser_u32(&inv->type, buf)) return false;
	if (!deser_u256(&inv->hash, buf)) return false;
	return true;
}

void ser_bitc_inv(cstring *s, const struct bitc_inv *inv)
{
	ser_u32(s, inv->type);
	ser_u256(s, &inv->hash);
}

void bitc_inv_freep(void *bitc_inv_p)
{
	struct bitc_inv *inv = bitc_inv_p;
	if (!inv)
		return;

	bitc_inv_free(inv);

	memset(inv, 0, sizeof(*inv));
	free(inv);
}

bool deser_bitc_locator(struct bitc_locator *locator, struct const_buffer *buf)
{
	bitc_locator_free(locator);

	if (!deser_u32(&locator->nVersion, buf)) return false;
	if (!deser_u256_array(&locator->vHave, buf)) return false;

	return true;
}

void ser_bitc_locator(cstring *s, const struct bitc_locator *locator)
{
	ser_u32(s, locator->nVersion);
	ser_u256_array(s, locator->vHave);
}

void bitc_locator_free(struct bitc_locator *locator)
{
	if (!locator)
		return;

	if (locator->vHave) {
		parr_free(locator->vHave, true);
		locator->vHave = NULL;
	}
}

void bitc_locator_push(struct bitc_locator *locator, const bu256_t *hash_in)
{
	/* TODO: replace '16' with number based on real world usage */
	if (!locator->vHave)
		locator->vHave = parr_new(16, bu256_freep);

	bu256_t *hash = bu256_new(hash_in);
	parr_add(locator->vHave, hash);
}
