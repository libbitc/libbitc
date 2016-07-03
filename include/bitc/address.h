#ifndef __LIBBITC_ADDRESS_H__
#define __LIBBITC_ADDRESS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/key.h>
#include <bitc/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern cstring *bitc_pubkey_get_address(const struct bitc_key *key, unsigned char addrtype);

extern cstring *bitc_privkey_get_address(const struct bitc_key *key, unsigned char addrtype);

#ifdef __cplusplus
}
#endif

#endif /* __LIBBITC_ADDRESS_H__ */
