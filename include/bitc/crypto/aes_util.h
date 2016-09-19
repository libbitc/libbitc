#ifndef __LIBBITC_CRYPTO_AES_UTIL_H__
#define __LIBBITC_CRYPTO_AES_UTIL_H__
/* Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdlib.h>
#include <stdint.h>
#include <bitc/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wrap low level aes routines to decrypt a buffer with a given
 * password.
 */
extern cstring *decrypt_aes_buffer(const void *ciphertext,
				   size_t ct_len,
				   const void *key,
				   size_t key_len);

/**
 * Wrap low level aes routines to encrypt a buffer with a given
 * password.
 */
extern void *encrypt_aes_buffer(const void *plaintext,
				size_t pt_len,
				const void *key,
				size_t key_len,
				size_t *ct_len);

extern cstring *read_aes_file(const char *filename, void *key, size_t key_len,
			      size_t max_file_len);

extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

#ifdef __cplusplus
}
#endif

#endif // __LIBBITC_CRYPTO_AES_UTIL_H__