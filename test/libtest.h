#ifndef __LIBTEST_H__
#define __LIBTEST_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/cstr.h>                  // for cstring
#include <stddef.h>                     // for size_t

#include <cJSON.h>                      // for cJSON

extern cJSON *read_json(const char *filename);
extern char *test_filename(const char *basename);
extern void dumphex(const char *prefix, const void *p_, size_t len);
extern cstring *parse_script_str(const char *enc);

#endif /* __LIBTEST_H__ */
