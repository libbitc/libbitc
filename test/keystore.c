/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <stdio.h>
#include <assert.h>
#include <bitc/key.h>

static void testit(void)
{
	bool rc;

	struct bitc_key *key1, *key2;
	key1 = calloc(1, sizeof(*key1));
	key2 = calloc(1, sizeof(*key2));
	bitc_key_init(key1);
	bitc_key_init(key2);

	rc = bitc_key_generate(key1);
	assert(rc == true);
	rc = bitc_key_generate(key2);
	assert(rc == true);

	struct bitc_keystore ks;
	bkeys_init(&ks);

	rc = bkeys_add(&ks, key1);
	assert(rc == true);
	rc = bkeys_add(&ks, key2);
	assert(rc == true);

	bkeys_free(&ks);
}

int main (int argc, char *argv[])
{
	testit();
	return 0;
}

