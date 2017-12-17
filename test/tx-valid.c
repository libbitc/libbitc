/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libbitc-config.h"

#include "bitc/buffer.h"                // for const_buffer
#include <bitc/buint.h>                 // for bu256_hex, BU256_STRSZ, etc
#include <bitc/core.h>                  // for bitc_outpt, bitc_tx, etc
#include "bitc/cstr.h"                  // for cstring, cstr_free
#include <bitc/hashtab.h>               // for bitc_hashtab_clear, etc
#include <bitc/hexcode.h>               // for hex2str
#include "bitc/key.h"                   // for bitc_key_static_shutdown
#include "bitc/parr.h"                  // for parr, parr_free, parr_new, etc
#include <bitc/script/interpreter.h>    // for bitc_script_verify, etc
#include <bitc/compat.h>                // for parr_new
#include "libtest.h"                    // for parse_script_str, etc

#include <cJSON.h>                      // for cJSON_GetArrayItem, cJSON, etc

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool, false
#include <stdint.h>                     // for uint32_t
#include <stdio.h>                      // for NULL, fprintf, stderr
#include <stdlib.h>                     // for free, malloc
#include <string.h>                     // for NULL, strtok, strcmp, etc

parr *comments = NULL;

static unsigned long input_hash(const void *key_)
{
	const struct bitc_outpt *key = key_;

	return key->hash.dword[4];
}

static bool input_equal(const void *a, const void *b)
{
	return bitc_outpt_equal(a, b);
}

static void input_value_free(void *v)
{
	cstr_free(v, true);
}

static void dump_comments(void)
{
	unsigned int i;
	for (i = 0; i < comments->len; i++) {
		fprintf(stderr, "tx-valid cmt: %s\n",
			(char *)parr_idx(comments, i));
	}
}

static void test_tx_valid(bool is_valid,
    struct bitc_hashtab* mapprevOutScriptPubKeys,
    struct bitc_hashtab* mapprevOutValues,
    cstring* tx_ser,
    const unsigned int test_flags)
{
	struct bitc_tx tx;

	bitc_tx_init(&tx);

	struct const_buffer buf = { tx_ser->str, tx_ser->len };
	assert(deser_bitc_tx(&tx, &buf) == true);

	if (is_valid) {
		/* checking for valid tx; !bitc_tx_valid implies test fail */
		assert(bitc_tx_valid(&tx) == true);
	} else {
		/* checking for invalid tx; bitc_tx_valid==false implies test
		 * succeeded; no more work to do; bitc_tx_valid==true
		 * implies the test will detect the invalid condition
		 * further down in the code
		 */
		if (bitc_tx_valid(&tx) == false)
			goto out;
	}

	bitc_tx_calc_sha256(&tx);

	bool state = true;
	unsigned int i;
	for (i = 0; i < tx.vin->len; i++) {
		struct bitc_txin *txin;

		txin = parr_idx(tx.vin, i);
		assert(txin != NULL);

		cstring* scriptPubKey = bitc_hashtab_get(mapprevOutScriptPubKeys, &txin->prevout);
		int64_t* amount = bitc_hashtab_get(mapprevOutValues, &txin->prevout);

		if (scriptPubKey == NULL) {
		    if (!is_valid) {
    		    /* if testing tx_invalid.json, missing input
    		     * is invalid, and therefore correct
    		     */
		        continue;
			}

			char tx_hexstr[BU256_STRSZ], hexstr[BU256_STRSZ];
			bu256_hex(tx_hexstr, &tx.sha256);
			bu256_hex(hexstr, &txin->prevout.hash);
			dump_comments();
			fprintf(stderr,
			"tx-valid: TX %s\n"
			"tx-valid: prevout (%s, %u) not found\n",
				tx_hexstr, hexstr, txin->prevout.n);

			assert(scriptPubKey != NULL);
		}

        bool rc = bitc_script_verify(txin->scriptSig, scriptPubKey, &txin->scriptWitness,
                    &tx, i, test_flags, *amount);

        state &= rc;

        if (rc != is_valid) {
			char tx_hexstr[BU256_STRSZ];
			bu256_hex(tx_hexstr, &tx.sha256);
			dump_comments();
			fprintf(stderr,
			"tx-valid: TX %s\n"
			"tx-valid: txin %u script verification failed\n",
				tx_hexstr, i);
		}
	}
	assert(state == is_valid);

out:
	bitc_tx_free(&tx);
}

static void runtest(bool is_valid, const char *json_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	cJSON *tests = read_json(json_fn);
	assert(tests != NULL);
	assert((tests->type & 0xFF) == cJSON_Array);

	struct bitc_hashtab* mapprevOutScriptPubKeys =
            bitc_hashtab_new_ext(input_hash, input_equal, free, input_value_free);
    struct bitc_hashtab* mapprevOutValues =
            bitc_hashtab_new_ext(input_hash, input_equal, free, free);

    comments = parr_new(8, free);

	unsigned int idx;
	for (idx = 0; idx < cJSON_GetArraySize(tests); idx++) {
		cJSON *test = cJSON_GetArrayItem(tests, idx);

		assert((test->type & 0xFF) == cJSON_Array);
		if ((cJSON_GetArrayItem(test, 0)->type & 0xFF) != cJSON_Array) {
			const char *cmt =
				cJSON_GetArrayItem(test, 0)->valuestring;
			if (cmt)
				parr_add(comments, strdup(cmt)); /* comments */
		} else {
		    assert(cJSON_GetArraySize(test) == 3);
		    assert((cJSON_GetArrayItem(test, 1)->type & 0xFF) == cJSON_String);
		    assert((cJSON_GetArrayItem(test, 2)->type & 0xFF) == cJSON_String);

		    cJSON *inputs = cJSON_GetArrayItem(test, 0);
		    assert((inputs->type & 0xFF) == cJSON_Array);
		    static unsigned int verify_flags;

            bitc_hashtab_clear(mapprevOutScriptPubKeys);
                    bitc_hashtab_clear(mapprevOutValues);

            unsigned int inpIdx;
            for (inpIdx = 0; inpIdx < cJSON_GetArraySize(inputs); inpIdx++) {
                cJSON* input = cJSON_GetArrayItem(inputs, inpIdx);
                assert((input->type & 0xFF) == cJSON_Array);

                const char* prev_hashstr = cJSON_GetArrayItem(input, 0)->valuestring;
                int prev_n = cJSON_GetArrayItem(input, 1)->valuedouble;
                const char* prev_pubkey_enc = cJSON_GetArrayItem(input, 2)->valuestring;

                assert(prev_hashstr != NULL);
                assert(cJSON_GetArrayItem(input, 1)->type == cJSON_Number);
                assert(prev_pubkey_enc != NULL);

                struct bitc_outpt* outpt;
                outpt = malloc(sizeof(*outpt));
                hex_bu256(&outpt->hash, prev_hashstr);
                outpt->n = prev_n;

                cstring* script = parse_script_str(prev_pubkey_enc);
                assert(script != NULL);

                bitc_hashtab_put(mapprevOutScriptPubKeys, outpt, script);

                struct bitc_outpt* outpt_amt;
                outpt_amt = malloc(sizeof(*outpt_amt));
                hex_bu256(&outpt_amt->hash, prev_hashstr);
                outpt_amt->n = prev_n;

                int64_t* amount;
                amount = malloc(sizeof(*amount));
                *amount = 0;
                if (cJSON_GetArraySize(input) >= 4) {
                    assert(cJSON_GetArrayItem(input, 3)->type == cJSON_Number);
                    *amount = cJSON_GetArrayItem(input, 3)->valuedouble;
                }
                bitc_hashtab_put(mapprevOutValues, outpt_amt, amount);
            }

		    const char *tx_hexser =
					cJSON_GetArrayItem(test, 1)->valuestring;
		    assert(tx_hexser != NULL);

		    verify_flags = SCRIPT_VERIFY_NONE;

		    const char *json_flags = cJSON_GetArrayItem(test, 2)->valuestring;

		    if (strlen(json_flags) > 0) {
				const char* json_flag  = strtok((char *)json_flags, ",");

				do {
					if (strcmp(json_flag, "P2SH") == 0)
					    verify_flags |= SCRIPT_VERIFY_P2SH;
					else if (strcmp(json_flag, "STRICTENC") == 0)
					    verify_flags |= SCRIPT_VERIFY_STRICTENC;
					else if (strcmp(json_flag, "DERSIG") == 0)
					    verify_flags |= SCRIPT_VERIFY_DERSIG;
					else if (strcmp(json_flag, "LOW_S") == 0)
					    verify_flags |= SCRIPT_VERIFY_LOW_S;
					else if (strcmp(json_flag, "NULLDUMMY") == 0)
					    verify_flags |= SCRIPT_VERIFY_NULLDUMMY;
					else if (strcmp(json_flag, "SIGPUSHONLY") == 0)
					    verify_flags |= SCRIPT_VERIFY_SIGPUSHONLY;
					else if (strcmp(json_flag, "MINIMALDATA") == 0)
					    verify_flags |= SCRIPT_VERIFY_MINIMALDATA;
					else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_NOPS") == 0)
					    verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
					else if (strcmp(json_flag, "CLEANSTACK") == 0)
					    verify_flags |= SCRIPT_VERIFY_CLEANSTACK;
					else if (strcmp(json_flag, "CHECKLOCKTIMEVERIFY") == 0)
					    verify_flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
					else if (strcmp(json_flag, "CHECKSEQUENCEVERIFY") == 0)
					    verify_flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
                    else if (strcmp(json_flag, "WITNESS") == 0)
                        verify_flags |= SCRIPT_VERIFY_WITNESS;
                    else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") == 0)
                        verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
                    json_flag = strtok(NULL, ",");
				} while (json_flag);
		    }

		    cstring *tx_ser = hex2str(tx_hexser);
		    assert(tx_ser != NULL);

            test_tx_valid(is_valid, mapprevOutScriptPubKeys,
                mapprevOutValues, tx_ser, verify_flags);

            cstr_free(tx_ser, true);

		    if (comments->len > 0) {
				parr_free(comments, true);
				comments = parr_new(8, free);
		    }
		}
    }

	parr_free(comments, true);
	comments = NULL;
    bitc_hashtab_unref(mapprevOutScriptPubKeys);
    bitc_hashtab_unref(mapprevOutValues);
    cJSON_Delete(tests);
	free(json_fn);
}

int main (int argc, char *argv[])
{
	runtest(true, "data/tx_valid.json");
	runtest(false, "data/tx_invalid.json");

    bitc_key_static_shutdown();
	return 0;
}
