/* Copyright 2017 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for read_json, test_filename
#include <bitc/buffer.h>                // for const_buffer
#include <bitc/buint.h>                 // for bu256_equal, bu256_t, etc
#include <bitc/core.h>                  // for bitc_tx_free, bitc_tx_init, etc
#include <bitc/cstr.h>                  // for cstr_free, cstring
#include <bitc/hexcode.h>               // for hex2str
#include <bitc/json/cJSON.h>            // for cJSON_GetArrayItem, cJSON, etc
#include <bitc/script.h>                // for bitc_tx_sighash

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true
#include <stdio.h>                      // for NULL
#include <stdlib.h>                     // for free


static void runtest(const char* json_base_fn)
{
    char* json_fn = test_filename(json_base_fn);
    cJSON* tests = read_json(json_fn);
    assert(tests != NULL);
    assert((tests->type & 0xFF) == cJSON_Array);

    unsigned int idx;
    for (idx = 0; idx < cJSON_GetArraySize(tests); idx++) {
        cJSON* test = cJSON_GetArrayItem(tests, idx);
        assert((test->type & 0xFF) == cJSON_Array);

        if (cJSON_GetArraySize(test) == 1)
            assert((cJSON_GetArrayItem(test, 0)->type & 0xFF) == cJSON_String);
        else {
            assert(cJSON_GetArraySize(test) == 5);
            assert((cJSON_GetArrayItem(test, 0)->type & 0xFF) == cJSON_String);
            assert((cJSON_GetArrayItem(test, 1)->type & 0xFF) == cJSON_String);
            assert((cJSON_GetArrayItem(test, 2)->type & 0xFF) == cJSON_Number);
            assert((cJSON_GetArrayItem(test, 3)->type & 0xFF) == cJSON_Number);
            assert((cJSON_GetArrayItem(test, 4)->type & 0xFF) == cJSON_String);

            const char *tx_hexser = cJSON_GetArrayItem(test, 0)->valuestring;
		    assert(tx_hexser != NULL);
		    cstring *tx_ser = hex2str(tx_hexser);
		    assert(tx_ser != NULL);

            struct bitc_tx txTo;
            bitc_tx_init(&txTo);
            struct const_buffer buf = { tx_ser->str, tx_ser->len };
            assert(deser_bitc_tx(&txTo, &buf) == true);
            assert(bitc_tx_valid(&txTo) == true);

            const char *scriptCode_hexser = cJSON_GetArrayItem(test, 1)->valuestring;
		    assert(scriptCode_hexser != NULL);
		    cstring *scriptCode = hex2str(scriptCode_hexser);

		    unsigned int nIn = cJSON_GetArrayItem(test, 2)->valueint;
		    int nHashType = cJSON_GetArrayItem(test, 3)->valueint;

		    bu256_t sighash;
            bitc_tx_sighash(&sighash, scriptCode, &txTo, nIn, nHashType, 0, 0);

            bu256_t sighash_res;
            hex_bu256(&sighash_res, cJSON_GetArrayItem(test, 4)->valuestring);
            assert(bu256_equal(&sighash, &sighash_res));

            cstr_free(scriptCode, true);
            cstr_free(tx_ser, true);
            bitc_tx_free(&txTo);
        }
    }
    cJSON_Delete(tests);
    free(json_fn);
}

int main(int argc, char* argv[])
{
    runtest("data/sighash.json");
    return 0;
}
