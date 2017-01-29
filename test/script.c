/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for parse_script_str, etc
#include <bitc/core.h>                  // for bitc_tx, bitc_txin, etc
#include <bitc/cstr.h>                  // for cstr_free, cstring
#include <bitc/json/cJSON.h>            // for cJSON_GetArrayItem, cJSON, etc
#include <bitc/script.h>                // for bitc_script_verify, etc

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool, false
#include <stdio.h>                      // for fprintf, stderr
#include <stdlib.h>                     // for NULL, free
#include <string.h>                     // for strcmp, strtok, strlen

struct bitc_tx BuildCreditingTransaction(struct cstring* scriptPubKey)
{
    struct bitc_tx txCredit;
    bitc_tx_init(&txCredit);
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin = parr_new(0, bitc_txin_freep);
    txCredit.vout = parr_new(0, bitc_txout_freep);

    struct bitc_txin* txinCredit = calloc(1, sizeof(struct bitc_txin));
    bitc_txin_init(txinCredit);
    bitc_outpt_null(&txinCredit->prevout);
    txinCredit->scriptSig = cstr_new(NULL);
    txinCredit->nSequence = SEQUENCE_FINAL;
    parr_add(txCredit.vin, txinCredit);

    struct bitc_txout* txoutCredit = calloc(1, sizeof(struct bitc_txout));
    bitc_txout_init(txoutCredit);
    txoutCredit->scriptPubKey = cstr_new_buf(scriptPubKey->str, scriptPubKey->len);
    txoutCredit->nValue = (uint64_t)0;
    parr_add(txCredit.vout, txoutCredit);
    bitc_tx_calc_sha256(&txCredit);

    return txCredit;
}

struct bitc_tx BuildSpendingTransaction(struct cstring* scriptSig, struct bitc_tx txCredit)
{
    struct bitc_tx txSpend;
    bitc_tx_init(&txSpend);
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin = parr_new(0, bitc_txin_freep);
    txSpend.vout = parr_new(0, bitc_txout_freep);

    struct bitc_txin* txinSpend = calloc(1, sizeof(struct bitc_txin));
    bitc_txin_init(txinSpend);
    bu256_copy(&txinSpend->prevout.hash, &txCredit.sha256);
    txinSpend->prevout.n = 0;
    txinSpend->scriptSig = cstr_new_buf(scriptSig->str, scriptSig->len);
    txinSpend->nSequence = SEQUENCE_FINAL;
    parr_add(txSpend.vin, txinSpend);

    struct bitc_txout* txoutSpend = calloc(1, sizeof(struct bitc_txout));
    bitc_txout_init(txoutSpend);
    txoutSpend->scriptPubKey = cstr_new(NULL); //
    txoutSpend->nValue = (uint64_t)0;
    parr_add(txSpend.vout, txoutSpend);

    bitc_tx_free(&txCredit);
    return txSpend;
}

static void test_script(bool is_valid,
    cstring* scriptSig,
    cstring* scriptPubKey,
    unsigned int idx,
    const char* scriptSigEnc,
    const char* scriptPubKeyEnc,
    const unsigned int test_flags)
{
    struct bitc_tx tx =
        BuildSpendingTransaction(scriptSig, BuildCreditingTransaction(scriptPubKey));

    bool rc;
    rc = bitc_script_verify(scriptSig, scriptPubKey, &tx, 0, test_flags, SIGHASH_NONE);

    if (rc != is_valid) {
        fprintf(stderr, "script: %sis_valid test %u failed\n"
                        "script: [\"%s\", \"%s\"]\n",
            is_valid ? "" : "!", idx, scriptSigEnc, scriptPubKeyEnc);
        assert(rc == is_valid);
    }

    bitc_tx_free(&tx);
}

static void runtest(const char* json_base_fn)
{
    char* json_fn = test_filename(json_base_fn);
    cJSON* tests = read_json(json_fn);
    assert(tests != NULL);
    assert((tests->type & 0xFF) == cJSON_Array);
    static unsigned int verify_flags;
    bool is_valid;

    unsigned int idx;
    for (idx = 0; idx < cJSON_GetArraySize(tests); idx++) {
        cJSON* test = cJSON_GetArrayItem(tests, idx);
        assert((test->type & 0xFF) == cJSON_Array);
        unsigned int pos = 0;
        if (cJSON_GetArraySize(test) > 1) {
            const char* scriptSigEnc = cJSON_GetArrayItem(test, pos++)->valuestring;
            const char* scriptPubKeyEnc = cJSON_GetArrayItem(test, pos++)->valuestring;
            assert(scriptSigEnc != NULL);
            assert(scriptPubKeyEnc != NULL);

            cstring* scriptSig = parse_script_str(scriptSigEnc);

            cstring* scriptPubKey = parse_script_str(scriptPubKeyEnc);
            assert(scriptSig != NULL);
            assert(scriptPubKey != NULL);

            verify_flags = SCRIPT_VERIFY_NONE;

            const char* json_flags = cJSON_GetArrayItem(test, pos++)->valuestring;
            if (strlen(json_flags) > 0) {
                const char* json_flag = strtok((char*)json_flags, ",");

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
                    else if (strcmp(json_flag, "CHECKSEQUENCEVERIFY") == 0)
                        verify_flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
                    json_flag = strtok(NULL, ",");
                } while (json_flag);
            }

            const char* scriptError = cJSON_GetArrayItem(test, 3)->valuestring;

            is_valid = strcmp(scriptError, "OK") == 0 ? true : false;
            test_script(is_valid, scriptSig, scriptPubKey, idx, scriptSigEnc, scriptPubKeyEnc,
                verify_flags);

            cstr_free(scriptSig, true);
            cstr_free(scriptPubKey, true);
        }
    }

    cJSON_Delete(tests);
    free(json_fn);
}

int main(int argc, char* argv[])
{
    runtest("script_tests.json");
    return 0;
}
