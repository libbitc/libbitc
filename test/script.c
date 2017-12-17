/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for parse_script_str, etc
#include <bitc/core.h>                  // for bitc_tx, bitc_txin, etc
#include <bitc/cstr.h>                  // for cstr_free, cstring
#include <bitc/hexcode.h>               // for hex2str
#include <bitc/script/interpreter.h>    // for bitc_script_verify, etc

#include <cJSON.h>                      // for cJSON_GetArrayItem, cJSON, etc

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool, false
#include <stdio.h>                      // for fprintf, stderr
#include <stdlib.h>                     // for NULL, free
#include <string.h>                     // for strcmp, strtok, strlen


struct bitc_tx BuildCreditingTransaction(struct cstring* scriptPubKey, int64_t nValue)
{
    struct bitc_tx txCredit;
    bitc_tx_init(&txCredit);
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin = parr_new(0, bitc_txin_freep);
    txCredit.vout = parr_new(0, bitc_txout_freep);

    struct bitc_txin* txinCredit = calloc(1, sizeof(struct bitc_txin));
    bitc_txin_init(txinCredit);
    txinCredit->prevout.n = (uint32_t)-1;
    bu256_set_u64(&txinCredit->prevout.hash, 0);
    txinCredit->scriptSig = cstr_new(NULL);
    cstr_append_c(txinCredit->scriptSig, 0);
    cstr_append_c(txinCredit->scriptSig, 0);
    txinCredit->nSequence = SEQUENCE_FINAL;
    parr_add(txCredit.vin, txinCredit);

    struct bitc_txout* txoutCredit = calloc(1, sizeof(struct bitc_txout));
    bitc_txout_init(txoutCredit);
    txoutCredit->scriptPubKey = cstr_new_buf(scriptPubKey->str, scriptPubKey->len);
    txoutCredit->nValue = nValue;
    parr_add(txCredit.vout, txoutCredit);
    bitc_tx_calc_sha256(&txCredit);

    return txCredit;
}

struct bitc_tx BuildSpendingTransaction(struct cstring* scriptSig, parr* scriptWitness,
    struct bitc_tx* txCredit)
{
    struct bitc_tx txSpend;
    bitc_tx_init(&txSpend);
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin = parr_new(0, bitc_txin_freep);
    txSpend.vout = parr_new(0, bitc_txout_freep);

    struct bitc_txin* txinSpend = calloc(1, sizeof(struct bitc_txin));
    bitc_txin_init(txinSpend);
    txinSpend->scriptWitness = scriptWitness;
    bu256_copy(&txinSpend->prevout.hash, &txCredit->sha256);
    txinSpend->prevout.n = 0;
    txinSpend->scriptSig = cstr_new_buf(scriptSig->str, scriptSig->len);
    txinSpend->nSequence = SEQUENCE_FINAL;
    parr_add(txSpend.vin, txinSpend);

    struct bitc_txout* txoutSpend = calloc(1, sizeof(struct bitc_txout));
    bitc_txout_init(txoutSpend);
    txoutSpend->scriptPubKey = cstr_new(NULL);
    struct bitc_txout* txoutCredit = parr_idx(txCredit->vout, 0);
    txoutSpend->nValue = txoutCredit->nValue;
    parr_add(txSpend.vout, txoutSpend);

    bitc_tx_free(txCredit);
    return txSpend;
}

static void test_script(bool is_valid, cstring* scriptSig, cstring* scriptPubKey,
    parr* scriptWitness, unsigned int idx, const char* scriptSigString,
    const char* scriptPubKeyString, const unsigned int test_flags,int64_t nValue)
{
    struct bitc_tx tx = BuildCreditingTransaction(scriptPubKey, nValue);
    tx = BuildSpendingTransaction(scriptSig, scriptWitness, &tx);

    bool rc;
    rc = bitc_script_verify(scriptSig, scriptPubKey, &scriptWitness, &tx, 0,
                        test_flags, nValue);

    if (rc != is_valid) {
        fprintf(stderr, "script: %sis_valid test %u failed\n"
                        "script: [\"%s\", \"%s\"]\n",
            is_valid ? "" : "!", idx, scriptSigString, scriptPubKeyString);
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
        parr* scriptWitness = parr_new(0, buffer_freep);
        int64_t nValue = 0;
        unsigned int pos = 0;
        if ((cJSON_GetArraySize(test) > 0) &&
            ((cJSON_GetArrayItem(test, pos)->type & 0xFF) == cJSON_Array)) {
            cJSON* witness_data = cJSON_GetArrayItem(test, pos);
            unsigned int i;
            for (i = 0; i < cJSON_GetArraySize(witness_data) - 1; i++) {
                cstring* witness = hex2str(cJSON_GetArrayItem(witness_data, i)->valuestring);
                if (!witness)
                    witness = cstr_new_sz(0);
                parr_add(scriptWitness, buffer_copy(witness->str, witness->len));
                cstr_free(witness, true);
            }
            nValue = cJSON_GetArrayItem(witness_data, i)->valuedouble * COIN;
            pos++;
        }

        // Allow size > 3; extra stuff ignored (useful for comments)
        if (cJSON_GetArraySize(test) < 4 + pos) {
            if (cJSON_GetArraySize(test) != 1) {
                fprintf(stderr, "script: Bad test %u\n", idx);
            }
            parr_free(scriptWitness, true);
            continue;
        }

        const char* scriptSigString = cJSON_GetArrayItem(test, pos++)->valuestring;
        assert(scriptSigString != NULL);
        cstring* scriptSig = parse_script_str(scriptSigString);
        assert(scriptSig != NULL);

        const char* scriptPubKeyString = cJSON_GetArrayItem(test, pos++)->valuestring;
        assert(scriptPubKeyString != NULL);
        cstring* scriptPubKey = parse_script_str(scriptPubKeyString);
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
                else if (strcmp(json_flag, "WITNESS") == 0)
                    verify_flags |= SCRIPT_VERIFY_WITNESS;
                else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") == 0)
                    verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
                else if (strcmp(json_flag, "MINIMALIF") == 0)
                    verify_flags |= SCRIPT_VERIFY_MINIMALIF;
                else if (strcmp(json_flag, "NULLFAIL") == 0)
                    verify_flags |= SCRIPT_VERIFY_NULLFAIL;
                else if (strcmp(json_flag, "WITNESS_PUBKEYTYPE") == 0)
                    verify_flags |= SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
                json_flag = strtok(NULL, ",");
            } while (json_flag);
        }

        const char* scriptError = cJSON_GetArrayItem(test, pos++)->valuestring;

        is_valid = strcmp(scriptError, "OK") == 0 ? true : false;
        test_script(is_valid, scriptSig, scriptPubKey, scriptWitness, idx,
            scriptSigString, scriptPubKeyString, verify_flags, nValue);

        cstr_free(scriptSig, true);
        cstr_free(scriptPubKey, true);
    }

    cJSON_Delete(tests);
    free(json_fn);
}

int main(int argc, char* argv[])
{
    runtest("data/script_tests.json");
    return 0;
}
