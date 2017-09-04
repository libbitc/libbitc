SUBDIRS = secp256k1 libbitc.github.io
AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES = cJSON/libcjson.la

cJSON_libcjson_la_CFLAGS = -fPIC
cJSON_libcjson_la_SOURCES = cJSON/cJSON.h cJSON/cJSON.c

cJSON_cJSON_test_SOURCES = cJSON/test.c
cJSON_cJSON_test_LDADD = cJSON/libcjson.la

check_PROGRAMS = cJSON/cJSON_test
TESTS = $(check_PROGRAMS)
