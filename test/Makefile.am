if ENABLE_VALGRIND
    TESTS_ENVIRONMENT = $(LIBTOOL) --mode=execute valgrind --leak-check=full \
                        --leak-resolution=high --num-callers=40 \
                        --error-exitcode=1
endif

AM_CPPFLAGS = \
	-DTEST_SRCDIR=\"$(top_srcdir)/test\" \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/external/secp256k1/include

EXTRA_DIST = \
	base58_encode_decode.json	\
	base58_keys_invalid.json base58_keys_valid.json		\
	blk0.json blk0.ser blks10.ser \
	blk120383.json blk120383.ser \
	hdr193000.ser tn_hdr35141.ser \
	random.data	script_tests.json \
	tn_blk35133.ser tx3e0dc3da.json tx3e0dc3da.ser \
	tx_invalid.json tx_valid.json \
	wallet-basics.json

noinst_LTLIBRARIES = libtest.la

libtest_la_SOURCES = libtest.h libtest.c randtest.c chisq.c

check_PROGRAMS = aes-util base58 blkdb block blockfile bloom \
    chain-verf clist coredefs crypto cstr ctaes fileio hash hashtab \
    hdkeys hex keystore json keyset mbr misc net message parr prng \
	script script-parse tx tx-valid wallet wallet-basics util

TESTS = $(check_PROGRAMS)

COMMON_LDADD = libtest.la \
	$(top_builddir)/lib/libbitc.la \
	$(top_builddir)/lib/libbitcwallet.la \
	$(top_builddir)/external/secp256k1/libsecp256k1.la \
	@GMP_LIBS@ @MATH_LIBS@

aes_util_LDADD		= $(COMMON_LDADD)
base58_LDADD		= $(COMMON_LDADD)
blkdb_LDADD		= $(COMMON_LDADD)
block_LDADD		= $(COMMON_LDADD)
blockfile_LDADD		= $(COMMON_LDADD)
bloom_LDADD		= $(COMMON_LDADD)
chain_verf_LDADD	= $(COMMON_LDADD)
clist_LDADD		= $(COMMON_LDADD)
coredefs_LDADD		= $(COMMON_LDADD)
crypto_LDADD		= $(COMMON_LDADD)
cstr_LDADD		= $(COMMON_LDADD)
ctaes_LDADD		= $(COMMON_LDADD)
fileio_LDADD		= $(COMMON_LDADD)
hash_LDADD		= $(COMMON_LDADD)
hashtab_LDADD		= $(COMMON_LDADD)
hdkeys_LDADD		= $(COMMON_LDADD)
hex_LDADD		= $(COMMON_LDADD)
json_LDADD		= $(COMMON_LDADD)
keyset_LDADD		= $(COMMON_LDADD)
keystore_LDADD		= $(COMMON_LDADD)
message_LDADD		= $(COMMON_LDADD)
mbr_LDADD		= $(COMMON_LDADD)
misc_LDADD		= $(COMMON_LDADD)
net_LDADD		= $(COMMON_LDADD) $(top_builddir)/lib/libbitcnet.la
parr_LDADD		= $(COMMON_LDADD)
prng_LDADD		= $(COMMON_LDADD)
script_LDADD		= $(COMMON_LDADD)
script_parse_LDADD	= $(COMMON_LDADD)
tx_LDADD		= $(COMMON_LDADD)
tx_valid_LDADD		= $(COMMON_LDADD)
util_LDADD		= $(COMMON_LDADD) $(top_builddir)/lib/libbitcnet.la
wallet_LDADD		= $(COMMON_LDADD)
wallet_basics_LDADD	= $(COMMON_LDADD)
