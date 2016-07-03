AUTOMAKE_OPTIONS= subdir-objects

AM_CPPFLAGS	=   -I$(top_srcdir)/include \
                -I$(top_srcdir)/external/secp256k1/include \
                -I$(top_srcdir)/external/secp256k1/contrib

lib_LTLIBRARIES= libbitc.la

libbitc_la_LIBADD= -lm \
                    $(top_builddir)/external/secp256k1/libsecp256k1.la

libbitc_la_SOURCES=	\
	crypto/aes_modes.c	\
	crypto/aescrypt.c	\
	crypto/aeskey.c	\
	crypto/aesopt.h	\
	crypto/aestab.c	\
	crypto/aestab.h	\
	crypto/hmac.c	\
	crypto/ripemd160.c	\
	crypto/sha1.c	\
	crypto/sha2.c	\
	address.c	\
	addr_match.c	\
	aes_util.c	\
	base58.c	\
	bignum.c	\
	blkdb.c		\
	block.c		\
	blockfile.c	\
	bloom.c		\
	buffer.c	\
	buint.c		\
	checkpoints.c	\
	clist.c		\
	core.c		\
	coredefs.c	\
	cstr.c		\
	file_seq.c	\
	hashtab.c	\
	hdkeys.c	\
	hexcode.c	\
	key.c		\
	keyset.c	\
	keystore.c	\
	mbr.c		\
	memmem.c	\
	message.c	\
	parr.c		\
	script.c	\
	script_eval.c	\
	script_names.c	\
	script_sign.c	\
	serialize.c	\
	util.c		\
	utxo.c		\
	wallet.c

noinst_LTLIBRARIES= libbitcnet.la

libbitcnet_la_SOURCES=	\
	net/dns.c	\
	net/net.c	\
	net/netbase.c	\
	net/peerman.c

