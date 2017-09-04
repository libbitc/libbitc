AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS	=   -I$(top_srcdir)/include \
                -I$(top_srcdir)/include/bitc/net \
                -I$(top_srcdir)/external/secp256k1/include \
                -I$(top_srcdir)/external/secp256k1/contrib \
                -I$(top_srcdir)/external/cJSON

lib_LTLIBRARIES = libbitc.la

libbitc_la_LIBADD = @MATH_LIBS@ \
                    $(top_builddir)/external/secp256k1/libsecp256k1.la

libbitc_la_SOURCES = \
			crypto/fortuna.c    \
			crypto/hmac.c	\
			crypto/prng.c   \
			crypto/random.c     \
			crypto/rijndael.c   \
			crypto/ripemd160.c	\
			crypto/sha1.c	\
			crypto/sha2.c	\
			address.c	\
			addr_match.c	\
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
			log.c		\
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
			utxo.c

noinst_LTLIBRARIES = libbitcev.la libbitcnet.la libbitcwallet.la

libbitcev_la_CFLAGS = -w

libbitcev_la_SOURCES =	\
			net/ev.c	\
			net/event.c

libbitcnet_la_LIBADD = libbitcev.la

libbitcnet_la_SOURCES =	\
			net/dns.c	\
			net/net.c	\
			net/netbase.c	\
			net/peerman.c

libbitcwallet_la_LIBADD = $(top_builddir)/external/cJSON/libcjson.la

libbitcwallet_la_SOURCES =	\
			crypto/aes_util.c   \
			crypto/ctaes.c		\
			wallet/wallet.c

EXTRA_DIST =	\
			net/ev_epoll.c	\
			net/ev_poll.c	\
			net/ev_kqueue.c	\
			net/ev_port.c	\
			net/ev_select.c
