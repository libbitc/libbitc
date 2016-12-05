
AM_CPPFLAGS = -I$(top_srcdir)/include \
            -I$(top_srcdir)/external/secp256k1/include

bin_PROGRAMS	= brd bitsy blkscan blkstats rawtx

brd_SOURCES	=	\
		brd.c	\
		brd.h

brd_LDADD	= $(top_builddir)/lib/libbitc.la \
		$(top_builddir)/lib/libbitcnet.la \
		@GMP_LIBS@ @EVENT_LIBS@

bitsy_SOURCES =	\
	bitsy.c	\
	bitsy.h	\
	wallet.c wallet.h

bitsy_LDADD	= $(top_builddir)/lib/libbitc.la \
		$(top_builddir)/lib/libbitcnet.la \
		$(top_builddir)/lib/libbitcwallet.la \
		@GMP_LIBS@ @ARGP_LIBS@ \
		@EVENT_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= $(top_builddir)/lib/libbitc.la \
		  @GMP_LIBS@ @ARGP_LIBS@
blkstats_LDADD	= $(top_builddir)/lib/libbitc.la \
		  @GMP_LIBS@ @ARGP_LIBS@
rawtx_LDADD	= $(top_builddir)/lib/libbitc.la \
		  @GMP_LIBS@ @ARGP_LIBS@ @JANSSON_LIBS@
