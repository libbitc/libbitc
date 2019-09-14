SUBDIRS = secp256k1 libbitc.github.io
AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES = 	\
			cJSON/libcjson.la \
			libev/libev.la \
			lmdb/libraries/liblmdb/liblmdb.la

cJSON_libcjson_la_CFLAGS = -fPIC
cJSON_libcjson_ladir = cJSON
cJSON_libcjson_la_HEADERS = cJSON/cJSON.h
cJSON_libcjson_la_SOURCES = cJSON/cJSON.c

libev_libev_la_CFLAGS = -w -D 'EV_CONFIG_H "$(top_builddir)/../libbitc-config.h"'
libev_libev_ladir = libev
libev_libev_la_HEADERS =	\
			libev/ev.h \
			libev/event.h
libev_libev_la_SOURCES =	\
			libev/ev.c \
			libev/event.c

lmdb_libraries_liblmdb_liblmdb_la_CFLAGS = -W -Wall -Wno-unused-parameter   \
			-Wno-missing-field-initializers -Wno-format-extra-args \
			-Wno-missing-braces -Wbad-function-cast -pthread \
                        -Wno-implicit-fallthrough		       
lmdb_libraries_liblmdb_liblmdb_ladir = lmdb/libraries/liblmdb
lmdb_libraries_liblmdb_liblmdb_la_HEADERS =	\
			lmdb/libraries/liblmdb/lmdb.h	\
			lmdb/libraries/liblmdb/midl.h
lmdb_libraries_liblmdb_liblmdb_la_SOURCES = \
			lmdb/libraries/liblmdb/mdb.c	\
			lmdb/libraries/liblmdb/midl.c

EXTRA_DIST =	\
			cJSON/LICENSE \
			libev/LICENSE \
			libev/libev.m4 \
			libev/ev_vars.h \
			libev/ev_wrap.h \
			libev/ev_epoll.c \
			libev/ev_select.c \
			libev/ev_poll.c \
			libev/ev_kqueue.c \
			libev/ev_port.c \
			libev/ev_win32.c \
			lmdb/libraries/liblmdb/LICENSE
