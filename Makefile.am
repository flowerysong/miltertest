# Copyright (c) Paul Arthur MacIain
# Copyright (c) 2009-2020 The Trusted Domain Project.
# See COPYING.

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CPPFLAGS = @LIBMILTER_CPPFLAGS@ @LIBLUA_CFLAGS@
miltertest_LDFLAGS = @LIBMILTER_LDFLAGS@ @LIBLUA_CFLAGS@
miltertest_LDADD = -lmilter @LIBLUA_LIBS@

man_MANS = miltertest.8

EXTRA_DIST = miltertest.8
