# Copyright (c) 2009-2020 The Trusted Domain Project.
# See COPYING.

bin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CPPFLAGS = $(LIBMILTER_INCDIRS) $(LIBLUA_INCDIRS)
miltertest_LDFLAGS = $(LIBLUA_LIBDIRS)
miltertest_LDADD = $(LIBLUA_LIBS) $(LIBNSL_LIBS)

man_MANS = miltertest.8

EXTRA_DIST = miltertest.8
