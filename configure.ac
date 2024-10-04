# Copyright (c) Paul Arthur MacIain
# See COPYING.

AC_INIT(miltertest, 1.0.0, simta@umich.edu)
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-xz])

AC_PREREQ(2.63)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) Paul Arthur MacIain])

# Check for programs
AC_PROG_CC
# autoconf 2.70 deprecated this, but it might still be necessary on old versions
m4_version_prereq([2.70], [:], [AC_PROG_CC_C99])

# Check for libraries
AC_SEARCH_LIBS([inet_pton], [nsl])
PKG_CHECK_MODULES([LIBLUA], [lua])
AX_CHECK_LIBRARY([LIBMILTER], [libmilter/mfapi.h], [milter], [], [AC_MSG_ERROR([Unable to find libmilter])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
