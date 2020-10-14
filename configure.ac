AC_INIT([kernel-fuzzer], [1.0])
AM_INIT_AUTOMAKE([1.14 subdir-objects])

AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_HEADERS(config.h)

AC_CANONICAL_HOST
AC_PROG_CC
AM_SANITY_CHECK

PKG_CHECK_MODULES([VMI], [libvmi],[],[AC_MSG_ERROR(LibVMI not found. Install missing package and re-run)])
PKG_CHECK_MODULES([CAPSTONE], [capstone],[],[AC_MSG_ERROR(Capstone not found. Install missing package and re-run)])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
