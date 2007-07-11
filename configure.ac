#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(egssapi, 0.1, [Mikael Magnusson <mikma@users.sourceforge.net>])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

dnl AM_CONFIG_HEADER([config.h])

AC_ARG_VAR([ERL_FLAGS], [Erlang/OTP emulator flags [none]])dnl

dnl Checks for libraries.
AC_ARG_WITH([kerberos5],
    [AS_HELP_STRING([--with-kerberos5=PATH], [Use MIT kerberos5 library [default=yes]])],
    [], [with_kerberos5="yes"])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_ERLANG_NEED_ERLC
AC_ERLANG_PATH_ERL
AC_ERLANG_SUBST_INSTALL_LIB_DIR
AC_ERLANG_CHECK_LIB(kernel)
AC_ERLANG_CHECK_LIB(stdlib)
AC_ERLANG_LIB_VER(kernel)
AC_ERLANG_LIB_VER(stdlib)

AC_CHECK_HEADER([ei.h],,[dnl
    AC_MSG_ERROR([You need the ei.h header])])

AC_CHECK_LIB([ei], [ei_decode_version], EI_LIBS="-lei", [dnl
    AC_MSG_ERROR([You need the ei library])])

save_CPPFLAGS=$CPPFLAGS
save_LDFLAGS=$LDFLAGS
AC_CHECK_KRB5
CPPFLAGS=$save_CPPFLAGS
LDFLAGS=$save_LDFLAGS

AC_SUBST(K5CFLAGS)
AC_SUBST(K5LIBS)
AC_SUBST(ERL_FLAGS)
AC_SUBST(EI_LIBS)

AC_CONFIG_FILES([
		 Makefile
		 egssapi/Makefile
		 egssapi/c_src/Makefile
		 egssapi/src/Makefile
		])

AC_OUTPUT
