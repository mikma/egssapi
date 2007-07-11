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

AC_SUBST(ERL_FLAGS)

AC_CONFIG_FILES([
		 Makefile
		 egssapi/Makefile
		 egssapi/c_src/Makefile
		 egssapi/src/Makefile
		])

AC_OUTPUT
