#                                               -*- Autoconf -*-
# autoconf.ac
# Copyright (C) 2007  Mikael Magnusson
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Process this file with autoconf to produce a configure script.

# Needs autoconf 2.59c for erlang support
AC_PREREQ(2.59c)
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
