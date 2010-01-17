AC_DEFUN([ERLANG_CHECK_EI],
[
dnl Begin check ei.h and ei library
  AC_ERLANG_CHECK_LIB(erl_interface)

  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"

  EI_LDFLAGS="-L$ERLANG_LIB_DIR_erl_interface/lib"
  EI_CFLAGS="-I$ERLANG_LIB_DIR_erl_interface/include"

  CPPFLAGS="$CPPFLAGS $EI_CFLAGS"
  LDFLAGS="$LDFLAGS $EI_LDFLAGS"

  AC_CHECK_HEADER([ei.h],,[dnl
    AC_MSG_ERROR([You need the ei.h header])])

  AC_CHECK_LIB([ei], [ei_decode_version], [EI_LIBS="-lei"], [dnl
    AC_MSG_ERROR([You need the ei library])])

  EI_LIBS="-lei"

  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"

  AC_SUBST(EI_CFLAGS)
  AC_SUBST(EI_LDFLAGS)
  AC_SUBST(EI_LIBS)
  dnl End check ei.h and ei library
]) # ERLANG_CHECK_EI
