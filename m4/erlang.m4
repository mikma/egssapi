dnl ERLANG_LIB_VER_SUBST=""
AC_DEFUN([AC_ERLANG_LIB_VER],
[AC_CACHE_CHECK([Erlang/OTP '$1' library version], [erlang_cv_lib_ver_$1],
   [if test "$ERLANG_LIB_VER_$1" = ""; then
       erlang_cv_lib_ver_$1=`echo "$ERLANG_LIB_DIR_$1"|sed -e "s/.*-\(.*\)/\1/"`
    fi])
AC_SUBST([ERLANG_LIB_VER_$1], [$erlang_cv_lib_ver_$1])
ERLANG_LIB_VER_SUBST="$ERLANG_LIB_VER_SUBST -e 's,[@]ERLANG_LIB_VER_$1[@],\$(ERLANG_LIB_VER_$1),g'"
AC_SUBST([ERLANG_LIB_VER_SUBST])
]) # AC_ERLANG_LIB_VER
