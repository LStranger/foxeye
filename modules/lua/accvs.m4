dnl Check if we have liblua so we can compile the module
AC_CHECK_PROGS(ac_have_luaconfig, [lua-config lua-config50 lua-config51], no)

if test $ac_have_luaconfig = no; then
dnl    AC_HAVE_LIBRARY(lua)
    AC_CHECK_PROGS(ac_have_pkgconfig, pkg-config, no)
    if test $ac_have_pkgconfig = no; then
	AC_HAVE_LIBRARY(lua,[AC_DEFINE(HAVE_LIBLUA)
	    LUA_LIBS=-llua], [LUA_LIBS=
	])
    else
	AC_MSG_CHECKING(for lua config)
	for lualibver in lua lua51 lua50 lua-5.1 lua-5.0; do
	    if ! test $LUA_INCLUDES; then
		if $ac_have_pkgconfig --exists $lualibver 2>/dev/null; then
		    LUA_INCLUDES="`$ac_have_pkgconfig --cflags $lualibver`"
		    LUA_LIBS="`$ac_have_pkgconfig --libs $lualibver`"
		    AC_MSG_RESULT($lualibver: $LUA_LIBS)
		    AC_DEFINE(HAVE_LIBLUA)
		fi
	    fi
	done
	if ! test $LUA_INCLUDES; then
	    AC_MSG_RESULT(none found)
	fi
    fi
else
    AC_DEFINE([HAVE_LIBLUA], 1, [Define to 1 if you have the `lua' library.])
    LUA_INCLUDES="`$ac_have_luaconfig --include`"
    LUA_LIBS="`$ac_have_luaconfig --libs`"
fi

if test -n "${LUA_INCLUDES}"; then
    CPPFLAGS="${LUA_INCLUDES} ${CPPFLAGS}"
fi

if test -n "${LUA_LIBS}"; then
    MODLIBS="MODLIBS_lua=\"${LUA_LIBS}\" ${MODLIBS}"
fi

if test x$ac_cv_lib_lua != xno; then
    AC_MSG_CHECKING([for version 5.1 of liblua])
    AC_TRY_COMPILE([#include <lauxlib.h>], [luaL_Reg *A;],
	[AC_DEFINE(HAVE_LIBLUA51, 1, [Define to 1 if you have lua 5.1])
	AC_MSG_RESULT(yes)], [AC_MSG_RESULT(no)])
fi

