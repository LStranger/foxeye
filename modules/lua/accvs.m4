dnl Check if we have liblua so we can compile the module
AC_CHECK_PROGS(ac_have_luaconfig, [lua-config lua-config50 lua-config51], no)

if test "$ac_have_luaconfig" = no; then
dnl    AC_HAVE_LIBRARY(lua)
    AC_CHECK_PROGS(ac_have_pkgconfig, [pkg-config], no)
    if test "$ac_have_pkgconfig" = no; then
	AC_HAVE_LIBRARY(lua, [AC_DEFINE(HAVE_LIBLUA)
	    LUA_LIBS=-llua], [LUA_LIBS=
	])
    else
	AC_MSG_CHECKING(for lua config)
	for lualibver in lua lua53 lua5.3 lua-5.3 lua52 lua5.2 lua-5.2 lua51 lua5.1 lua-5.1 lua50 lua5.0 lua-5.0; do
		if $ac_have_pkgconfig --exists $lualibver 2>/dev/null; then
		    LUA_INCLUDES="`$ac_have_pkgconfig --cflags $lualibver`"
		    if test "$fe_cv_static" = yes; then
			LUA_LIBS="`$ac_have_pkgconfig --libs --static $lualibver`"
		    else
			LUA_LIBS="`$ac_have_pkgconfig --libs $lualibver`"
		    fi
		    AC_MSG_RESULT($lualibver: $LUA_LIBS)
		    AC_DEFINE(HAVE_LIBLUA)
		    break
		fi
	done
	if test -z "$LUA_LIBS"; then
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
    if test "$fe_cv_static" = yes; then
	STATICLIBS="${LUA_LIBS} ${STATICLIBS}"
    else
	dnl add rpath in any case
	case "$LUA_LIBS" in
	    *-L*)
		fe_cv_lua_rpath=" `echo $LUA_LIBS | sed -e 's/.*-L/-R/' -e 's/ .*$//'`"
		;;
	    *)
		fe_cv_lua_rpath=
		;;
	esac
	MODLIBS="MODLIBS_lua=\"${LUA_LIBS}${fe_cv_lua_rpath}\" ${MODLIBS}"
    fi
fi

if test x$ac_cv_lib_lua != xno; then
    AC_MSG_CHECKING([for version 5.1 of liblua])
    AC_TRY_COMPILE([#include <lauxlib.h>], [luaL_Reg *A;],
	[AC_DEFINE(HAVE_LIBLUA51, 1, [Define to 1 if you have the Lua version 5.1 or above.])
	AC_MSG_RESULT(yes)], [AC_MSG_RESULT(no)])
fi

