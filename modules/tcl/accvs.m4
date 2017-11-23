dnl Checks for Tcl.
AC_ARG_WITH(tcl,
    [  --with-tcl[[=PATH]]       where the root of Tcl is installed],
    [  fe_tcl_with="$withval"
    ], [fe_tcl_with=yes
    ])

if test ! "x$fe_tcl_includes" = x; then
    unset fe_cv_have_tcl
fi

AC_CACHE_VAL(fe_cv_have_tcl,
[# check for Tcl config script first
 AC_MSG_CHECKING(for Tcl config)
 if test "$fe_tcl_with" = no; then
  AC_MSG_RESULT([not requested])
  fe_cv_have_tcl="have_tcl=no"
 else
  if test "$fe_tcl_with" = yes; then
    fe_tcl_with=
  fi
  fe_tcl_libs=no TCL_LIB_SPEC=no TCL_INCLUDE_SPEC=no
  tcl_config_dirs="$fe_tcl_with $prefix/lib/tcl* /usr/lib/tcl* /usr/local/lib/tcl*"
  for dir in $tcl_config_dirs; do
    if test -f $dir/tclConfig.sh; then
	. $dir/tclConfig.sh
	AC_MSG_CHECKING([$dir/tclConfig.sh])
	if test x"$TCL_LIB_SPEC" = xno || test x"$TCL_INCLUDE_SPEC" = xno; then
	    dnl malformed config
	    TCL_LIB_SPEC=no TCL_INCLUDE_SPEC=no
	    AC_MSG_RESULT([invalid])
	    continue
	fi
	AC_MSG_RESULT([fine])
	fe_tcl_libs="$TCL_LIB_SPEC $TCL_DL_LIBS"
	fe_tcl_includes="$TCL_INCLUDE_SPEC"
	break
    fi
  done
  if test x"$fe_tcl_libs" != xno; then
    fe_cv_have_tcl="have_tcl=yes \
	fe_tcl_includes=\"$fe_tcl_includes\" fe_tcl_libs=\"$fe_tcl_libs\""
  else
    dnl check for default then...
    AC_MSG_RESULT([none working])
    AC_MSG_CHECKING([for Tcl headers])
    fe_tcl_save_LIBS="${LIBS}"
    dnl finding includes - default first, then paths
    LIBS="${LIBS} -ltcl"
    AC_TRY_LINK([#include <tcl.h>], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_cv_have_tcl="have_tcl=yes fe_tcl_includes=default fe_tcl_libs=\"-ltcl\""
	AC_MSG_RESULT([defaults])],
	[# not found, now try to find...
        AC_TRY_CPP([#include <tcl.h>], [fe_tcl_includes=default
	    fe_try_incs="<tcl.h>"],
            [fe_tcl_includes=no
		tcl_incdirs="$fe_tcl_with/include $prefix/include \
		$prefix/tcl/include /usr/local/include /usr/local/include/tcl* \
		/usr/local/pkgs/tcl/include /usr/include/tcl"
	    tcl_incdir=
	    AC_FIND_FILE(tcl.h, $tcl_incdirs, tcl_incdir)
	    if test x"$tcl_incdir" != x; then
		fe_tcl_includes="-I$tcl_incdir"
		fe_try_incs="\"$tcl_incdir/tcl.h\""
	    fi
        ])
	if test "$fe_tcl_includes" == no; then
	    AC_MSG_RESULT([not found])
	else
	    fe_tcl_incdir=`echo $fe_tcl_includes|sed s/-I//`
	    AC_MSG_RESULT($fe_tcl_incdir)
	    AC_MSG_CHECKING([for Tcl libraries])
	    dnl header possibly found, trying library
	    fe_tcl_libs=none
	    tcl_libdirs="default ${fe_tcl_with}/lib $prefix/lib \
		$prefix/tcl/lib /usr/local/lib /usr/local/lib/tcl \
		/usr/local/pkgs/tcl/lib /usr/lib /usr/lib/tcl*"
	    for dir in $tcl_libdirs; do
		if test $dir = default; then
		    tcl_library=tcl
		    tcl_lddir=
		else
		    try="ls -1 $dir/libtcl*.so*"
		    if test "x`eval $try 2>/dev/null`" = "x"; then
			continue
		    fi
		    tcl_library=`eval $try | tail -1 | sed -e 's/^.*lib//' -e 's/\.so.*$//'`
		    if test "$fe_cv_static" = yes; then
			tcl_lddir="-L$dir "
		    else
			tcl_lddir="-R$dir -L$dir "
		    fi
		fi
		LIBS="${fe_tcl_save_LIBS} ${tcl_lddir}-l${tcl_library}"
		AC_TRY_LINK([#include $fe_try_incs], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_tcl_libs="${tcl_lddir}-l${tcl_library}"
		    fe_cv_have_tcl="have_tcl=yes fe_tcl_libs=\"$fe_tcl_libs\" \
		    fe_tcl_includes=\"$fe_tcl_includes\""], [
		    dnl try -lm for it, it could want it
		    LIBS="$LIBS -lm"
		    AC_TRY_LINK([#include $fe_try_incs], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_tcl_libs="${tcl_lddir}-l${tcl_library} -lm"
			fe_cv_have_tcl="have_tcl=yes fe_tcl_libs=\"$fe_tcl_libs\" \
			fe_tcl_includes=\"$fe_tcl_includes\""], [
			dnl also try -ldl for it, it could want it too
			LIBS="$LIBS -ldl"
			AC_TRY_LINK([#include $fe_try_incs], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_tcl_libs="${tcl_lddir}-l${tcl_library} -lm -ldl"
			    fe_cv_have_tcl="have_tcl=yes fe_tcl_libs=\"$fe_tcl_libs\" \
			    fe_tcl_includes=\"$fe_tcl_includes\""
		])])])
		if test "$fe_tcl_libs" != none; then
		    dnl library found
		    break
		fi
	    done
	    AC_MSG_RESULT([$fe_tcl_libs])
	fi
	if test "$fe_tcl_includes" = no || test "$fe_tcl_libs" = none; then
	    fe_cv_have_tcl="have_tcl=no"
	fi
    ])
    LIBS="${fe_tcl_save_LIBS}"
  fi
 fi
])
eval "$fe_cv_have_tcl"

if test "$have_tcl" != no; then
    AC_DEFINE(HAVE_TCL, 1, [Define to 1 if you have the Tcl interpreter library.])
    if test "$fe_tcl_includes" != default; then
	CPPFLAGS="${fe_tcl_includes} ${CPPFLAGS}"
    fi
    if test "$fe_cv_static" = yes; then
	STATICLIBS="${fe_tcl_libs} ${STATICLIBS}"
    else
	MODLIBS="MODLIBS_tcl=\"${fe_tcl_libs}\" ${MODLIBS}"
    fi
    dnl now i want check for tcl version
    fe_tcl_save_LIBS="${LIBS}"
    fe_tcl_save_LDFLAGS="${LDFLAGS}"
    LDFLAGS=
    LIBS="$fe_tcl_libs $LIBS"
    try_lib=`echo $fe_tcl_libs | sed -e 's/^.*-ltcl/tcl/' -e 's/ .*//'`
    AC_SEARCH_LIBS(Tcl_CreateObjCommand, [$try_lib], [
	AC_DEFINE(HAVE_TCL8X, 1, [Define to 1 if you have the Tcl version 8.0 or above.])
    ])
    dnl check for multithreaded tcl
    AC_SEARCH_LIBS(Tcl_MutexFinalize, [$try_lib], [
	AC_DEFINE(HAVE_TCL_MULTITHREAD, 1, [Define to 1 if your Tcl interpreter supports mutexes.])
    ])
    dnl check for some functions (8.1+)
    AC_CHECK_FUNCS(Tcl_SetSystemEncoding)
    AC_CHECK_FUNCS(Tcl_EvalObjv)
    LIBS="${fe_tcl_save_LIBS}"
    LDFLAGS="${fe_tcl_save_LDFLAGS}"
fi
AC_MSG_CACHE_ADD([Tcl language support], [${have_tcl:-failed}])

