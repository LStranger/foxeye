dnl Checks for Tcl.
AC_ARG_WITH(tcl,
    [  --with-tcl=PATH         where the root of Tcl is installed],
    [  fe_tcl_includes="$withval"/include
       fe_tcl_libdir="$withval"/lib
       fe_tcl_library=tcl
    ])

if test ! "x$fe_tcl_includes" = x; then
    unset fe_cv_have_tcl
fi

AC_MSG_CHECKING(for Tcl)
AC_CACHE_VAL(fe_cv_have_tcl,
[# check for default first...
    fe_save_LDFLAGS="${LDFLAGS}"
    if test "x$fe_tcl_libdir" = x; then
	fe_tcl_libdir=default
	fe_tcl_library=tcl
    else
	fe_try_libs=" -L${fe_tcl_libdir}"
    fi
    if test "x$fe_tcl_includes" = x; then
	fe_try_incs="<tcl.h>"
	fe_tcl_includes=default
    else
	fe_try_incs="\"$fe_tcl_includes/tcl.h\""
    fi
    LDFLAGS="${LDFLAGS}${fe_try_libs} -ltcl"
    AC_TRY_LINK([#include $fe_try_incs], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_cv_have_tcl="have_tcl=yes \
    fe_tcl_includes=$fe_tcl_includes fe_tcl_libdir=$fe_tcl_libdir \
    fe_tcl_library=$fe_tcl_library"],
    [# not found, now try to find...
	AC_TRY_CPP([#include <tcl.h>], [fe_tcl_includes=default
	    fe_try_incs="<tcl.h>"],
	    [tcl_incdirs="$fe_tcl_includes $prefix/include $prefix/tcl/include /usr/local/include /usr/local/include/tcl* /usr/local/pkgs/tcl/include /usr/include/tcl"
	    AC_FIND_FILE(tcl.h, $tcl_incdirs, tcl_incdir)
	    fe_tcl_includes="$tcl_incdir"
	    fe_try_incs="\"$tcl_incdir/tcl.h\""
	])
	tcl_libdir=NO
	tcl_library=tcl
	tcl_libdirs="$fe_tcl_libraries $prefix/lib $prefix/tcl/lib /usr/local/lib /usr/local/lib/tcl /usr/local/pkgs/tcl/lib /usr/lib /usr/lib/tcl"
	for dir in $tcl_libdirs; do
	    try="ls -1 $dir/libtcl*"
	    if test "x`eval $try 2>/dev/null`" != "x"; then
		    tcl_library=`eval $try | head -1 | sed 's/^.*lib//' | sed 's/\..*$//'`;
		    tcl_libdir=$dir; break
		else echo "tried $dir" >&AC_FD_CC ; fi
	done
	fe_tcl_libdir="$tcl_libdir"
	fe_tcl_library="$tcl_library"
	if test "$fe_tcl_includes" = NO || test "$fe_tcl_libdir" = NO; then
	    fe_cv_have_tcl="have_tcl=no"
	else
	LDFLAGS="${fe_save_LDFLAGS} -L${fe_tcl_libdir} -l${fe_tcl_library}"
	AC_TRY_LINK([#include $fe_try_incs], [Tcl_Interp *interp;

Tcl_AppendElement(interp, NULL);
], [fe_cv_have_tcl="have_tcl=yes \
	fe_tcl_includes=$fe_tcl_includes fe_tcl_libdir=$fe_tcl_libdir \
	fe_tcl_library=$fe_tcl_library"],
	    [fe_cv_have_tcl="have_tcl=no"
	    fe_tcl_libdir=NO
	]); fi
    ])
    LDFLAGS="${fe_save_LDFLAGS}"
]) dnl
eval "$fe_cv_have_tcl"

if test "$have_tcl" = no; then
    AC_MSG_RESULT([not found!])
else
    if test "$fe_tcl_libdir" = default; then AC_MSG_RESULT([$fe_tcl_libdir])
    else AC_MSG_RESULT([${fe_tcl_libdir}/lib${fe_tcl_library}]); fi
    AC_DEFINE(HAVE_TCL, 1, [Define to 1 if you have a Tcl])
    if ! test "$fe_tcl_includes" = default; then CPPFLAGS="-I${fe_tcl_includes} ${CPPFLAGS}"; fi
    if ! test "$fe_tcl_libdir" = default; then LDFLAGS="-L${fe_tcl_libdir} ${LDFLAGS}"; fi
    dnl now i want check for tcl version
    AC_CHECK_LIB(${fe_tcl_library}, Tcl_CreateObjCommand, [
	AC_DEFINE(HAVE_TCL8X, 1, [Define to 1 for Tcl 8.x because it can work much faster])
    ])
    dnl check for multithreaded tcl
    AC_CHECK_LIB(${fe_tcl_library}, Tcl_MutexFinalize, [
	AC_DEFINE(HAVE_TCL_MULTITHREAD, 1, [Define to 1 if Tcl interpreter is multithreaded])
    ])
    AC_CHECK_FUNCS(Tcl_SetSystemEncoding)
    AC_CHECK_FUNCS(Tcl_EvalObjv)
    dnl only for module
    LD="${LD} -l${fe_tcl_library}"
fi

