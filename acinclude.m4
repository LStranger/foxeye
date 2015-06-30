dnl    This file is free software; you can redistribute it and/or
dnl    modify it under the terms of the GNU Library General Public
dnl    License as published by the Free Software Foundation; either
dnl    version 2 of the License, or (at your option) any later version.

dnl    This library is distributed in the hope that it will be useful,
dnl    but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl    Library General Public License for more details.

dnl    You should have received a copy of the GNU Library General Public License
dnl    along with this library; see the file COPYING.LIB.  If not, write to
dnl    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
dnl    Boston, MA 02110-1301, USA.

dnl ------------------------------------------------------------------------
dnl Find a file (or one of more files in a list of dirs)
dnl ------------------------------------------------------------------------
dnl I stole this from the KDE
dnl

AC_DEFUN([AC_FIND_FILE],
[
$3=NO
for i in $2;
do
  for j in $1;
  do
    if test -r "$i/$j"; then
      $3=$i
      break 2
    fi
  done
done
])

dnl ------------------------------------------------------------------------
dnl Project-specific set of tests
dnl ------------------------------------------------------------------------

AC_DEFUN([AC_CHECK_LDFLAG],
[AC_CACHE_CHECK([whether the target compiler accepts $2], $1,
    [$1=no
    echo 'int main(){return 0;}' > conftest.c
    if test -z "`${CC} $2 -o conftest conftest.c 2>&1`"; then
	$1=yes
    else
	$1=no
    fi
    rm -f conftest*
    ])
if test x${$1} = xyes; then $3="$2 ${$3}"; fi
])

AC_DEFUN([AC_CHECK_ICONV],
[AC_MSG_CHECKING(for iconv paths)
ac_iconv_libpath=
dnl Reusing AM_ICONV --with-libiconv-prefix variable
case "x$with_libiconv_prefix" in
dnl --without-libiconv-prefix
xno)
    AC_MSG_RESULT(disabled)
    dnl AM_ICONV will check it
    am_cv_func_iconv=no
    ac_iconv_libpath=no
    ;;
dnl Neither --with-libiconv-prefix nor --without-libiconv-prefix given
x)
    ac_iconv_bin=
    dnl check for default includes first...
    fe_save_CPPFLAGS="$CPPFLAGS"
    fe_save_LIBS="$LIBS"
    AC_TRY_CPP([#include <iconv.h>],
	ac_iconv_includes=,
	[dnl not found, now try to find...
	AC_TRY_CPP([#include "/usr/local/include/iconv.h"],
	    ac_iconv_includes=-I/usr/local/include,
	    [ac_iconv_includes=no
	    AC_MSG_RESULT(no header found)
    ])])
    if test "x$ac_iconv_includes" != xno ; then
	CPPFLAGS="$ac_iconv_includes ${CPPFLAGS}"
	dnl check if we need -liconv...
	AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], [ac_iconv_libpath=],
		[dnl so far we need -liconv
		LIBS="${LIBS} -liconv"
		dnl check for default library first...
		AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], [ac_iconv_libpath=],
		    [dnl not found, now try to find...
		    LIBS="${LIBS} -L/usr/local/lib"
		    AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], [ac_iconv_libpath="/usr/local/lib"],
		    [ac_iconv_libpath=no
		    AC_MSG_RESULT(no library found)
	])])])
    fi
    CPPFLAGS="$fe_save_CPPFLAGS"
    LIBS="$fe_save_LIBS"
    ;;
xyes)
    ;;
dnl Absolute paths
x/*)
    ac_iconv_bin="$with_libiconv_prefix/bin/iconv"
#    ac_iconv_includes="-I$with_libiconv_prefix/include"
    ;;
dnl Relative paths
*)
    with_libiconv_prefix="`pwd`/$with_libiconv_prefix"
    ac_iconv_bin="$with_libiconv_prefix/bin/iconv"
#    ac_iconv_includes="-I$with_libiconv_prefix/include"
    ;;
esac

#eval "$ac_cv_have_iconv"

if test "x$ac_iconv_libpath" = xno -o "x$ac_iconv_includes" = xno ; then
    dnl AM_ICONV will check it
    am_cv_func_iconv=no
else
    AC_MSG_RESULT(ok)
    fe_save_CPPFLAGS="$CPPFLAGS"
    fe_save_LIBS="$LIBS"
    CPPFLAGS="$ac_iconv_includes ${CPPFLAGS}"
    if test "x$ac_iconv_libpath" != x; then
	LIBS="-L$ac_iconv_libpath ${LIBS}"
    fi
    dnl AM_ICONV will set LIBICONV to library and path if needed
    AM_ICONV
    ac_iconv_includes="$ac_iconv_includes $INCICONV"
    INCICONV=
    LIBS="$fe_save_LIBS"
    CPPFLAGS="$fe_save_CPPFLAGS"
    if test "$am_cv_func_iconv" = yes; then
	dnl Well, usable iconv found
#	if test "x$ac_iconv_alib" != x; then
#	    STATICLIBS="${STATICLIBS} $ac_iconv_alib"
#	fi
	if test "x$ac_iconv_libpath" != x ; then
	    LDFLAGS="-L$ac_iconv_libpath -R$ac_iconv_libpath ${LDFLAGS}"
	fi

	AC_MSG_CHECKING(for russian translit)
	if test "x$ac_iconv_bin" = x; then
	    ac_iconv_bin=iconv
	fi
	dnl set LC_ALL due to configure might set it to C
	dnl if test x`echo -n проба|LC_ALL= LC_CTYPE=uk_UA.KOI8-U $ac_iconv_bin -t ascii//translit 2>/dev/null` != xproba; then
	if test x`echo п©я─п╬п╠п╟|LC_ALL= LC_CTYPE=uk_UA.UTF-8 $ac_iconv_bin -t ascii//translit 2>/dev/null` != xproba; then
	    AC_MSG_RESULT(no)
	    AC_MSG_WARN(Your iconv doesn't support Cyrillic translit!)
	else
	    AC_MSG_RESULT(yes)
	    AC_DEFINE([HAVE_CYRILLIC_TRANSLIT], 1,
		    [Define to 1 if your iconv can do cyrillic transliteration.])
	fi
	AC_MSG_CHECKING(for order of //ignore and //translit)
	if test x`echo proba|$ac_iconv_bin -t ascii//translit//ignore 2>/dev/null` != xproba; then
	    AC_MSG_RESULT(//ignore//translit)
	    AC_DEFINE([TRANSLIT_IGNORE], ["//IGNORE//TRANSLIT"],
			[Order ot //ignore and //translit on iconv setup.])
	else
	    AC_MSG_RESULT(//translit//ignore)
	    AC_DEFINE([TRANSLIT_IGNORE], ["//TRANSLIT//IGNORE"])
	fi

	dnl it will be included first to avoid possible conflicts
	ICONV_INCLUDES="$ac_iconv_includes"
	AC_SUBST(ICONV_INCLUDES)
    fi
fi
])

AC_DEFUN([AC_CHECK_IPV6],
[dnl Bit of borrowed from rusnet-irc configure script
AC_ARG_ENABLE(ipv6,
    [  --enable-ipv6           enables IPv6 connections support],
    [], [enableval=no])
if test "x$enableval" = xyes; then
    AC_CACHE_CHECK([IPv6 system type], fe_cv_v6type,
    [
	fe_cv_v6type=
	dnl check for posix type support
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <unistd.h>
#include <netinet/in.h>]], [[struct in6_addr addr]])],
			  [fe_cv_v6type=native])

	dnl check for linux specific header/library
	if test "x$fe_cv_v6type" = x; then
	    if test -d /usr/inet6; then
		AC_EGREP_CPP(yes, [
#include "/usr/inet6/include/netinet/in.h"
#ifdef _INET6APPS_NETINET_IN_H
yes
#endif], fe_cv_v6type=linux)
	    fi
	fi

	if test "x$fe_cv_v6type" = x; then
	    fe_cv_v6type=unknown
	fi
    ])

    dnl eventually update LIBS
    case $fe_cv_v6type in
    unknown)
	AC_MSG_WARN([Cannot support IPv6 on this system, disabling it.])
	;;
    linux)
	LIBS="-L/usr/inet6/lib -linet6 $LIBS"
	CFLAGS="$CFLAGS -I/usr/inet6/include"
	AC_DEFINE([ENABLE_IPV6], [1])
	;;
    *)
	AC_DEFINE([ENABLE_IPV6], [1], [Define to enable IPv6 support.])
	;;
    esac
fi
])

AC_DEFUN([AC_CHECK_LIBIDN],
[AC_ARG_WITH(libidn, AC_HELP_STRING([--with-libidn=[DIR]],
                                     [Support IDN (needs GNU Libidn)]),
	libidn=$withval, libidn=yes)
    if test "$libidn" != "no" ; then
	if test "$libidn" != "yes" ; then
	    dnl check if supplied path gives valid result
	    save_LDFLAGS="${LDFLAGS}"
	    save_CPPFLAGS="${CPPFLAGS}"
	    LDFLAGS="${LDFLAGS} -L$libidn/lib"
	    CPPFLAGS="${CPPFLAGS} -I$libidn/include"
	    AC_CHECK_HEADER(idna.h,
			AC_CHECK_LIB(idn, stringprep_check_version,
				    [LIBIDN_CFLAGS=-I$libidn/include
				     LIBIDN_LIBS="-L$libidn/lib -lidn"],
				    libidn=no),
			[libidn=no])
	    LDFLAGS="save_LDFLAGS"
	    CPPFLAGS="save_CPPFLAGS"
	else
	    dnl check with pkg-config first
	    PKG_CHECK_MODULES(LIBIDN, libidn >= 0.0.0, [libidn=yes], [libidn=no])
	    dnl check for default paths if not found by pkg-config
	    if test "$libidn" != "yes" ; then
		AC_CHECK_HEADER(idna.h,
			    AC_CHECK_LIB(idn, stringprep_check_version,
					[LIBIDN_LIBS="-lidn"], [libidn=no]),
			    [libidn=no])
	    fi
	fi
    fi
    if test "$libidn" != "no" ; then
	AC_DEFINE(HAVE_LIBIDN, 1, [Define to 1 if you want IDN support.])
    fi
    AC_MSG_CHECKING([if Libidn should be used])
    AC_MSG_RESULT($libidn)
])

dnl autoconf prior to 2.60 doesn't have this macro
m4_ifndef([AC_PROG_MKDIR_P], [
    AC_DEFUN([AC_PROG_MKDIR_P], [
AC_MSG_CHECKING([for a thread-safe mkdir -p])
if test -z "$MKDIR_P"; then
  AC_CACHE_VAL([ac_cv_path_mkdir], [
      for ac_prog in mkdir gmkdir; do
         for ac_exec_ext in '' $ac_executable_extensions; do
           case `"$as_dir/$ac_prog$ac_exec_ext" --version 2>&1` in #(
             'mkdir (GNU coreutils) '* | \
             'mkdir (coreutils) '* | \
             'mkdir (fileutils) '4.1*)
               ac_cv_path_mkdir=$as_dir/$ac_prog$ac_exec_ext
               break 3;;
           esac
         done
       done])
  if test "${ac_cv_path_mkdir+set}" = set; then
    MKDIR_P="$ac_cv_path_mkdir -p"
  else
    # As a last resort, use the slow shell script.  Don't cache a
    # value for MKDIR_P within a source directory, because that will
    # break other packages using the cache if that directory is
    # removed, or if the value is a relative name.
    test -d ./--version && rmdir ./--version
    dnl automake prior to 1.13 use mkinstalldirs instead of install_sh -d
    if test -n "$ac_aux_dir" && test -x "$ac_aux_dir/mkinstalldirs"; then
      MKDIR_P="$ac_aux_dir/mkinstalldirs"
    elif test -x ./mkinstalldirs; then
      MKDIR_P="\$(top_srcdir)/mkinstalldirs"
    else
      MKDIR_P="$ac_install_sh -d"
    fi
  fi
fi
AC_SUBST([MKDIR_P])
AC_MSG_RESULT([$MKDIR_P])
])])
