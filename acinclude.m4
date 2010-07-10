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
dnl    the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
dnl    Boston, MA 02111-1307, USA.

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

AC_DEFUN([AC_SET_NODEBUG],
[
test "$LDFLAGS" = "" && LDFLAGS="-s"
test "$CFLAGS" = "" || CFLAGS=`echo "$CFLAGS" | sed 's/[-]p\?g[ ]*//g'`
])

AC_DEFUN([AC_CHECK_DEBUG],
[
AC_ARG_ENABLE(debug,
    [  --enable-debug          creates debugging code],
[
if test "$enableval" = "no"; then
  AC_SET_NODEBUG
else
  test "$CFLAGS" = "" || CFLAGS=`echo "$CFLAGS" | sed 's/[-]O2/-O0/g'`
fi
],
AC_SET_NODEBUG)
])

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
AC_CACHE_VAL(ac_cv_have_iconv,
    [dnl check for default includes first...
    fe_save_CPPFLAGS="$CPPFLAGS"
    fe_save_LIBS="$LIBS"
    AC_TRY_CPP([#include <iconv.h>],
	ac_iconv_includes=,
	[dnl not found, now try to find...
	CPPFLAGS="-I/usr/local/include $CPPFLAGS"
	AC_TRY_CPP([#include <iconv.h>],
	    ac_iconv_includes=/usr/local/include,
	    ac_iconv_includes=no
    )])
    if test "x$ac_iconv_includes" != xno ; then
	dnl check if we need -liconv...
	AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], ac_iconv_libs=,
	    [dnl check for default library first...
		LIBS="${LIBS} -liconv"
		AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], ac_iconv_libs=,
		    [dnl not found, now try to find...
		    LIBS="${LIBS} -L/usr/local/lib"
		    AC_TRY_LINK([#include <iconv.h>], [
iconv_open("","");
], ac_iconv_libs=/usr/local/lib,
		    ac_iconv_libs=no
	)])])
    fi
    LIBS="$fe_save_LIBS"
    CPPFLAGS="$fe_save_CPPFLAGS"
    ac_cv_have_iconv="ac_iconv_includes=$ac_iconv_includes ac_iconv_libs=$ac_iconv_libs"
])

eval "$ac_cv_have_iconv"

if test "x$ac_iconv_libs" = xno -o "x$ac_iconv_includes" = xno ; then
    AC_MSG_RESULT(fault)
else
    AC_MSG_RESULT(ok)
    if test "x$ac_iconv_includes" != x ; then
	CPPFLAGS="-I$ac_iconv_includes ${CPPFLAGS}"
    fi
    if test "x$ac_iconv_libs" != x ; then
	LDFLAGS="-L$ac_iconv_libs ${LDFLAGS}"
    fi

    AC_MSG_CHECKING(for russian translit)
    dnl set LC_ALL due to configure might set it to C
    if test x`echo проба|LC_ALL=ru_RU.KOI8-R iconv -f koi8-r -t ascii//translit 2>/dev/null` != xproba; then
	AC_MSG_RESULT(no)
	AC_MSG_WARN(Your iconv doesn't support Cyrillic translit!)
    else
	AC_MSG_RESULT(yes)
fi
fi
])
