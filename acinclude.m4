dnl    This file is free software; you can redistribute it and/or
dnl    modify it under the terms of the GNU Library General Public
dnl    License as published by the Free Software Foundation; either
dnl    version 2 of the License, or (at your option) any later version.

dnl    This library is distributed in the hope that it will be useful,
dnl    but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl    Library General Public License for more details.

dnl    You should have received a copy of the GNU Library General Public Licensednl    along with this library; see the file COPYING.LIB.  If not, write to
dnl    the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
dnl    Boston, MA 02111-1307, USA.

dnl ------------------------------------------------------------------------
dnl Find a file (or one of more files in a list of dirs)
dnl ------------------------------------------------------------------------
dnl I stole this from the KDE
dnl

AC_DEFUN(AC_FIND_FILE,
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

AC_DEFUN(AC_SET_NODEBUG,
[
test "$LDFLAGS" = "" && LDFLAGS="-s"
test "$CFLAGS" = "" || CFLAGS=`echo "$CFLAGS" | sed 's/[-]g[ ]*//'`
])

AC_DEFUN(AC_CHECK_DEBUG,
[
AC_ARG_ENABLE(debug,
    [  --enable-debug          creates debugging code],
[
if test "$enableval" = "no"; then
  AC_SET_NODEBUG
fi
],
AC_SET_NODEBUG)
])

AC_DEFUN(AC_CHECK_LDFLAG,
[
$3=no
echo 'int main(){return 0;}' > conftest.c
if test -z "`$1 $2 -o conftest conftest.c 2>&1`"; then
  $3=yes
else
  $3=no
fi
rm -f conftest*
])
