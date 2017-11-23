dnl Zlib support from configure.in for irc-2.10.1

AC_MSG_CHECKING(for zlib package)
AC_ARG_WITH(zlib, [  --with-zlib[[=ZDIR]]      checks for zlib(default); enables compressed links])
if test "x$withval" = xno; then
  no_zlib=yes
else
fe_zlib_prefix=$with_zlib
AC_CACHE_VAL(fe_cv_path_zlib,
[no_zlib=yes
no_zlib_include=yes
no_zlib_library=yes
AC_PREPROC_IFELSE([AC_LANG_SOURCE([[#include <zlib.h>]])],[no_zlib_include=
fe_zlib_include=],[for fe_dir in "$fe_zlib_include" \
                     `test -z "$fe_zlib_prefix" || echo "$fe_zlib_prefix/include"` \
                     `echo "$fe_zlib_library" | sed s/lib/include/` \
                     /usr/include /usr/local/include /usr/unsupported/include \
                     /usr/share/include /usr/local/share/include /include \
                     /usr/zlib/include /usr/local/zlib/include \
                     /usr/include/zlib /usr/local/include/zlib \
                     /usr/unsupported/include/zlib /usr/share/include/zlib \
                     /usr/local/share/include/zlib /include/zlib \
                     /usr/zlib/include/zlib /usr/local/zlib/include/zlib; \
  do
    if test -r "$fe_dir/zlib.h"; then
      no_zlib_include=
      fe_zlib_include=$fe_dir
      break
    fi
  done
])
fe_save_LIBS="$LIBS"
LIBS="-lz $LIBS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[inflate()]])],[no_zlib_library=
fe_zlib_library=
LIBS="$fe_save_LIBS"],[LIBS="$fe_save_LIBS"
for fe_dir in "$fe_zlib_library" \
                    `test -z "$fe_zlib_prefix" || echo "$fe_zlib_prefix/lib"` \
                    `echo "$fe_zlib_include" | sed s/include/lib/` \
                    /usr/lib /usr/local/lib /usr/unsupported/lib \
                    /usr/share/lib /usr/local/share/lib /lib /usr/zlib/lib \
                    /usr/local/zlib/lib /usr/lib/zlib /usr/local/lib/zlib \
                    /usr/unsupported/lib/zlib /usr/share/lib/zlib \
                    /usr/local/share/lib/zlib /lib/zlib \
                    /usr/zlib/lib/zlib /usr/local/zlib/lib/zlib; \
do
  for fe_extension in a so sl; do
    if test -r $fe_dir/libz.$fe_extension; then
      no_zlib_library=
      fe_zlib_library=$fe_dir
      break 2
    fi
  done
done
])
if test "x$no_zlib_include" = x && test "x$no_zlib_library" = x; then
  no_zlib=
fi
if test "$no_zlib" = yes; then
  fe_cv_path_zlib="no_zlib=yes"
else
  fe_cv_path_zlib="no_zlib= fe_zlib_include=$fe_zlib_include fe_zlib_library=$fe_zlib_library"
fi])
  eval "$fe_cv_path_zlib"
fi
if test "$no_zlib" = yes; then
  AC_MSG_RESULT(no)
  AC_MSG_CACHE_ADD([ZLib support], [no])
else
  AC_DEFINE([HAVE_ZLIB], [1], [Define if zlib package must be used for compilation/linking.])
  if test "x$fe_zlib_library" = x; then
    fe_zlib_library_message="found by the linker"
    ZLIB_LIBRARY=-lz
  else
    fe_zlib_library_message="in $fe_zlib_library"
    ZLIB_LIBRARY=-L$fe_zlib_library
    if test ! "$fe_cv_solaris_2" = no; then
      ZLIB_LIBRARY="$ZLIB_LIBRARY -R$fe_zlib_library"
    fi
    ZLIB_LIBRARY="$ZLIB_LIBRARY -lz"
  fi
  if test "$fe_cv_static" = yes; then
    STATICLIBS="${ZLIB_LIBRARY} ${STATICLIBS}"
  else
    MODLIBS="MODLIBS_ziplink=\"${ZLIB_LIBRARY}\" ${MODLIBS}"
  fi
  if test "x$fe_zlib_include" = x; then
    fe_zlib_include_message="found by the compiler"
  else
    fe_zlib_include_message="in $fe_zlib_include"
    CPPFLAGS="-I$fe_zlib_include ${CPPFLAGS}"
  fi
  AC_MSG_RESULT([])
  AC_MSG_RESULT([  library $fe_zlib_library_message])
  AC_MSG_RESULT([  header $fe_zlib_include_message])
  AC_MSG_CACHE_ADD([ZLib support], [yes])
fi

