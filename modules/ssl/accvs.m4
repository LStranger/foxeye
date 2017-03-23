dnl OpenSSL support from configure.in for rusnet-ircd-1.5, reworked

fe_save_LIBS="$LIBS"
fe_save_LDFLAGS="$LDFLAGS"
fe_save_CFLAGS="$CFLAGS"
USE_OPENSSL=no
LIBS="-lcrypto -lssl $LIBS"
openssl_libpath=
openssl_include=

AC_ARG_WITH(openssl,
    AC_HELP_STRING([--with-openssl=PATH], [Specify path to OpenSSL installation]), [
    fe_openssl_path=$withval], [
    fe_openssl_path=auto])

dnl Search for OpenSSL library
case $fe_openssl_path in
no)
    # Disable OpenSSL
    ;;

auto)
    # Autodetect
    AC_MSG_CHECKING(for OpenSSL libraries in default paths)
    AC_LINK_IFELSE([AC_LANG_CALL([], [SSL_library_init])], [
	AC_MSG_RESULT(found)
	# Found in default paths
	USE_OPENSSL=yes
    ], [
      AC_LINK_IFELSE([AC_LANG_CALL([], [OPENSSL_init_ssl])], [
	AC_MSG_RESULT(found)
	# Found OpenSSL 1.1 in default paths
	USE_OPENSSL=yes
      ], [
	AC_MSG_RESULT(no)
	# Search for it
	for tryssl_dir in	/usr/local/ssl /usr /usr/local /usr/local/share \
				/usr/local/openssl /usr/lib/openssl /usr/lib/ssl \
				/usr/pkg /opt /opt/openssl
	do
	    test -d "$tryssl_dir/." || continue
	    if test -d "${tryssl_dir}/lib"; then
		openssl_libpath="${tryssl_dir}/lib"
	    else
		openssl_libpath="${tryssl_dir}"
	    fi
	    LDFLAGS="-L${openssl_libpath} ${fe_save_LDFLAGS}"
	    if test -d "${tryssl_dir}/include"; then
		openssl_include="${tryssl_dir}/include"
	    else
		openssl_include="${tryssl_dir}"
	    fi
	    # Now check if it links
	    unset ac_cv_lib_ssl_SSL_library_init
	    AC_MSG_CHECKING(for OpenSSL libraries in $tryssl_dir)
	    AC_LINK_IFELSE([AC_LANG_CALL([], [SSL_library_init])], [
		AC_MSG_RESULT(found)
		USE_OPENSSL=yes
		break
	    ], [
	      AC_LINK_IFELSE([AC_LANG_CALL([], [OPENSSL_init_ssl])], [
		AC_MSG_RESULT(found)
		USE_OPENSSL=yes
		break
	      ], [
		AC_MSG_RESULT(no)
		openssl_include=
	    ])])
	done
    ])])
    dnl at this point if $USE_OPENSSL isn't "yes" then it's not found
    if test x$USE_OPENSSL != xyes; then
	AC_MSG_WARN(could not find OpenSSL libcrypto: see config.log for details)
	openssl_libpath=
    fi
    ;;

yes)
    # Try to enforce link
    AC_MSG_CHECKING(for OpenSSL libraries in default paths)
    AC_LINK_IFELSE([AC_LANG_CALL([], [SSL_library_init])], [
	AC_MSG_RESULT(found)
	USE_OPENSSL=yes
    ], [
      AC_LINK_IFELSE([AC_LANG_CALL([], [OPENSSL_init_ssl])], [
	AC_MSG_RESULT(found)
	USE_OPENSSL=yes
      ], [
	AC_MSG_RESULT(no)
	AC_MSG_FAILURE(couldn't find OpenSSL)
    ])])
    ;;

*)
    # Try to find it in the given path
    case "$fe_openssl_path" in
    # Relative paths
    ./*|../*)
	fe_openssl_path="`pwd`/$fe_openssl_path"
	;;
    esac
    if test -d "$fe_openssl_path/lib"; then
	openssl_libpath="$fe_openssl_path/lib"
    else
	openssl_libpath="$fe_openssl_path"
    fi
    LDFLAGS="-L${openssl_libpath} ${fe_save_LDFLAGS}"
    if test -d "$fe_openssl_path/include"; then
	openssl_include="$fe_openssl_path/include"
    else
	openssl_include="$fe_openssl_path"
    fi

    # Now check if it links
    AC_MSG_CHECKING(for OpenSSL libraries in $openssl_libpath)
    AC_LINK_IFELSE([AC_LANG_CALL([], [SSL_library_init])], [
	AC_MSG_RESULT(found)
	USE_OPENSSL=yes
    ], [
      AC_LINK_IFELSE([AC_LANG_CALL([], [OPENSSL_init_ssl])], [
	AC_MSG_RESULT(found)
	USE_OPENSSL=yes
      ], [
	AC_MSG_RESULT(no)
	AC_MSG_FAILURE(couldn't find OpenSSL)
    ])])
    ;;
esac
dnl -- end of OpenSSL search

if test x$USE_OPENSSL = xyes; then
    dnl Check for OpenSSL headers
    AC_CHECK_HEADER([openssl/ssl.h], [], [
	if test -z "$openssl_include"; then
	    AC_MSG_FAILURE(couldn't find OpenSSL)
	else
	    OPENSSL_CFLAGS="-I$openssl_include"
	    CFLAGS="${OPENSSL_CFLAGS} ${CFLAGS}"
	    AC_MSG_CHECKING(in $openssl_include)
	    unset ac_cv_header_openssl_ssl_h
	    AC_CHECK_HEADER([openssl/ssl.h], [], [
		AC_MSG_FAILURE(couldn't find OpenSSL)
	    ])
	fi
    ])

    dnl Determine OpenSSL header version
    AC_MSG_CHECKING(OpenSSL header version)
    AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#define DATA "conftest.sslincver"
int main(void) {
        FILE *fd;
        int rc;

        fd = fopen(DATA,"w");
        if(fd == NULL)
                exit(1);
        if ((rc = fprintf(fd ,"%lx (%s)\n", OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
                exit(1);
        exit(0);
}
    ]])], [
	ssl_header_ver=`cat conftest.sslincver`
	AC_MSG_RESULT($ssl_header_ver)
    ], [
	AC_MSG_RESULT(not found)
	AC_MSG_ERROR(OpenSSL version header not found.)
    ], [
	AC_MSG_WARN(cross compiling: not checking)
    ])

    dnl Determine OpenSSL library version
    AC_MSG_CHECKING(OpenSSL library version)
    AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#define DATA "conftest.ssllibver"
int main(void) {
        FILE *fd;
        int rc;

        fd = fopen(DATA,"w");
        if(fd == NULL)
                exit(1);

        if ((rc = fprintf(fd ,"%lx (%s)\n", SSLeay(), SSLeay_version(SSLEAY_VERSION))) <0)
                exit(1);

        exit(0);
}
    ]])], [
	ssl_library_ver=`cat conftest.ssllibver`
	AC_MSG_RESULT($ssl_library_ver)
    ], [
	AC_MSG_RESULT(not found)
	AC_MSG_ERROR(OpenSSL library not found.)
    ], [
	AC_MSG_WARN(cross compiling: not checking)
    ])

    dnl Sanity check OpenSSL headers
    AC_MSG_CHECKING(whether OpenSSL headers match the library)
    AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
int main(void) { exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1); }
    ]])], [
	AC_MSG_RESULT(yes)
    ], [
	AC_MSG_RESULT(no)
	AC_MSG_FAILURE(your OpenSSL headers do NOT match your library)
    ], [
	AC_MSG_WARN(cross compiling: not checking)
    ])

    AC_DEFINE([USE_OPENSSL], [1], [Define if openssl package must be used for compilation/linking.])

    dnl update LIBS for the module
    openssl_libs="-lssl -lcrypto"
    if test -n "$openssl_libpath"; then
	openssl_libs="$openssl_libs -L$openssl_libpath -R$openssl_libpath"
    fi
    if test "$fe_cv_static" = yes; then
	STATICLIBS="${openssl_libs} ${STATICLIBS}"
    else
	MODLIBS="MODLIBS_ssl=\"${openssl_libs}\" ${MODLIBS}"
    fi
fi

LIBS="$fe_save_LIBS"
CFLAGS="$fe_save_CFLAGS"
LDFLAGS="$fe_save_LDFLAGS"

if test -n "$OPENSSL_CFLAGS"; then
    CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS"
fi
# End of OpenSSL
