AC_ARG_WITH([rusnet],
    [AS_HELP_STRING([--with-rusnet],
		    [compile ircd optimized for RusNet @<:@default=no@:>@])],
    [if test x$withval = xyes; then
	AC_DEFINE([RUSNET_COMPILE], [1],
		  [Define to 1 to compile ircd-rusnet module for using in RusNet IRC network])
	AC_MSG_CACHE_ADD([RusNet ircd support module], [yes])
    else
	AC_MSG_CACHE_ADD([RusNet ircd support module], [no])
    fi
])

