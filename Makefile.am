## Process this file with automake to produce Makefile.in
## Use aclocal; automake

LANG = C

AUTOMAKE_OPTIONS = foreign 1.5 no-dist-gzip dist-xz

SUBDIRS = doc intl help po scripts tree modules core ui

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = foxeye.pc

EXTRA_DIST = foxeye.pc.in LICENSE.OpenSSL
