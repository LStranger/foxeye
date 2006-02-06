## Process this file with automake to produce Makefile.in
## Use aclocal; automake --foreign

docdir = ${prefix}/share/doc/$(PACKAGE)-$(VERSION)

doc_DATA = help.format userflag.txt

man_MANS = foxeye.1

EXTRA_DIST = $(doc_DATA) $(man_MANS) tech.txt module.template.c foxeye.sgml \
	modules.api

foxeye.1: foxeye.sgml
	@SGML2TXT@ $< > $@
