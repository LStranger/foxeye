## Process this file with automake to produce Makefile.in
## Use aclocal; automake --foreign

docdir = ${prefix}/doc/$(PACKAGE)-$(VERSION)

doc_DATA = 

man_MANS = foxeye.1

EXTRA_DIST = modules.api module.template.c help.format foxeye.sgml foxeye.1

foxeye.1: foxeye.sgml
	@SGML2TXT@ -m -c latin foxeye && mv -f foxeye.man foxeye.1
