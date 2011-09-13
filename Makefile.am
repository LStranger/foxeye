## Process this file with automake to produce Makefile.in
## Use aclocal; automake

LANG = C

AUTOMAKE_OPTIONS = foreign 1.5

SUBDIRS = doc intl help po scripts tree modules core ui

EXTRA_DIST = debian/c* debian/rules

kit: distdir
	-rm -rf $(distdir)/modules/[^M]* $(distdir)/core/*.c $(distdir)/scripts/[^M]* $(distdir)/tree/*.c $(distdir)/help/[^M]* $(distdir)/po/[^M]*
	$(AMTAR) chof - $(distdir) | GZIP=$(GZIP_ENV) gzip -c >$(distdir)-kit.tar.gz
	-chmod -R a+w $(distdir) >/dev/null 2>&1; rm -rf $(distdir)
