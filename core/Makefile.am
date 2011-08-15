## Process this file with automake to produce Makefile.in
## Use aclocal; automake --foreign

localedir = $(datadir)/locale
helpdir = $(pkglibdir)/help

transform = s/foxeye/@PACKAGE@-@VERSION@/
bin_PROGRAMS = foxeye

foxeye_SOURCES = direct.c dispatcher.c help.c init.c lib.c main.c modules.c \
	sheduler.c socket.c list.c wtmp.c conversion.c connchain.c

foxeye_LDADD = @LD_MODS@ $(LIBOBJS) $(INTLOBJS) $(LTLIBINTL) $(LIBICONV) \
	@STATICLIBS@ -L$(top_srcdir)/tree -ltree
foxeye_DEPENDENCIES = $(LIBOBJS) $(INTLOBJS)

INCLUDES = @ICONV_INCLUDES@ -I$(top_srcdir)/tree
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DMODULESDIR=\"$(pkglibdir)\" \
	-DHELPDIR=\"$(helpdir)\"

EXTRA_DIST = direct.h foxeye.h modules.h protos.h sheduler.h socket.h list.h \
	wtmp.h formats.default conversion.h inlines.h

CLEANFILES = static.h

install-exec-local:
	@if test -h $(DESTDIR)$(bindir)/@PACKAGE@; then \
		echo Removing symlink to archival @PACKAGE@ binary.; \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
	@echo Copying new \'@PACKAGE@\' executable and creating symlink.
	@LN_S@ @PACKAGE@-@VERSION@ $(DESTDIR)$(bindir)/@PACKAGE@

uninstall-local:
	@if test -L $(DESTDIR)$(bindir)/@PACKAGE@; then \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
