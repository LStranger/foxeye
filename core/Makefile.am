## Process this file with automake to produce Makefile.in
## Use aclocal; automake --foreign

RANLIB = @RANLIB@

CC = @CC@
LD = @CC@
CFLAGS = @CFLAGS@

localedir = $(datadir)/locale
helpdir = $(pkglibdir)/help

transform = s/foxeye/@PACKAGE@-@VERSION@/
bin_PROGRAMS = foxeye

foxeye_SOURCES = dcc.c dispatcher.c help.c init.c lib.c main.c modules.c \
	sheduler.c socket.c users.c wtmp.c

foxeye_LDADD = $(wildcard @LD_MODS@) @LIBOBJS@ $(INTLLIBS) \
	$(top_srcdir)/tree/libtree.a
foxeye_DEPENDENCIES = @LIBOBJS@ $(INTLDEPS) $(top_srcdir)/tree/libtree.a

INCLUDES = -I. -I$(top_srcdir)/intl -I$(top_srcdir)/tree -I$(includedir)
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DMODULESDIR=\"$(pkglibdir)\" \
	-DHELPDIR=\"$(helpdir)\"

EXTRA_DIST = dcc.h foxeye.h init.h.in modules.h protos.h sheduler.h \
	socket.h users.h wtmp.h

CLEANFILES = static.h

install-exec-local:
	@if test -h $(DESTDIR)$(bindir)/@PACKAGE@; then \
		echo Removing symlink to archival @PACKAGE@ binary.; \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
	@LN_S@ @PACKAGE@-@VERSION@ $(DESTDIR)$(bindir)/@PACKAGE@

install-data-local:
	@echo Copying new \'@PACKAGE@\' executable and creating symlink.
	@if test ! -d $(DESTDIR)$(sharedstatedir)/filesys; then \
		echo Creating a skeletal \'filesys\' subdirectory.; \
		$(mkinstalldirs) $(DESTDIR)$(sharedstatedir)/filesys; \
		$(mkinstalldirs) $(DESTDIR)$(sharedstatedir)/filesys/incoming; \
	fi

uninstall-local:
	@if test -h $(DESTDIR)$(bindir)/@PACKAGE@; then \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
