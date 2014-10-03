## Process this file with automake to produce Makefile.in
## Use aclocal; automake --foreign

# soname: ABI version and age/revision
ABIVER = 0
AGEVER = 0.0

localedir = $(datadir)/locale
helpdir = $(pkglibdir)/help

transform = s/foxeye/@PACKAGE@-@VERSION@/
bin_PROGRAMS = foxeye

foxeye_SUBLIB = libfoxeye.so
SUBLIB_SONAME = $(foxeye_SUBLIB).$(ABIVER)
SUBLIB_TARGET = $(SUBLIB_SONAME).$(AGEVER)
sublib_SOURCES = direct.c dispatcher.c help.c init.c lib.c modules.c \
	sheduler.c socket.c list.c wtmp.c conversion.c connchain.c
sublib_OBJS = $(sublib_SOURCES:.c=.o)
sublib_LLIBS = $(ALL_LIBADD) $(LIBS) -Wl,-soname,$(SUBLIB_SONAME)
$(SUBLIB_TARGET): $(sublib_OBJS)
	@LD@ $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(sublib_OBJS) $(sublib_LLIBS)
$(foxeye_SUBLIB): $(SUBLIB_TARGET)
	$(LN_S) $< $@ 2>/dev/null || true

foxeye_SOURCES = main.c

ALL_LIBADD = $(LIBOBJS) $(INTLOBJS) $(LTLIBINTL) $(LIBICONV) \
	-L$(top_builddir)/tree -ltree $(LIBIDN_LIBS)
foxeye_LDADD = @LD_MODS@ @STATICLIBS@
foxeye_DEPENDENCIES = $(LIBOBJS) $(INTLOBJS)

if STATICBUILD
foxeye_SOURCES += $(sublib_SOURCES)
foxeye_LDADD += $(ALL_LIBADD)
else
foxeye_DEPENDENCIES += $(foxeye_SUBLIB)
foxeye_LDADD += -L$(top_builddir)/core -lfoxeye
endif

AM_CPPFLAGS = @ICONV_INCLUDES@ -I$(top_srcdir)/tree $(LIBIDN_CFLAGS)
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DMODULESDIR=\"$(pkglibdir)\" \
	-DHELPDIR=\"$(helpdir)\"

libfoxeyeincdir = $(includedir)/foxeye
libfoxeyeinc_HEADERS = direct.h foxeye.h modules.h protos.h sheduler.h socket.h list.h \
	wtmp.h formats.default conversion.h inlines.h init.h
EXTRA_DIST = $(libfoxeyeinc_HEADERS)

CLEANFILES = static.h $(SUBLIB_TARGET) $(foxeye_SUBLIB)

install-exec-local:
if ! STATICBUILD
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	@echo Installing the common library
	@$(INSTALL) $(SUBLIB_TARGET) $(DESTDIR)$(libdir)/$(SUBLIB_TARGET)
	@for p in $(SUBLIB_SONAME) $(foxeye_SUBLIB); do \
		$(LN_S) $(SUBLIB_TARGET) $(DESTDIR)$(libdir)/$$p; \
	done
endif
	@if test -h $(DESTDIR)$(bindir)/@PACKAGE@; then \
		echo Removing symlink to archival @PACKAGE@ binary.; \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
	@echo Copying new \'@PACKAGE@\' executable and creating symlink.
	@LN_S@ @PACKAGE@-@VERSION@ $(DESTDIR)$(bindir)/@PACKAGE@

uninstall-local:
if ! STATICBUILD
	@for p in $(SUBLIB_SONAME) $(foxeye_SUBLIB); do \
		if test -L $(DESTDIR)$(libdir)/$$p; then \
			rm -f $(DESTDIR)$(libdir)/$$p; \
		fi; \
	done
endif
	@if test -L $(DESTDIR)$(bindir)/@PACKAGE@; then \
		rm -f $(DESTDIR)$(bindir)/@PACKAGE@; \
	fi
