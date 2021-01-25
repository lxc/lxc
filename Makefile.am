# Makefile.am

ACLOCAL_AMFLAGS = -I config
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_LDFLAGS += $(PTHREAD_LIBS)

LIBTOOL_DEPS = @LIBTOOL_DEPS@
SUBDIRS = config coccinelle src templates doc hooks
DIST_SUBDIRS = config coccinelle  src templates doc hooks
EXTRA_DIST = autogen.sh \
	     lxc.spec \
	     CONTRIBUTING \
	     CODING_STYLE.md \
	     LICENSE.GPL2 \
	     LICENSE.LGPL2.1 \
	     MAINTAINERS \
	     README.md

RPMARGS =

pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = lxc.pc

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(LXCPATH)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/cache/lxc

ChangeLog::
	@touch ChangeLog

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz $(RPMARGS)
