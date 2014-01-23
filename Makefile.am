# Makefile.am

ACLOCAL_AMFLAGS = -I config

SUBDIRS = config src templates doc hooks
DIST_SUBDIRS = config src templates doc hooks
EXTRA_DIST = \
	autogen.sh \
	lxc.spec \
	CONTRIBUTING \
	MAINTAINERS

RPMARGS =

if ENABLE_LUA
RPMARGS += --with lua
endif

if ENABLE_PYTHON
RPMARGS += --with python
endif

pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = lxc.pc

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(LXCPATH)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/cache/lxc

ChangeLog::
	@touch ChangeLog

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz $(RPMARGS)
