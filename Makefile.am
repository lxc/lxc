# Makefile.am

ACLOCAL_AMFLAGS = -I config

SUBDIRS = src etc scripts doc
DIST_SUBDIRS = config src etc scripts doc
EXTRA_DIST = autogen.sh lxc.spec CONTRIBUTING MAINTAINERS ChangeLog

pcdatadir = $(datadir)/pkgconfig
pcdata_DATA = lxc.pc

ChangeLog::
	@touch ChangeLog

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz
