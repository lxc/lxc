# Makefile.am

ACLOCAL_AMFLAGS = -I config

SUBDIRS = src test etc scripts doc
DIST_SUBDIRS = config src test etc scripts doc
EXTRA_DIST = autogen.sh lxc.spec CONTRIBUTING MAINTAINERS ChangeLog

ChangeLog::
	@touch ChangeLog

dist-hook:
	-@cvs2cl
	@mv ChangeLog $(distdir)

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz
