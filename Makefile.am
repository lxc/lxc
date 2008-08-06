# Makefile.am

SUBDIRS = src test etc
DIST_SUBDIRS = config src test etc
EXTRA_DIST = lxc.spec

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz
