# Makefile.am

SUBDIRS = src test etc
DIST_SUBDIRS = config src test etc
EXTRA_DIST = lxc.spec

ChangeLog::
	touch ChangeLog

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz

release: rpm
	@echo "Generating ChangeLog"
	@cvs2cl
	@sh ./release.sh $(PACKAGE_NAME) \
			$(LXC_MAJOR_VERSION) \
			$(LXC_MINOR_VERSION) \
			$(LXC_MICRO_VERSION)
