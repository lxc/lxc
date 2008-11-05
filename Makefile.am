# Makefile.am

SUBDIRS = src test etc
DIST_SUBDIRS = config src test etc
EXTRA_DIST = lxc.spec CONTRIBUTING MAINTAINERS

ChangeLog::
	@touch ChangeLog

dist-hook:
	-@cvs2cl
	@cp ChangeLog $(distdir)

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz

release: rpm
	@sh ./release.sh $(PACKAGE_NAME) \
			$(LXC_MAJOR_VERSION) \
			$(LXC_MINOR_VERSION) \
			$(LXC_MICRO_VERSION)
