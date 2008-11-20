# Makefile.am

SUBDIRS = doc src test etc
DIST_SUBDIRS = config doc src test etc
EXTRA_DIST = lxc.spec CONTRIBUTING MAINTAINERS ChangeLog lxc.pc.in
pkgconfigdir = /usr/lib/pkgconfig
pkgconfig_DATA = lxc.pc

ChangeLog::
	@touch ChangeLog

dist-hook:
	-@cvs2cl
	@mv ChangeLog $(distdir)

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz

release: rpm
	@sh ./release.sh $(PACKAGE_NAME) \
			$(LXC_MAJOR_VERSION) \
			$(LXC_MINOR_VERSION) \
			$(LXC_MICRO_VERSION)
