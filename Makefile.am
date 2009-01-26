# Makefile.am

SUBDIRS = doc src test etc scripts 
DIST_SUBDIRS = config doc src test etc scripts
EXTRA_DIST = lxc.spec CONTRIBUTING MAINTAINERS ChangeLog

ChangeLog::
	@touch ChangeLog

dist-hook:
	-@cvs2cl
	@mv ChangeLog $(distdir)

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz
