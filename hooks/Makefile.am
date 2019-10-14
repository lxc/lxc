hooksdir=@LXCHOOKDIR@
binhooksdir=@LXCBINHOOKDIR@

hooks_SCRIPTS = \
	clonehostname \
	mountecryptfsroot \
	ubuntu-cloud-prep \
	dhclient-script \
	dhclient \
	squid-deb-proxy-client \
	nvidia

binhooks_PROGRAMS = \
	unmount-namespace

unmount_namespace_SOURCES = \
	unmount-namespace.c

if IS_BIONIC
unmount_namespace_SOURCES += \
	../src/include/lxcmntent.c ../src/include/lxcmntent.h
endif

EXTRA_DIST=$(hooks_SCRIPTS)

uninstall-hook:
	if test -d $(DESTDIR)$(hooksdir); then rmdir $(DESTDIR)$(hooksdir); fi
	if test -d $(DESTDIR)$(datadir)/lxc; then rmdir $(DESTDIR)$(datadir)/lxc; fi
