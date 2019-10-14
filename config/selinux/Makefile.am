selinuxdir=$(pkgdatadir)/selinux

EXTRA_DIST = \
	lxc.if lxc.te

selinux_DATA = \
	lxc.if \
	lxc.te

uninstall-hook:
	if test -d $(DESTDIR)$(selinuxdir); then rmdir $(DESTDIR)$(selinuxdir); fi
