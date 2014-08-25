EXTRA_DIST = lxc-containers.in lxc-net.in

if INIT_SCRIPT_SYSV
# If we're installing for sysv init, install the helper scripts
# directly to the rc directory under the appropriate name.

if HAVE_DEBIAN
initdir = "init.d"
else
initdir = "rc.d/init.d"
endif

install-sysvinit: lxc-containers lxc-net
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/$(initdir)
	$(INSTALL_SCRIPT) lxc-containers $(DESTDIR)$(sysconfdir)/$(initdir)/lxc
	$(INSTALL_SCRIPT) lxc-net $(DESTDIR)$(sysconfdir)/$(initdir)/lxc-net

uninstall-sysvinit:
	rm -f $(DESTDIR)$(sysconfdir)/$(initdir)/lxc
	rm -f $(DESTDIR)$(sysconfdir)/$(initdir)/lxc-net
	rmdir $(DESTDIR)$(sysconfdir)/$(initdir) || :

install-data-local: install-sysvinit
uninstall-local: uninstall-sysvinit
endif
