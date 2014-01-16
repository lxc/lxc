EXTRA_DIST = lxc

if INIT_SCRIPT_SYSV
install-sysvinit: lxc
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) lxc $(DESTDIR)$(sysconfdir)/rc.d/init.d/lxc

uninstall-sysvinit:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/lxc
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-data-local: install-sysvinit
uninstall-local: uninstall-sysvinit
endif
