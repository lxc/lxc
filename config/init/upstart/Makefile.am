EXTRA_DIST = lxc.conf lxc-instance.conf lxc-net.conf.in

if INIT_SCRIPT_UPSTART
install-upstart: lxc.conf lxc-instance.conf lxc-net.conf
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) lxc.conf $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) $(srcdir)/lxc-instance.conf $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) lxc-net.conf $(DESTDIR)$(sysconfdir)/init/

uninstall-upstart:
	rm -f $(DESTDIR)$(sysconfdir)/init/lxc.conf
	rm -f $(DESTDIR)$(sysconfdir)/init/lxc-instance.conf
	rm -f $(DESTDIR)$(sysconfdir)/init/lxc-net.conf
	rmdir $(DESTDIR)$(sysconfdir)/init || :

install-data-local: install-upstart
uninstall-local: uninstall-upstart
endif
