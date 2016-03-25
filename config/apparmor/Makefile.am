EXTRA_DIST = \
	abstractions/container-base \
	abstractions/container-base.in \
	abstractions/start-container \
	container-rules \
	container-rules.base \
	lxc-containers \
	lxc-generate-aa-rules.py \
	profiles/lxc-default \
	profiles/lxc-default-cgns \
	profiles/lxc-default-with-mounting \
	profiles/lxc-default-with-nesting \
	usr.bin.lxc-start


if ENABLE_APPARMOR
install-apparmor:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/apparmor.d/
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/
	$(INSTALL_DATA) $(srcdir)/abstractions/container-base $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/
	$(INSTALL_DATA) $(srcdir)/abstractions/start-container $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/
	$(INSTALL_DATA) $(srcdir)/profiles/lxc-default $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/
	$(INSTALL_DATA) $(srcdir)/profiles/lxc-default-cgns $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/
	$(INSTALL_DATA) $(srcdir)/profiles/lxc-default-with-mounting $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/
	$(INSTALL_DATA) $(srcdir)/profiles/lxc-default-with-nesting $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/
	$(INSTALL_DATA) $(srcdir)/lxc-containers $(DESTDIR)$(sysconfdir)/apparmor.d/
	$(INSTALL_DATA) $(srcdir)/usr.bin.lxc-start $(DESTDIR)$(sysconfdir)/apparmor.d/

uninstall-apparmor:
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/usr.bin.lxc-start
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/lxc-containers
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/lxc-default-with-nesting
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/lxc-default-with-mounting
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/lxc-default-cgns
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/lxc-default
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/start-container
	rm -f $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/container-base
	rmdir $(DESTDIR)$(sysconfdir)/apparmor.d/lxc/ || :
	rmdir $(DESTDIR)$(sysconfdir)/apparmor.d/abstractions/lxc/ || :
	rmdir $(DESTDIR)$(sysconfdir)/apparmor.d/ || :

install-data-local: install-apparmor
uninstall-local: uninstall-apparmor
endif
