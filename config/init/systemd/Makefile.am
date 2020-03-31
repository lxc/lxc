EXTRA_DIST = \
	lxc-apparmor-load \
	lxc.service.in \
	lxc@.service.in \
	lxc-net.service.in \
	lxc-monitord.service.in

if INIT_SCRIPT_SYSTEMD
BUILT_SOURCES = lxc.service lxc@.service lxc-net.service lxc-monitord.service

install-systemd: lxc.service lxc@.service lxc-net.service lxc-monitord.service lxc-apparmor-load
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) lxc.service lxc@.service lxc-net.service lxc-monitord.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc@.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc-net.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc-monitord.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

pkglibexec_SCRIPTS = lxc-apparmor-load

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
