EXTRA_DIST = \
	lxc-devsetup \
	lxc-apparmor-load \
	lxc.service.in \
	lxc-net.service.in \
	$(NULL)

if INIT_SCRIPT_SYSTEMD
lxc-autostart-helper: ../sysvinit/lxc.in $(top_builddir)/config.status
	$(AM_V_GEN)sed                                          \
	    -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g'             \
	    -e 's|[@]LOCALSTATEDIR[@]|$(localstatedir)|g'       \
	    -e 's|[@]BINDIR[@]|$(bindir)|g'                     \
	    < $< > $@-t &&                                      \
	    chmod a+x $@-t &&                                   \
	    mv $@-t $@
BUILT_SOURCES = lxc-autostart-helper lxc.service lxc-net.service

install-systemd: lxc.service lxc-net.service lxc-devsetup lxc-apparmor-load lxc-autostart-helper
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) lxc.service lxc-net.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc-net.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

pkglibexec_SCRIPTS = lxc-devsetup lxc-apparmor-load lxc-autostart-helper

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
