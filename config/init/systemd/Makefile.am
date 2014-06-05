EXTRA_DIST = \
	lxc-devsetup \
	lxc.service

if INIT_SCRIPT_SYSTEMD
SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

lxc-autostart-helper: ../sysvinit/lxc.in $(top_builddir)/config.status
	$(AM_V_GEN)sed                                          \
	    -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g'             \
	    -e 's|[@]LOCALSTATEDIR[@]|$(localstatedir)|g'       \
	    -e 's|[@]BINDIR[@]|$(bindir)|g'                     \
	    < $< > $@-t &&                                      \
	    chmod a+x $@-t &&                                   \
	    mv $@-t $@
BUILT_SOURCES = lxc-autostart-helper

install-systemd: lxc.service lxc-devsetup lxc-autostart-helper
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) lxc.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

pkglibexec_SCRIPTS = lxc-devsetup lxc-autostart-helper

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
