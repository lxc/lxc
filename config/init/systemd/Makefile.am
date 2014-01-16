EXTRA_DIST = \
	lxc-devsetup \
	lxc.service

if INIT_SCRIPT_SYSTEMD
if HAVE_DEBIAN
SYSTEMD_UNIT_DIR = /lib/systemd/system
else
SYSTEMD_UNIT_DIR = /usr/lib/systemd/system
endif

install-systemd: lxc.service lxc-devsetup
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) lxc.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxc.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

pkglibexec_SCRIPTS = lxc-devsetup

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
