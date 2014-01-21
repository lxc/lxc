EXTRA_DIST = lxc

if ENABLE_BASH
install-bash:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/bash_completion.d/
	$(INSTALL_DATA) lxc $(DESTDIR)$(sysconfdir)/bash_completion.d/

uninstall-bash:
	rm -f $(DESTDIR)$(sysconfdir)/bash_completion.d/lxc
	rmdir $(DESTDIR)$(sysconfdir)/bash_completion.d/ || :

install-data-local: install-bash
uninstall-local: uninstall-bash
endif
