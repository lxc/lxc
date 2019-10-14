templatesdir=@LXCTEMPLATEDIR@

templates_SCRIPTS = lxc-busybox \
		    lxc-download \
		    lxc-local \
		    lxc-oci

uninstall-hook:
	if test -d $(DESTDIR)$(templatesdir); then rmdir $(DESTDIR)$(templatesdir); fi
