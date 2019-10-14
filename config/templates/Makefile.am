templatesconfigdir=@LXCTEMPLATECONFIG@

EXTRA_DIST = common.seccomp

SUBDIRS = common.conf.d

templatesconfig_DATA = common.conf \
		       common.seccomp \
		       nesting.conf \
		       oci.common.conf \
		       userns.conf

uninstall-hook:
	if test -d $(DESTDIR)$(templatesconfigdir); then rmdir $(DESTDIR)$(templatesconfigdir); fi
