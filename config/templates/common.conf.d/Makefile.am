commonconfddir=@LXCTEMPLATECONFIG@/common.conf.d/

EXTRA_DIST = README

commonconfd_DATA = \
	README

uninstall-hook:
	if test -d $(DESTDIR)$(commonconfddir); then rmdir $(DESTDIR)$(commonconfddir); fi
