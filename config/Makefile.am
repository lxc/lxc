configdir = $(sysconfdir)/lxc
config_DATA = lxc.conf
conffile = @LXC_CONFFILE@

EXTRA_DIST = lxc.conf.ubuntu lxc.conf.libvirt lxc.conf.unknown

lxc.conf:
	cp $(conffile) $@

clean-local:
	@$(RM) -f lxc.conf

distclean-local:
	@$(RM) -f lxc.conf
	@$(RM) -f compile config.guess config.sub depcomp install-sh ltmain.sh missing Makefile.in Makefile
