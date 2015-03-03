configdir = $(sysconfdir)/lxc
config_DATA = default.conf

EXTRA_DIST = default.conf.lxcbr default.conf.libvirt default.conf.unknown

distclean-local:
	@$(RM) -f default.conf
	@$(RM) -f compile config.guess config.sub depcomp install-sh ltmain.sh missing Makefile.in Makefile
