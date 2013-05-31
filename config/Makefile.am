configdir = $(sysconfdir)/lxc
config_DATA = default.conf
distroconf = @LXC_DISTRO_CONF@

EXTRA_DIST = default.conf.ubuntu default.conf.libvirt default.conf.unknown

default.conf:
	cp $(distroconf) $@

clean-local:
	@$(RM) -f default.conf

distclean-local:
	@$(RM) -f default.conf
	@$(RM) -f compile config.guess config.sub depcomp install-sh ltmain.sh missing Makefile.in Makefile
