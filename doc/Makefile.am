SUBDIRS = examples rootfs
DIST_SUBDIRS = examples rootfs

EXTRA_DIST = \
	FAQ.txt \
	$(man_MANS)

if ENABLE_DOCBOOK
man_MANS = \
	lxc-create.1 \
	lxc-destroy.1 \
	lxc-execute.1 \
	lxc-start.1 \
	lxc-stop.1 \
	lxc-checkpoint.1 \
	lxc-restart.1 \
	lxc-console.1 \
	lxc-freeze.1 \
	lxc-unfreeze.1 \
	lxc-monitor.1 \
	lxc-wait.1 \
	lxc-ls.1 \
	lxc-ps.1 \
	lxc-cgroup.1 \
	lxc-kill.1 \
	\
	lxc.conf.5 \
	\
	lxc.7


%.1 : %.sgml 
	docbook2man -w all $<

%.5 : %.sgml 
	docbook2man -w all $<

%.7 : %.sgml 
	docbook2man -w all $<

lxc-%.sgml : common_options.sgml see_also.sgml

maintainer-clean-local:
	$(RM) manpage.* *.7 *.5 *.1 $(man_MANS)
endif
