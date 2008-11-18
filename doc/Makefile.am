if ENABLE_DOCBOOK
man_MANS = \
	lxc-create.1 \
	lxc-destroy.1 \
	lxc-execute.1 \
	lxc-start.1 \
	lxc-stop.1 \
	lxc-freeze.1 \
	lxc-unfreeze.1 \
	lxc-monitor.1 \
	lxc-wait.1 \
	lxc-ls.1 \
	lxc-ps.1


%.1 : %.sgml 
	docbook2man $<
endif