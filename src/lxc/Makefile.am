INCLUDES= -I$(top_srcdir)/src -DLXCPATH="\"$(localstatedir)/lxc\"" -DLXCBINDIR="\"$(bindir)\""
lib_LTLIBRARIES = liblxc.la
pkginclude_HEADERS = \
		monitor.h \
		lxc.h \
		lxc_cgroup.h \
		lxc_conf.h \
		lxc_list.h \
		lxc_lock.h \
		lxc_log.h \
		lxc_namespace.h \
		lxc_state.h \
		lxc_utils.h

liblxc_la_SOURCES = \
	create.c \
	destroy.c \
	start.c \
	stop.c \
	monitor.c monitor.h \
	freezer.c \
	checkpoint.c \
	restart.c \
	version.c \
	error.h error.c \
	cgroup.c cgroup.h \
	lxc.h \
	lxc_utils.h \
	lxc_lock.c lxc_lock.h \
	lxc_namespace.h \
	lxc_conf.c lxc_conf.h \
	lxc_list.h \
	lxc_state.c lxc_state.h \
	lxc_log.c lxc_log.h \
	\
	network.c network.h \
        nl.c nl.h \
        rtnl.c rtnl.h \
        genl.c genl.h \
	\
	cr_plugin_columbia.c lxc_plugin.h

liblxc_la_LDFLAGS = -release @PACKAGE_VERSION@

bin_SCRIPTS = \
	lxc-ps \
	lxc-netstat \
	lxc-ls \
	lxc-checkconfig

bin_PROGRAMS = \
	lxc-unshare \
	lxc-init \
	lxc-create \
	lxc-destroy \
	lxc-stop \
	lxc-start \
	lxc-execute \
	lxc-monitor \
	lxc-wait \
	lxc-console \
	lxc-freeze \
	lxc-info \
	lxc-cgroup \
	lxc-unfreeze \
	lxc-checkpoint \
	lxc-restart \
	lxc-version

lxc_unshare_SOURCES = lxc_unshare.c
lxc_unshare_LDADD = liblxc.la

lxc_init_SOURCES = lxc_init.c
lxc_init_LDADD = liblxc.la

lxc_create_SOURCES = lxc_create.c lxc_config.c lxc_config.h
lxc_create_LDADD = liblxc.la

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDADD = liblxc.la

lxc_start_SOURCES = lxc_start.c
lxc_start_LDADD = liblxc.la

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDADD = liblxc.la

lxc_execute_SOURCES = lxc_execute.c lxc_config.c lxc_config.h
lxc_execute_LDADD = liblxc.la

lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitor_LDADD = liblxc.la

lxc_wait_SOURCES = lxc_wait.c
lxc_wait_LDADD = liblxc.la

lxc_console_SOURCES = lxc_console.c
lxc_console_LDADD = liblxc.la

lxc_info_SOURCES = lxc_info.c
lxc_info_LDADD = liblxc.la

lxc_freeze_SOURCES = lxc_freeze.c
lxc_freeze_LDADD = liblxc.la

lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unfreeze_LDADD = liblxc.la

lxc_cgroup_SOURCES = lxc_cgroup.c
lxc_cgroup_LDADD = liblxc.la

lxc_checkpoint_SOURCES = lxc_checkpoint.c
lxc_checkpoint_LDADD = liblxc.la

lxc_restart_SOURCES = lxc_restart.c
lxc_restart_LDADD = liblxc.la

lxc_version_SOURCES = lxc_version.c
lxc_version_LDADD = liblxc.la

install-exec-local:
	-@export PATH=$$PATH:/sbin:/usr/sbin && \
	 setcap cap_setpcap,cap_net_admin,cap_net_raw,cap_sys_admin,cap_dac_override=ep \
		$(bindir)/lxc-execute && \
	 setcap cap_setpcap,cap_net_admin,cap_net_raw,cap_sys_admin,cap_dac_override=ep \
		$(bindir)/lxc-start && \
	 setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_dac_override=ep \
		$(bindir)/lxc-restart && \
	 setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_dac_override=ep \
		$(bindir)/lxc-unshare && \
	 setcap cap_sys_admin=ep \
		$(bindir)/lxc-init && \
	 setcap cap_sys_admin=ep \
		$(bindir)/lxc-netstat && \
	 mkdir -p $(prefix)/var/lxc && \
	 chmod ugo+rw $(prefix)/var/lxc || \
	(echo && echo && \
	 echo "*****************************************************************" && \
	 echo "*                                                               *" && \
	 echo "* The installation failed to set file capabilities, that is ok, *" && \
	 echo "* but you won't have enough privilege to run the 'lxc' commands *" && \
	 echo "* and you will need to run them as 'root' yourself.             *" && \
	 echo "*                                                               *" && \
	 echo "*****************************************************************" && \
	 echo && echo)
