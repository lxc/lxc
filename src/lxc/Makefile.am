INCLUDES= -I$(top_srcdir)/src

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
	execute.c \
	monitor.c monitor.h \
	kill.c \
	freezer.c \
	checkpoint.c \
	restart.c \
	version.c \
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
        genl.c genl.h

liblxc_la_LDFLAGS = -release @PACKAGE_VERSION@

bin_SCRIPTS = \
	lxc-ps

bin_PROGRAMS = \
	lxc-create \
	lxc-destroy \
	lxc-stop \
	lxc-start \
	lxc-execute \
	lxc-monitor \
	lxc-wait \
	lxc-console \
	lxc-kill \
	lxc-freeze \
	lxc-info \
	lxc-cgroup \
	lxc-unfreeze \
	lxc-checkpoint \
	lxc-restart \
	lxc-version

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

lxc_kill_SOURCES = lxc_kill.c
lxc_kill_LDADD = liblxc.la

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
