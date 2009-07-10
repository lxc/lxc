INCLUDES= -I$(top_srcdir)/src -DLXCPATH="\"@LXCPATH@\"" \
	  -DLXCBINDIR="\"$(bindir)\"" \
	  -DLXCLIBEXECDIR="\"$(libexecdir)\""
AM_LDFLAGS= -lutil
lib_LTLIBRARIES = liblxc.la
pkginclude_HEADERS = \
		start.h \
		error.h \
		monitor.h \
		utils.h \
		namespace.h \
		lock.h \
		lxc.h \
		cgroup.h \
		conf.h \
		list.h \
		log.h \
		state.h


liblxc_la_SOURCES = \
	arguments.c arguments.h \
	create.c \
	destroy.c \
	start.c \
	stop.c \
	monitor.c monitor.h \
	console.c \
	freezer.c \
	checkpoint.c \
	restart.c \
	error.h error.c \
	parse.c parse.h \
	cgroup.c cgroup.h \
	lxc.h \
	utils.c utils.h \
	lock.c lock.h \
	namespace.h namespace.c \
	conf.c conf.h \
	list.h \
	state.c state.h \
	log.c log.h \
	\
	network.c network.h \
        nl.c nl.h \
        rtnl.c rtnl.h \
        genl.c genl.h \
	\
	mainloop.c mainloop.h \
	af_unix.c af_unix.h \
	\
	cr_plugin_columbia.c lxc_plugin.h

liblxc_la_LDFLAGS = -release @PACKAGE_VERSION@

bin_SCRIPTS = \
	lxc-ps \
	lxc-netstat \
	lxc-ls \
	lxc-checkconfig \
	lxc-setcap \
	lxc-version

bin_PROGRAMS = \
	lxc-unshare \
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
	lxc-restart

libexec_PROGRAMS = \
	lxc-init

lxc_unshare_SOURCES = lxc_unshare.c
lxc_unshare_LDADD = liblxc.la

lxc_init_SOURCES = lxc_init.c
lxc_init_LDADD = liblxc.la

lxc_create_SOURCES = lxc_create.c confile.c confile.h
lxc_create_LDADD = liblxc.la

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDADD = liblxc.la

lxc_start_SOURCES = lxc_start.c
lxc_start_LDADD = liblxc.la

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDADD = liblxc.la

lxc_execute_SOURCES = lxc_execute.c confile.c confile.h
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
