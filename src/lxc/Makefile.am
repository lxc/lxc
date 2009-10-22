AM_CFLAGS= -I$(top_srcdir)/src

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

sodir=$(libdir)
# use PROGRAMS to avoid complains from automake
so_PROGRAMS = liblxc.so

liblxc_so_SOURCES = \
	arguments.c arguments.h \
	commands.c commands.h \
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
	confile.c confile.h \
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

liblxc_so_CFLAGS = -fPIC -DPIC

liblxc_so_LDFLAGS = \
	-shared \
	-Wl,-soname,liblxc.so.$(firstword $(subst ., ,$(VERSION)))

liblxc_so_LDADD = -lutil

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
lxc_unshare_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_unshare_LDADD = liblxc.so

lxc_init_SOURCES = lxc_init.c
lxc_init_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_init_LDADD = liblxc.so

lxc_create_SOURCES = lxc_create.c
lxc_create_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_create_LDADD = liblxc.so

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_destroy_LDADD = liblxc.so

lxc_start_SOURCES = lxc_start.c
lxc_start_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_start_LDADD = liblxc.so

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_stop_LDADD = liblxc.so

lxc_execute_SOURCES = lxc_execute.c
lxc_execute_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_execute_LDADD = liblxc.so

lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitor_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_monitor_LDADD = liblxc.so

lxc_wait_SOURCES = lxc_wait.c
lxc_wait_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_wait_LDADD = liblxc.so

lxc_console_SOURCES = lxc_console.c
lxc_console_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_console_LDADD = liblxc.so

lxc_info_SOURCES = lxc_info.c
lxc_info_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_info_LDADD = liblxc.so

lxc_freeze_SOURCES = lxc_freeze.c
lxc_freeze_SLDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_freeze_LDADD = liblxc.so

lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unfreeze_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_unfreeze_LDADD = liblxc.so

lxc_cgroup_SOURCES = lxc_cgroup.c
lxc_cgroup_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_cgroup_LDADD = liblxc.so

lxc_checkpoint_SOURCES = lxc_checkpoint.c
lxc_checkpoint_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_checkpoint_LDADD = liblxc.so

lxc_restart_SOURCES = lxc_restart.c
lxc_restart_LDFLAGS = -Wl,-E -Wl,-rpath -Wl,$(libdir)
lxc_restart_LDADD = liblxc.so


install-exec-local: install-soPROGRAMS
	mv $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.$(VERSION)
	/sbin/ldconfig -l $(DESTDIR)$(libdir)/liblxc.so.$(VERSION)
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.$(firstword $(subst ., ,$(VERSION))) liblxc.so

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
