pkginclude_HEADERS = \
	attach_options.h \
	lxccontainer.h \
	version.h

noinst_HEADERS = \
	arguments.h \
	attach.h \
	bdev/bdev.h \
	bdev/lxcaufs.h \
	bdev/lxcbtrfs.h \
	bdev/lxcdir.h \
	bdev/lxcloop.h \
	bdev/lxclvm.h \
	bdev/lxcnbd.h \
	bdev/lxcoverlay.h \
	bdev/lxcrbd.h \
	bdev/lxcrsync.h \
	bdev/lxczfs.h \
	cgroups/cgroup.h \
	caps.h \
	conf.h \
	console.h \
	error.h \
	initutils.h \
	list.h \
	log.h \
	lxc.h \
	lxclock.h \
	monitor.h \
	namespace.h \
	start.h \
	state.h \
	utils.h \
	criu.h \
	../tests/lxctest.h

if IS_BIONIC
noinst_HEADERS += \
	../include/ifaddrs.h \
	../include/openpty.h \
	../include/lxcmntent.h
endif

if !HAVE_GETLINE
if HAVE_FGETLN
noinst_HEADERS += ../include/getline.h
endif
endif

if !HAVE_GETSUBOPT
noinst_HEADERS += ../include/getsubopt.h
endif

sodir=$(libdir)
# use PROGRAMS to avoid complains from automake
so_PROGRAMS = liblxc.so

LSM_SOURCES = \
	lsm/nop.c \
	lsm/lsm.h lsm/lsm.c

if ENABLE_APPARMOR
LSM_SOURCES += lsm/apparmor.c
endif

if ENABLE_SELINUX
LSM_SOURCES += lsm/selinux.c
endif

liblxc_so_SOURCES = \
	arguments.c arguments.h \
	bdev/bdev.c bdev/bdev.h \
	bdev/lxcaufs.c bdev/lxcaufs.h \
	bdev/lxcbtrfs.c bdev/lxcbtrfs.h \
	bdev/lxcdir.c bdev/lxcdir.h \
	bdev/lxcloop.c bdev/lxcloop.h \
	bdev/lxclvm.c bdev/lxclvm.h \
	bdev/lxcnbd.c bdev/lxcnbd.h \
	bdev/lxcoverlay.c bdev/lxcoverlay.h \
	bdev/lxcrbd.c bdev/lxcrbd.h \
	bdev/lxcrsync.c bdev/lxcrsync.h \
	bdev/lxczfs.c bdev/lxczfs.h \
	cgroups/cgfs.c \
	cgroups/cgfsng.c \
	cgroups/cgroup.c cgroups/cgroup.h \
	commands.c commands.h \
	start.c start.h \
	execute.c \
	monitor.c monitor.h \
	console.c \
	freezer.c \
	error.h error.c \
	parse.c parse.h \
	lxc.h \
	initutils.c initutils.h \
	utils.c utils.h \
	sync.c sync.h \
	namespace.h namespace.c \
	conf.c conf.h \
	confile.c confile.h \
	list.h \
	state.c state.h \
	log.c log.h \
	attach.c attach.h \
	criu.c criu.h \
	\
	network.c network.h \
	nl.c nl.h \
	rtnl.c rtnl.h \
	genl.c genl.h \
	\
	caps.c caps.h \
	lxcseccomp.h \
	mainloop.c mainloop.h \
	af_unix.c af_unix.h \
	\
	lxcutmp.c lxcutmp.h \
	lxclock.h lxclock.c \
	lxccontainer.c lxccontainer.h \
	version.h \
	\
	$(LSM_SOURCES)

if ENABLE_CGMANAGER
liblxc_so_SOURCES += cgroups/cgmanager.c
endif

if IS_BIONIC
liblxc_so_SOURCES += \
	../include/ifaddrs.c ../include/ifaddrs.h \
	../include/openpty.c ../include/openpty.h \
	../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETLINE
if HAVE_FGETLN
liblxc_so_SOURCES += ../include/getline.c ../include/getline.h
endif
endif

AM_CFLAGS=-DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	-DLXCPATH=\"$(LXCPATH)\" \
	-DLXC_GLOBAL_CONF=\"$(LXC_GLOBAL_CONF)\" \
	-DLXCINITDIR=\"$(LXCINITDIR)\" \
	-DLIBEXECDIR=\"$(LIBEXECDIR)\" \
	-DLXCTEMPLATEDIR=\"$(LXCTEMPLATEDIR)\" \
	-DLXCTEMPLATECONFIG=\"$(LXCTEMPLATECONFIG)\" \
	-DLOGPATH=\"$(LOGPATH)\" \
	-DLXC_DEFAULT_CONFIG=\"$(LXC_DEFAULT_CONFIG)\" \
	-DLXC_USERNIC_DB=\"$(LXC_USERNIC_DB)\" \
	-DLXC_USERNIC_CONF=\"$(LXC_USERNIC_CONF)\" \
	-DDEFAULT_CGROUP_PATTERN=\"$(DEFAULT_CGROUP_PATTERN)\" \
	-DRUNTIME_PATH=\"$(RUNTIME_PATH)\" \
	-DSBINDIR=\"$(SBINDIR)\" \
	-I $(top_srcdir)/src \
	-I $(top_srcdir)/src/lxc \
	-I $(top_srcdir)/src/lxc/bdev \
	-I $(top_srcdir)/src/lxc/cgroups

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
endif

if ENABLE_CGMANAGER
AM_CFLAGS += -DHAVE_CGMANAGER
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

if USE_CONFIGPATH_LOGS
AM_CFLAGS += -DUSE_CONFIGPATH_LOGS
endif

if ENABLE_SECCOMP
AM_CFLAGS += -DHAVE_SECCOMP $(SECCOMP_CFLAGS)
liblxc_so_SOURCES += seccomp.c
endif

liblxc_so_CFLAGS = -fPIC -DPIC $(AM_CFLAGS) -pthread

liblxc_so_LDFLAGS = \
	-pthread \
	-shared \
	-Wl,-soname,liblxc.so.$(firstword $(subst ., ,@LXC_VERSION_ABI@))

liblxc_so_LDADD = $(CAP_LIBS) $(APPARMOR_LIBS) $(SELINUX_LIBS) $(SECCOMP_LIBS)

if ENABLE_CGMANAGER
liblxc_so_LDADD += $(CGMANAGER_LIBS) $(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS)
liblxc_so_CFLAGS += $(CGMANAGER_CFLAGS) $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
endif

bin_SCRIPTS = tools/lxc-checkconfig

EXTRA_DIST = \
	tools/lxc-top.lua

if ENABLE_DEPRECATED
if ENABLE_PYTHON
bin_SCRIPTS += tools/lxc-start-ephemeral
endif
endif

bin_PROGRAMS = \
	lxc-attach \
	lxc-autostart \
	lxc-cgroup \
	lxc-checkpoint \
	lxc-copy \
	lxc-config \
	lxc-console \
	lxc-create \
	lxc-destroy \
	lxc-device \
	lxc-execute \
	lxc-freeze \
	lxc-info \
	lxc-ls \
	lxc-monitor \
	lxc-snapshot \
	lxc-start \
	lxc-stop \
	lxc-top \
	lxc-unfreeze \
	lxc-unshare \
	lxc-usernsexec \
	lxc-wait

if ENABLE_DEPRECATED
bin_PROGRAMS += lxc-clone
endif

sbin_PROGRAMS = init.lxc
pkglibexec_PROGRAMS = \
	lxc-monitord \
	lxc-user-nic

AM_LDFLAGS = -Wl,-E
if ENABLE_RPATH
AM_LDFLAGS += -Wl,-rpath -Wl,$(libdir)
endif
LDADD=liblxc.so @CAP_LIBS@ @APPARMOR_LIBS@ @SELINUX_LIBS@ @SECCOMP_LIBS@

lxc_attach_SOURCES = tools/lxc_attach.c
lxc_autostart_SOURCES = tools/lxc_autostart.c
lxc_cgroup_SOURCES = tools/lxc_cgroup.c
lxc_config_SOURCES = tools/lxc_config.c
lxc_console_SOURCES = tools/lxc_console.c
lxc_destroy_SOURCES = tools/lxc_destroy.c
lxc_device_SOURCES = tools/lxc_device.c
lxc_execute_SOURCES = tools/lxc_execute.c
lxc_freeze_SOURCES = tools/lxc_freeze.c
lxc_info_SOURCES = tools/lxc_info.c
init_lxc_SOURCES = tools/lxc_init.c
lxc_monitor_SOURCES = tools/lxc_monitor.c
lxc_ls_SOURCES = tools/lxc_ls.c
lxc_copy_SOURCES = tools/lxc_copy.c
lxc_start_SOURCES = tools/lxc_start.c
lxc_stop_SOURCES = tools/lxc_stop.c
lxc_top_SOURCES = tools/lxc_top.c
lxc_unfreeze_SOURCES = tools/lxc_unfreeze.c
lxc_unshare_SOURCES = tools/lxc_unshare.c
lxc_wait_SOURCES = tools/lxc_wait.c
lxc_create_SOURCES = tools/lxc_create.c
lxc_snapshot_SOURCES = tools/lxc_snapshot.c
lxc_usernsexec_SOURCES = tools/lxc_usernsexec.c
lxc_checkpoint_SOURCES = tools/lxc_checkpoint.c
lxc_user_nic_SOURCES = lxc_user_nic.c network.c network.h
lxc_monitord_SOURCES = lxc_monitord.c

if ENABLE_DEPRECATED
lxc_clone_SOURCES = tools/lxc_clone.c
endif

if !HAVE_GETSUBOPT
lxc_copy_SOURCES += ../include/getsubopt.c ../include/getsubopt.h
endif

if HAVE_STATIC_LIBCAP
sbin_PROGRAMS += init.lxc.static

init_lxc_static_SOURCES = tools/lxc_init.c error.c log.c initutils.c caps.c

if !HAVE_GETLINE
if HAVE_FGETLN
init_lxc_static_SOURCES += ../include/getline.c
endif
endif

init_lxc_static_LDFLAGS = -static
init_lxc_static_LDADD = @CAP_LIBS@
init_lxc_static_CFLAGS = $(AM_CFLAGS) -DNO_LXC_CONF
endif

install-exec-local: install-soPROGRAMS
	mkdir -p $(DESTDIR)$(datadir)/lxc
	install -c -m 644 lxc.functions $(DESTDIR)$(datadir)/lxc
	mv $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.@LXC_VERSION_ABI@
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.@LXC_VERSION_ABI@ liblxc.so.$(firstword $(subst ., ,@LXC_VERSION_ABI@)); \
	ln -sf liblxc.so.$(firstword $(subst ., ,@LXC_VERSION_ABI@)) liblxc.so

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/lxc/lxc-user-nic

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
