pkginclude_HEADERS = \
	attach_options.h \
	lxccontainer.h \
	version.h

noinst_HEADERS = \
	tools/arguments.h \
	attach.h \
	storage/storage.h \
	storage/aufs.h \
	storage/btrfs.h \
	storage/dir.h \
	storage/loop.h \
	storage/lvm.h \
	storage/nbd.h \
	storage/overlay.h \
	storage/rbd.h \
	storage/rsync.h \
	storage/zfs.h \
	storage/storage_utils.h \
	cgroups/cgroup.h \
	cgroups/cgroup_utils.h \
	caps.h \
	conf.h \
	confile.h \
	confile_utils.h \
	console.h \
	error.h \
	initutils.h \
	list.h \
	log.h \
	lxc.h \
	lxclock.h \
	macro.h \
	monitor.h \
	namespace.h \
	rexec.h \
	start.h \
	state.h \
	utils.h \
	criu.h \
	../tests/lxctest.h

if IS_BIONIC
noinst_HEADERS += \
	../include/fexecve.h \
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

if !HAVE_GETGRGID_R
noinst_HEADERS += ../include/getgrgid_r.h
endif

sodir=$(libdir)

LSM_SOURCES = \
	lsm/nop.c \
	lsm/lsm.h lsm/lsm.c

if ENABLE_APPARMOR
LSM_SOURCES += lsm/apparmor.c
endif

if ENABLE_SELINUX
LSM_SOURCES += lsm/selinux.c
endif

lib_LTLIBRARIES = liblxc.la
liblxc_la_SOURCES = \
	storage/storage.c storage/storage.h \
	storage/aufs.c storage/aufs.h \
	storage/btrfs.c storage/btrfs.h \
	storage/dir.c storage/dir.h \
	storage/loop.c storage/loop.h \
	storage/lvm.c storage/lvm.h \
	storage/nbd.c storage/nbd.h \
	storage/overlay.c storage/overlay.h \
	storage/rbd.c storage/rbd.h \
	storage/rsync.c storage/rsync.h \
	storage/zfs.c storage/zfs.h \
	storage/storage_utils.c storage/storage_utils.h \
	cgroups/cgfs.c \
	cgroups/cgfsng.c \
	cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
	cgroups/cgroup.c cgroups/cgroup.h \
	commands.c commands.h \
	commands_utils.c commands_utils.h \
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
	confile_utils.c confile_utils.h \
	list.h \
	state.c state.h \
	log.c log.h \
	attach.c attach.h \
	criu.c criu.h \
	\
	network.c network.h \
	nl.c nl.h \
	rtnl.c rtnl.h \
	\
	caps.c caps.h \
	lxcseccomp.h \
	macro.h \
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
liblxc_la_SOURCES += cgroups/cgmanager.c
endif

if IS_BIONIC
liblxc_la_SOURCES += \
	../include/fexecve.c ../include/fexecve.h \
	../include/ifaddrs.c ../include/ifaddrs.h \
	../include/openpty.c ../include/openpty.h \
	../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETLINE
if HAVE_FGETLN
liblxc_la_SOURCES += ../include/getline.c ../include/getline.h
endif
endif

if !HAVE_STRLCPY
liblxc_la_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
liblxc_la_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if ENFORCE_MEMFD_REXEC
liblxc_la_SOURCES += rexec.c rexec.h
endif

AM_CFLAGS = -DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
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
	    -DAPPARMOR_CACHE_DIR=\"$(APPARMOR_CACHE_DIR)\" \
	    -I $(top_srcdir)/src \
	    -I $(top_srcdir)/src/lxc \
	    -I $(top_srcdir)/src/lxc/storage \
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
liblxc_la_SOURCES += seccomp.c
endif

liblxc_la_CFLAGS = -fPIC -DPIC $(AM_CFLAGS) -pthread

liblxc_la_LDFLAGS = \
	-pthread \
	-shared \
	-Wl,-soname,liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)) \
	-version-info @LXC_ABI_MAJOR@

liblxc_la_LIBADD = $(CAP_LIBS) $(SELINUX_LIBS) $(SECCOMP_LIBS)

if ENABLE_CGMANAGER
liblxc_la_LIBADD += $(CGMANAGER_LIBS) $(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS)
liblxc_la_CFLAGS += $(CGMANAGER_CFLAGS) $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
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
LDADD=liblxc.la @CAP_LIBS@ @SELINUX_LIBS@ @SECCOMP_LIBS@

lxc_attach_SOURCES = tools/lxc_attach.c tools/arguments.c rexec.c rexec.h
lxc_autostart_SOURCES = tools/lxc_autostart.c tools/arguments.c
lxc_cgroup_SOURCES = tools/lxc_cgroup.c tools/arguments.c
lxc_config_SOURCES = tools/lxc_config.c tools/arguments.c
lxc_console_SOURCES = tools/lxc_console.c tools/arguments.c
lxc_destroy_SOURCES = tools/lxc_destroy.c tools/arguments.c
lxc_device_SOURCES = tools/lxc_device.c tools/arguments.c
lxc_execute_SOURCES = tools/lxc_execute.c tools/arguments.c
lxc_freeze_SOURCES = tools/lxc_freeze.c tools/arguments.c
lxc_info_SOURCES = tools/lxc_info.c tools/arguments.c
init_lxc_SOURCES = lxc_init.c
lxc_monitor_SOURCES = tools/lxc_monitor.c tools/arguments.c
lxc_ls_SOURCES = tools/lxc_ls.c tools/arguments.c
lxc_copy_SOURCES = tools/lxc_copy.c tools/arguments.c
lxc_start_SOURCES = tools/lxc_start.c tools/arguments.c
lxc_stop_SOURCES = tools/lxc_stop.c tools/arguments.c
lxc_top_SOURCES = tools/lxc_top.c tools/arguments.c
lxc_unfreeze_SOURCES = tools/lxc_unfreeze.c tools/arguments.c
lxc_unshare_SOURCES = tools/lxc_unshare.c tools/arguments.c
lxc_wait_SOURCES = tools/lxc_wait.c tools/arguments.c
lxc_create_SOURCES = tools/lxc_create.c tools/arguments.c
lxc_snapshot_SOURCES = tools/lxc_snapshot.c tools/arguments.c
lxc_usernsexec_SOURCES = tools/lxc_usernsexec.c tools/arguments.c
lxc_checkpoint_SOURCES = tools/lxc_checkpoint.c tools/arguments.c
lxc_user_nic_SOURCES = lxc_user_nic.c namespace.c network.c tools/arguments.c
lxc_monitord_SOURCES = lxc_monitord.c tools/arguments.c

if ENABLE_DEPRECATED
lxc_clone_SOURCES = tools/lxc_clone.c tools/arguments.c
endif

if !HAVE_GETSUBOPT
lxc_copy_SOURCES += ../include/getsubopt.c ../include/getsubopt.h
endif

if HAVE_STATIC_LIBCAP
sbin_PROGRAMS += init.lxc.static

init_lxc_static_SOURCES = lxc_init.c error.c log.c initutils.c caps.c parse.c namespace.c

if !HAVE_GETLINE
if HAVE_FGETLN
init_lxc_static_SOURCES += ../include/getline.c
endif
endif

if !HAVE_STRLCPY
init_lxc_static_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
init_lxc_static_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_GETGRGID_R
liblxc_la_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

init_lxc_static_LDFLAGS = -all-static
init_lxc_static_LDADD = @CAP_LIBS@
init_lxc_static_CFLAGS = $(AM_CFLAGS) -DNO_LXC_CONF
endif

install-exec-local: install-libLTLIBRARIES
	mkdir -p $(DESTDIR)$(datadir)/lxc
	install -c -m 644 lxc.functions $(DESTDIR)$(datadir)/lxc
	mv $(shell readlink -f $(DESTDIR)$(libdir)/liblxc.so) $(DESTDIR)$(libdir)/liblxc.so.@LXC_ABI@
	rm -f $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.1
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.@LXC_ABI@ liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)); \
	ln -sf liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)) liblxc.so

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/lxc/lxc-user-nic

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
