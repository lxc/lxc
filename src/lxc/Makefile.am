pkginclude_HEADERS = \
		arguments.h \
		attach.h \
		attach_options.h \
		bdev.h \
		caps.h \
		cgroup.h \
		conf.h \
		console.h \
		error.h \
		list.h \
		log.h \
		lxccontainer.h \
		lxc.h \
		lxclock.h \
		monitor.h \
		namespace.h \
		start.h \
		state.h \
		utils.h \
		version.h

if IS_BIONIC
pkginclude_HEADERS += \
	../include/ifaddrs.h \
	../include/openpty.h \
	../include/lxcmntent.h
endif

if !HAVE_GETLINE
if HAVE_FGETLN
pkginclude_HEADERS += ../include/getline.h
endif
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
	bdev.c bdev.h \
	commands.c commands.h \
	start.c start.h \
	execute.c \
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
	sync.c sync.h \
	namespace.h namespace.c \
	conf.c conf.h \
	confile.c confile.h \
	list.h \
	state.c state.h \
	log.c log.h \
	attach.c attach.h \
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
	version.c version.h \
	\
	$(LSM_SOURCES)

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

AM_CFLAGS=-I$(top_srcdir)/src \
	-DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	-DLXCPATH=\"$(LXCPATH)\" \
	-DLXC_GLOBAL_CONF=\"$(LXC_GLOBAL_CONF)\" \
	-DLXCINITDIR=\"$(LXCINITDIR)\" \
	-DLXCTEMPLATEDIR=\"$(LXCTEMPLATEDIR)\" \
	-DLOGPATH=\"$(LOGPATH)\" \
	-DLXC_DEFAULT_CONFIG=\"$(LXC_DEFAULT_CONFIG)\" \
	-DLXC_USERNIC_DB=\"$(LXC_USERNIC_DB)\" \
	-DLXC_USERNIC_CONF=\"$(LXC_USERNIC_CONF)\" \
	-DDEFAULT_CGROUP_PATTERN=\"$(DEFAULT_CGROUP_PATTERN)\"

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

if HAVE_NEWUIDMAP
AM_CFLAGS += -DHAVE_NEWUIDMAP
endif

if USE_CONFIGPATH_LOGS
AM_CFLAGS += -DUSE_CONFIGPATH_LOGS
endif

if ENABLE_SECCOMP
AM_CFLAGS += -DHAVE_SECCOMP
liblxc_so_SOURCES += seccomp.c
endif

liblxc_so_CFLAGS = -fPIC -DPIC $(AM_CFLAGS)

liblxc_so_LDFLAGS = \
	-shared \
	-Wl,-soname,liblxc.so.$(firstword $(subst ., ,$(VERSION)))

liblxc_so_LDADD = $(CAP_LIBS) $(APPARMOR_LIBS) $(SECCOMP_LIBS)

bin_SCRIPTS = \
	lxc-ps \
	lxc-netstat \
	lxc-checkconfig \
	lxc-version

EXTRA_DIST = \
	lxc-device \
	lxc-ls \
	lxc-top

if ENABLE_PYTHON
bin_SCRIPTS += lxc-device
bin_SCRIPTS += lxc-ls
bin_SCRIPTS += lxc-start-ephemeral
else
bin_SCRIPTS += legacy/lxc-ls
endif

if ENABLE_LUA
bin_SCRIPTS += lxc-top
endif

bin_PROGRAMS = \
	lxc-attach \
	lxc-unshare \
	lxc-stop \
	lxc-start \
	lxc-clone \
	lxc-execute \
	lxc-monitor \
	lxc-monitord \
	lxc-wait \
	lxc-console \
	lxc-freeze \
	lxc-info \
	lxc-cgroup \
	lxc-unfreeze \
	lxc-checkpoint \
	lxc-restart \
	lxc-kill \
	lxc-config \
	lxc-destroy \
	lxc-create \
	lxc-user-nic \
	lxc-snapshot

if HAVE_NEWUIDMAP
bin_PROGRAMS += lxc-usernsexec
endif

pkglibexec_PROGRAMS = \
	lxc-init

AM_LDFLAGS = -Wl,-E
if ENABLE_RPATH
AM_LDFLAGS += -Wl,-rpath -Wl,$(libdir)
endif
LDADD=liblxc.so @CAP_LIBS@ @APPARMOR_LIBS@ @SECCOMP_LIBS@

lxc_attach_SOURCES = lxc_attach.c
lxc_cgroup_SOURCES = lxc_cgroup.c
lxc_checkpoint_SOURCES = lxc_checkpoint.c
lxc_config_SOURCES = lxc_config.c
lxc_console_SOURCES = lxc_console.c
lxc_destroy_SOURCES = lxc_destroy.c
lxc_execute_SOURCES = lxc_execute.c
lxc_freeze_SOURCES = lxc_freeze.c
lxc_info_SOURCES = lxc_info.c
lxc_init_SOURCES = lxc_init.c
lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitord_SOURCES = lxc_monitord.c
lxc_restart_SOURCES = lxc_restart.c
lxc_clone_SOURCES = lxc_clone.c
lxc_start_SOURCES = lxc_start.c
lxc_stop_SOURCES = lxc_stop.c
lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unshare_SOURCES = lxc_unshare.c
lxc_wait_SOURCES = lxc_wait.c
lxc_kill_SOURCES = lxc_kill.c
lxc_create_SOURCES = lxc_create.c
lxc_snapshot_SOURCES = lxc_snapshot.c
lxc_usernsexec_SOURCES = lxc_usernsexec.c
lxc_user_nic_SOURCES = lxc_user_nic.c

install-exec-local: install-soPROGRAMS
	mkdir -p $(DESTDIR)$(datadir)/lxc
	install -c -m 644 lxc.functions $(DESTDIR)$(datadir)/lxc
	mv $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.$(VERSION)
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.$(VERSION) liblxc.so.$(firstword $(subst ., ,$(VERSION))); \
	ln -sf liblxc.so.$(firstword $(subst ., ,$(VERSION))) liblxc.so

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
