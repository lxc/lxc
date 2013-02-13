pkginclude_HEADERS = \
		arguments.h \
		start.h \
		console.h \
		error.h \
		monitor.h \
		utils.h \
		namespace.h \
		caps.h \
		lxc.h \
		cgroup.h \
		conf.h \
		list.h \
		log.h \
		state.h \
		attach.h \
		lxccontainer.h \
		lxclock.h

if IS_BIONIC
pkginclude_HEADERS += \
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

liblxc_so_SOURCES = \
	arguments.c arguments.h \
	commands.c commands.h \
	start.c start.h \
	stop.c \
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
	apparmor.c apparmor.h \
	lxclock.h lxclock.c \
	lxccontainer.c lxccontainer.h

if IS_BIONIC
liblxc_so_SOURCES += \
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
	-DLOGPATH=\"$(LOGPATH)\"

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
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

if !IS_BIONIC
liblxc_so_LDADD += -lutil -lrt
endif

bin_SCRIPTS = \
	lxc-ps \
	lxc-netstat \
	lxc-checkconfig \
	lxc-version \
	lxc-create \
	lxc-clone \
	lxc-shutdown \
	lxc-destroy

EXTRA_DIST=
if ENABLE_PYTHON
    EXTRA_DIST += lxc-device lxc-ls
    bin_SCRIPTS += lxc-device
    bin_SCRIPTS += lxc-ls
    bin_SCRIPTS += lxc-start-ephemeral
else
    bin_SCRIPTS += legacy/lxc-ls
endif

if ENABLE_LUA
    EXTRA_DIST += lxc-top
    bin_SCRIPTS += lxc-top
endif

bin_PROGRAMS = \
	lxc-attach \
	lxc-unshare \
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
	lxc-kill

pkglibexec_PROGRAMS = \
	lxc-init

#pkglibexec_SCRIPTS = \
#	lxc.functions

AM_LDFLAGS = -Wl,-E
if ENABLE_RPATH
AM_LDFLAGS += -Wl,-rpath -Wl,$(libdir)
endif
LDADD=liblxc.so @CAP_LIBS@ @APPARMOR_LIBS@ @SECCOMP_LIBS@

if !IS_BIONIC
LDADD += -lrt
endif

lxc_attach_SOURCES = lxc_attach.c
lxc_cgroup_SOURCES = lxc_cgroup.c
lxc_checkpoint_SOURCES = lxc_checkpoint.c
lxc_console_SOURCES = lxc_console.c
lxc_execute_SOURCES = lxc_execute.c
lxc_freeze_SOURCES = lxc_freeze.c
lxc_info_SOURCES = lxc_info.c
lxc_init_SOURCES = lxc_init.c
lxc_monitor_SOURCES = lxc_monitor.c
lxc_restart_SOURCES = lxc_restart.c
lxc_start_SOURCES = lxc_start.c
lxc_stop_SOURCES = lxc_stop.c
lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unshare_SOURCES = lxc_unshare.c
lxc_wait_SOURCES = lxc_wait.c
lxc_kill_SOURCES = lxc_kill.c

install-exec-local: install-soPROGRAMS
	mkdir -p $(DESTDIR)$(datadir)/lxc
	install -c -m 644 lxc.functions $(DESTDIR)$(datadir)/lxc
	mv $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.$(VERSION)
	/sbin/ldconfig -l $(DESTDIR)$(libdir)/liblxc.so.$(VERSION)
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.$(VERSION) liblxc.so.$(firstword $(subst ., ,$(VERSION))); \
	ln -sf liblxc.so.$(firstword $(subst ., ,$(VERSION))) liblxc.so

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
