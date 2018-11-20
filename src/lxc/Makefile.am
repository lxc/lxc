pkginclude_HEADERS = attach_options.h \
		     lxccontainer.h \
		     version.h

noinst_HEADERS = attach.h \
		 caps.h \
		 cgroups/cgroup.h \
		 cgroups/cgroup_utils.h \
		 compiler.h \
		 conf.h \
		 confile.h \
		 confile_utils.h \
		 criu.h \
		 error.h \
		 file_utils.h \
		 ../include/netns_ifaddrs.h \
		 initutils.h \
		 list.h \
		 log.h \
		 lxc.h \
		 lxclock.h \
		 macro.h \
		 monitor.h \
		 namespace.h \
		 raw_syscalls.h \
		 start.h \
		 state.h \
		 storage/btrfs.h \
		 storage/dir.h \
		 storage/loop.h \
		 storage/lvm.h \
		 storage/nbd.h \
		 storage/overlay.h \
		 storage/rbd.h \
		 storage/rsync.h \
		 storage/storage.h \
		 storage/storage_utils.h \
		 storage/zfs.h \
		 string_utils.h \
		 syscall_wrappers.h \
		 terminal.h \
		 ../tests/lxctest.h \
		 tools/arguments.h \
		 storage/storage_utils.h \
		 utils.h

if IS_BIONIC
noinst_HEADERS += ../include/lxcmntent.h \
		  ../include/openpty.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
noinst_HEADERS += ../include/prlimit.h
endif
endif

if !HAVE_GETLINE
if HAVE_FGETLN
noinst_HEADERS += ../include/getline.h
endif
endif

if !HAVE_GETSUBOPT
noinst_HEADERS += tools/include/getsubopt.h
endif

if !HAVE_GETGRGID_R
noinst_HEADERS += ../include/getgrgid_r.h
endif

sodir=$(libdir)

LSM_SOURCES = lsm/lsm.c \
	      lsm/lsm.h \
	      lsm/nop.c

if ENABLE_APPARMOR
LSM_SOURCES += lsm/apparmor.c
endif

if ENABLE_SELINUX
LSM_SOURCES += lsm/selinux.c
endif

lib_LTLIBRARIES = liblxc.la
liblxc_la_SOURCES = af_unix.c af_unix.h \
		    attach.c attach.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		    compiler.h \
		    commands.c commands.h \
		    commands_utils.c commands_utils.h \
		    conf.c conf.h \
		    confile.c confile.h \
		    confile_utils.c confile_utils.h \
		    criu.c criu.h \
		    error.c error.h \
		    execute.c \
		    freezer.c \
		    file_utils.c file_utils.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    list.h \
		    log.c log.h \
		    lxc.h \
		    lxccontainer.c lxccontainer.h \
		    lxclock.c lxclock.h \
		    lxcseccomp.h \
		    macro.h \
		    mainloop.c mainloop.h \
		    namespace.c namespace.h \
		    nl.c nl.h \
		    network.c network.h \
		    monitor.c monitor.h \
		    parse.c parse.h \
		    raw_syscalls.c raw_syscalls.h \
		    ringbuf.c ringbuf.h \
		    rtnl.c rtnl.h \
		    state.c state.h \
		    start.c start.h \
		    storage/btrfs.c storage/btrfs.h \
		    storage/dir.c storage/dir.h \
		    storage/loop.c storage/loop.h \
		    storage/lvm.c storage/lvm.h \
		    storage/nbd.c storage/nbd.h \
		    storage/overlay.c storage/overlay.h \
		    storage/rbd.c storage/rbd.h \
		    storage/rsync.c storage/rsync.h \
		    storage/storage.c storage/storage.h \
		    storage/storage_utils.c storage/storage_utils.h \
		    storage/zfs.c storage/zfs.h \
		    string_utils.c string_utils.h \
		    sync.c sync.h \
		    syscall_wrappers.h \
		    terminal.c \
		    utils.c utils.h \
		    version.h \
		    $(LSM_SOURCES)

if IS_BIONIC
liblxc_la_SOURCES += ../include/lxcmntent.c ../include/lxcmntent.h \
		     ../include/openpty.c ../include/openpty.h
endif

if !HAVE_GETGRGID_R
liblxc_la_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_GETLINE
if HAVE_FGETLN
liblxc_la_SOURCES += ../include/getline.c ../include/getline.h
endif
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
liblxc_la_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif

if ENABLE_SECCOMP
liblxc_la_SOURCES += seccomp.c
endif

if !HAVE_STRLCPY
liblxc_la_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
liblxc_la_SOURCES += ../include/strlcat.c ../include/strlcat.h
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
	    -I $(top_srcdir)/src \
	    -I $(top_srcdir)/src/lxc \
	    -I $(top_srcdir)/src/lxc/storage \
	    -I $(top_srcdir)/src/lxc/cgroups

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
endif

if ENABLE_GNUTLS
AM_CFLAGS += -DHAVE_LIBGNUTLS
endif

if ENABLE_SECCOMP
AM_CFLAGS += -DHAVE_SECCOMP \
	     $(SECCOMP_CFLAGS)
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

if USE_CONFIGPATH_LOGS
AM_CFLAGS += -DUSE_CONFIGPATH_LOGS
endif

# build the shared library
liblxc_la_CFLAGS = -fPIC \
		   -DPIC \
		   $(AM_CFLAGS) \
		   -pthread

liblxc_la_LDFLAGS = -pthread \
		    -Wl,-no-undefined \
		    -Wl,-soname,liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)) \
		    -version-info @LXC_ABI_MAJOR@

liblxc_la_LIBADD = $(CAP_LIBS) \
		   $(GNUTLS_LIBS) \
		   $(SELINUX_LIBS) \
		   $(SECCOMP_LIBS)

bin_SCRIPTS=

if ENABLE_COMMANDS
bin_SCRIPTS += cmd/lxc-checkconfig \
	       cmd/lxc-update-config
endif

if ENABLE_TOOLS
bin_PROGRAMS = lxc-attach \
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
	       lxc-wait
endif

if ENABLE_COMMANDS

if ENABLE_TOOLS
bin_PROGRAMS += lxc-usernsexec
else
bin_PROGRAMS = lxc-usernsexec
endif

sbin_PROGRAMS = init.lxc

pkglibexec_PROGRAMS = lxc-monitord \
		      lxc-user-nic
endif

AM_LDFLAGS = -Wl,-E

if ENABLE_RPATH
AM_LDFLAGS += -Wl,-rpath -Wl,$(libdir)
endif

LDADD = liblxc.la \
	@CAP_LIBS@ \
	@GNUTLS_LIBS@ \
	@SECCOMP_LIBS@ \
	@SELINUX_LIBS@

if ENABLE_TOOLS
lxc_attach_SOURCES = tools/lxc_attach.c \
		     tools/arguments.c tools/arguments.h
lxc_autostart_SOURCES = tools/lxc_autostart.c \
			tools/arguments.c tools/arguments.h
lxc_cgroup_SOURCES = tools/lxc_cgroup.c \
		     tools/arguments.c tools/arguments.h
lxc_config_SOURCES = tools/lxc_config.c \
		     tools/arguments.c tools/arguments.h
lxc_console_SOURCES = tools/lxc_console.c \
		      tools/arguments.c tools/arguments.h
lxc_destroy_SOURCES = tools/lxc_destroy.c \
		      tools/arguments.c tools/arguments.h
lxc_device_SOURCES = tools/lxc_device.c \
		     tools/arguments.c tools/arguments.h
lxc_execute_SOURCES = tools/lxc_execute.c \
		      tools/arguments.c tools/arguments.h
lxc_freeze_SOURCES = tools/lxc_freeze.c \
		     tools/arguments.c tools/arguments.h
lxc_info_SOURCES = tools/lxc_info.c \
		   tools/arguments.c tools/arguments.h
lxc_monitor_SOURCES = tools/lxc_monitor.c \
		      macro.h \
		      tools/arguments.c tools/arguments.h
lxc_ls_SOURCES = tools/lxc_ls.c \
		 tools/arguments.c tools/arguments.h
lxc_copy_SOURCES = tools/lxc_copy.c \
		   tools/arguments.c tools/arguments.h \
		   storage/storage_utils.c storage/storage_utils.h
lxc_start_SOURCES = tools/lxc_start.c \
		    tools/arguments.c tools/arguments.h
lxc_stop_SOURCES = tools/lxc_stop.c \
		   tools/arguments.c tools/arguments.h
lxc_top_SOURCES = tools/lxc_top.c \
		  tools/arguments.c tools/arguments.h
lxc_unfreeze_SOURCES = tools/lxc_unfreeze.c \
		       tools/arguments.c tools/arguments.h
lxc_unshare_SOURCES = tools/lxc_unshare.c \
		      tools/arguments.c tools/arguments.h
lxc_wait_SOURCES = tools/lxc_wait.c \
		   tools/arguments.c tools/arguments.h
lxc_create_SOURCES = tools/lxc_create.c \
		     tools/arguments.c tools/arguments.h \
		     storage/storage_utils.c storage/storage_utils.h
lxc_snapshot_SOURCES = tools/lxc_snapshot.c \
		       tools/arguments.c tools/arguments.h
lxc_checkpoint_SOURCES = tools/lxc_checkpoint.c \
			 tools/arguments.c tools/arguments.h
endif

if ENABLE_COMMANDS
# Binaries shipping with liblxc
init_lxc_SOURCES = cmd/lxc_init.c \
		   compiler.h \
		   error.h \
		   initutils.c initutils.h \
		   parse.c parse.h \
		   raw_syscalls.c raw_syscalls.h \
		   string_utils.c string_utils.h
lxc_monitord_SOURCES = cmd/lxc_monitord.c \
		       af_unix.c af_unix.h \
		       log.c log.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       raw_syscalls.c raw_syscalls.h \
		       utils.c utils.h
lxc_user_nic_SOURCES = cmd/lxc_user_nic.c \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       log.c log.h \
		       network.c network.h \
		       parse.c parse.h \
		       raw_syscalls.c raw_syscalls.h \
		       syscall_wrappers.h
lxc_usernsexec_SOURCES = cmd/lxc_usernsexec.c \
			 conf.c conf.h \
			 list.h \
			 log.c log.h \
			 macro.h \
			 file_utils.c file_utils.h \
			 string_utils.c string_utils.h \
			 syscall_wrappers.h \
			 utils.c utils.h
endif


if ENABLE_TOOLS
if !HAVE_GETSUBOPT
lxc_copy_SOURCES += tools/include/getsubopt.c tools/include/getsubopt.h
endif
endif

if ENABLE_COMMANDS
if HAVE_STATIC_LIBCAP
sbin_PROGRAMS += init.lxc.static

init_lxc_static_SOURCES = cmd/lxc_init.c \
			  caps.c caps.h \
			  error.c error.h \
			  initutils.c initutils.h \
			  file_utils.c file_utils.h \
			  log.c log.h \
			  macro.h \
			  namespace.c namespace.h \
			  string_utils.c string_utils.h

if !HAVE_GETLINE
if HAVE_FGETLN
init_lxc_static_SOURCES += ../include/getline.c ../include/getline.h
endif
endif

if !HAVE_STRLCPY
init_lxc_static_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
init_lxc_static_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

init_lxc_static_LDFLAGS = -all-static
init_lxc_static_LDADD = @CAP_LIBS@
init_lxc_static_CFLAGS = $(AM_CFLAGS) -DNO_LXC_CONF
endif
endif

if ENABLE_PAM
if HAVE_PAM
pam_LTLIBRARIES = pam_cgfs.la

pam_cgfs_la_SOURCES = pam/pam_cgfs.c \
		      file_utils.c file_utils.h \
		      macro.h \
		      string_utils.c string_utils.h

if !HAVE_STRLCAT
pam_cgfs_la_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_STRLCPY
pam_cgfs_la_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

pam_cgfs_la_CFLAGS = $(AM_CFLAGS) -DNO_LXC_CONF

pam_cgfs_la_LIBADD = $(AM_LIBS) \
		     $(PAM_LIBS) \
		     -L$(top_srcdir)

pam_cgfs_la_LDFLAGS = $(AM_LDFLAGS) \
		      -avoid-version \
		      -module \
		      -shared \
		      -Wl,-no-undefined
endif
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
	$(RM) $(DESTDIR)$(libdir)/liblxc.a
if ENABLE_PAM
if HAVE_PAM
	$(RM) $(DESTDIR)$(pamdir)/pam_cgfs.so*

install-data-hook: install-pamLTLIBRARIES
	$(RM) "$(DESTDIR)$(pamdir)/pam_cgfs.la"
	$(RM) "$(DESTDIR)$(pamdir)/pam_cgfs.a"
endif
endif
