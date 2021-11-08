# SPDX-License-Identifier: LGPL-2.1+

pkginclude_HEADERS = attach_options.h \
		     lxccontainer.h \
		     version.h

noinst_HEADERS = api_extensions.h \
		 attach.h \
		 ../include/bpf.h \
		 ../include/bpf_common.h \
		 caps.h \
		 cgroups/cgroup.h \
		 cgroups/cgroup_utils.h \
		 cgroups/cgroup2_devices.h \
		 compiler.h \
		 conf.h \
		 confile.h \
		 confile_utils.h \
		 criu.h \
		 error.h \
		 error_utils.h \
		 file_utils.h \
		 hlist.h \
		 ../include/strchrnul.h \
		 ../include/strlcat.h \
		 ../include/strlcpy.h \
		 ../include/netns_ifaddrs.h \
		 initutils.h \
		 list.h \
		 log.h \
		 lxc.h \
		 lxclock.h \
		 macro.h \
		 memory_utils.h \
		 monitor.h \
		 mount_utils.h \
		 namespace.h \
		 process_utils.h \
		 rexec.h \
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
		 syscall_numbers.h \
		 syscall_wrappers.h \
		 terminal.h \
		 ../tests/lxctest.h \
		 tools/arguments.h \
		 utils.h \
		 uuid.h

if IS_BIONIC
noinst_HEADERS += ../include/fexecve.h \
		  ../include/lxcmntent.h
endif

if !HAVE_OPENPTY
noinst_HEADERS += ../include/openpty.h
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
		    api_extensions.h \
		    attach.c attach.h \
		    ../include/bpf.h \
		    ../include/bpf_common.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
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
		    error_utils.h \
		    freezer.c \
		    file_utils.c file_utils.h \
		    hlist.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    list.h \
		    log.c log.h \
		    lxc.h \
		    lxccontainer.c lxccontainer.h \
		    lxclock.c lxclock.h \
		    lxcseccomp.h \
		    macro.h \
		    memory_utils.h \
		    mainloop.c mainloop.h \
		    mount_utils.c mount_utils.h \
		    namespace.c namespace.h \
		    network.c network.h \
		    nl.c nl.h \
		    monitor.c monitor.h \
		    parse.c parse.h \
		    process_utils.c process_utils.h \
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
		    syscall_numbers.h \
		    syscall_wrappers.h \
		    terminal.c terminal.h \
		    utils.c utils.h \
		    uuid.c uuid.h \
		    version.h \
		    $(LSM_SOURCES)

if IS_BIONIC
liblxc_la_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		     ../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_OPENPTY
liblxc_la_SOURCES += ../include/openpty.c ../include/openpty.h
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
liblxc_la_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRLCPY
liblxc_la_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
liblxc_la_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_STRCHRNUL
liblxc_la_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if ENFORCE_MEMFD_REXEC
liblxc_la_SOURCES += rexec.c rexec.h
endif

AM_CFLAGS += -DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
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
	     -I $(top_srcdir)/src/include \
	     -I $(top_srcdir)/src/lxc \
	     -I $(top_srcdir)/src/lxc/storage \
	     -I $(top_srcdir)/src/lxc/cgroups
if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
endif

if ENABLE_OPENSSL
AM_CFLAGS += -DHAVE_OPENSSL
endif

if ENABLE_SECCOMP
AM_CFLAGS += -DHAVE_SECCOMP \
	     $(SECCOMP_CFLAGS)
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

if ENABLE_DLOG
AM_CFLAGS += -DHAVE_DLOG \
	      $(DLOG_CFLAGS)
endif

if USE_CONFIGPATH_LOGS
AM_CFLAGS += -DUSE_CONFIGPATH_LOGS
endif

# build the shared library
liblxc_la_CFLAGS = -fPIC \
		   -DPIC \
		   $(AM_CFLAGS) \
		   $(LIBLXC_SANITIZER) \
		   -pthread

liblxc_la_LDFLAGS = -pthread \
		    -Wl,-soname,liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)) \
		    -version-info @LXC_ABI_MAJOR@

if ENABLE_NO_UNDEFINED
liblxc_la_LDFLAGS += -Wl,-no-undefined
endif

liblxc_la_LIBADD = $(CAP_LIBS) \
		   $(OPENSSL_LIBS) \
		   $(SELINUX_LIBS) \
		   $(SECCOMP_LIBS) \
		   $(DLOG_LIBS) \
		   $(LIBURING_LIBS)

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

AM_LDFLAGS += -Wl,-E

if ENABLE_RPATH
AM_LDFLAGS += -Wl,-rpath -Wl,$(libdir)
endif

LDADD = liblxc.la \
	@CAP_LIBS@ \
	@OPENSSL_LIBS@ \
	@SECCOMP_LIBS@ \
	@SELINUX_LIBS@ \
	@DLOG_LIBS@ \
	@LIBURING_LIBS@

if ENABLE_TOOLS
lxc_attach_SOURCES = tools/lxc_attach.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_attach_SOURCES += $(liblxc_la_SOURCES)
lxc_attach_LDFLAGS = -all-static -pthread
else
lxc_attach_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      rexec.c rexec.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_attach_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_attach_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_attach_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_attach_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_attach_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_attach_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_attach_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_attach_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_autostart_SOURCES = tools/lxc_autostart.c \
			tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_autostart_SOURCES += $(liblxc_la_SOURCES)
lxc_autostart_LDFLAGS = -all-static -pthread
else
lxc_autostart_SOURCES += af_unix.c af_unix.h \
			 caps.c caps.h \
			 cgroups/cgfsng.c \
			 cgroups/cgroup.c cgroups/cgroup.h \
			 cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			 cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			 commands.c commands.h \
			 commands_utils.c commands_utils.h \
			 conf.c conf.h \
			 confile.c confile.h \
			 confile_utils.c confile_utils.h \
			 error.c error.h \
			 file_utils.c file_utils.h \
			 ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			 initutils.c initutils.h \
			 log.c log.h \
			 lxclock.c lxclock.h \
			 mainloop.c mainloop.h \
			 monitor.c monitor.h \
			 mount_utils.c mount_utils.h \
			 namespace.c namespace.h \
			 network.c network.h \
			 nl.c nl.h \
			 parse.c parse.h \
			 process_utils.c process_utils.h \
			 ringbuf.c ringbuf.h \
			 start.c start.h \
			 state.c state.h \
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
			 terminal.c terminal.h \
			 utils.c utils.h \
			 uuid.c uuid.h \
			 $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_autostart_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_autostart_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_autostart_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_autostart_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_autostart_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_autostart_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_autostart_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_autostart_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_cgroup_SOURCES = tools/lxc_cgroup.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_cgroup_SOURCES += $(liblxc_la_SOURCES)
lxc_cgroup_LDFLAGS = -all-static -pthread
else
lxc_cgroup_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_cgroup_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_cgroup_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_cgroup_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_cgroup_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_cgroup_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_cgroup_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_cgroup_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_cgroup_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_config_SOURCES = tools/lxc_config.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_config_SOURCES += $(liblxc_la_SOURCES)
lxc_config_LDFLAGS = -all-static -pthread
else
lxc_config_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_config_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_config_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_config_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_config_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_config_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_config_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_config_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_config_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_console_SOURCES = tools/lxc_console.c \
		      tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_console_SOURCES += $(liblxc_la_SOURCES)
lxc_console_LDFLAGS = -all-static -pthread
else
lxc_console_SOURCES += af_unix.c af_unix.h \
		       caps.c caps.h \
		       cgroups/cgfsng.c \
		       cgroups/cgroup.c cgroups/cgroup.h \
		       cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		       cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		       commands.c commands.h \
		       commands_utils.c commands_utils.h \
		       conf.c conf.h \
		       confile.c confile.h \
		       confile_utils.c confile_utils.h \
		       error.c error.h \
		       file_utils.c file_utils.h \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       initutils.c initutils.h \
		       log.c log.h \
		       lxclock.c lxclock.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       mount_utils.c mount_utils.h \
		       namespace.c namespace.h \
		       network.c network.h \
		       nl.c nl.h \
		       parse.c parse.h \
		       process_utils.c process_utils.h \
		       ringbuf.c ringbuf.h \
		       start.c start.h \
		       state.c state.h \
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
		       terminal.c terminal.h \
		       utils.c utils.h \
		       uuid.c uuid.h \
		       $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_console_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_console_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_console_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_console_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_console_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_console_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_console_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_console_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_destroy_SOURCES = tools/lxc_destroy.c \
		      tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_destroy_SOURCES += $(liblxc_la_SOURCES)
lxc_destroy_LDFLAGS = -all-static -pthread
else
lxc_destroy_SOURCES += af_unix.c af_unix.h \
		       caps.c caps.h \
		       cgroups/cgfsng.c \
		       cgroups/cgroup.c cgroups/cgroup.h \
		       cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		       cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		       commands.c commands.h \
		       commands_utils.c commands_utils.h \
		       conf.c conf.h \
		       confile.c confile.h \
		       confile_utils.c confile_utils.h \
		       error.c error.h \
		       file_utils.c file_utils.h \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       initutils.c initutils.h \
		       log.c log.h \
		       lxclock.c lxclock.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       mount_utils.c mount_utils.h \
		       namespace.c namespace.h \
		       network.c network.h \
		       nl.c nl.h \
		       parse.c parse.h \
		       process_utils.c process_utils.h \
		       ringbuf.c ringbuf.h \
		       start.c start.h \
		       state.c state.h \
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
		       terminal.c terminal.h \
		       utils.c utils.h \
		       uuid.c uuid.h \
		       $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_destroy_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_destroy_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_destroy_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_destroy_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_destroy_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_destroy_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_destroy_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_destroy_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_device_SOURCES = tools/lxc_device.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_device_SOURCES += $(liblxc_la_SOURCES)
lxc_device_LDFLAGS = -all-static -pthread
else
lxc_device_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_device_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_device_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_device_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_device_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_device_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_device_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_device_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_device_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_execute_SOURCES = tools/lxc_execute.c \
		      tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_execute_SOURCES += $(liblxc_la_SOURCES)
lxc_execute_LDFLAGS = -all-static -pthread
else
lxc_execute_SOURCES += af_unix.c af_unix.h \
		       caps.c caps.h \
		       cgroups/cgfsng.c \
		       cgroups/cgroup.c cgroups/cgroup.h \
		       cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		       cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		       commands.c commands.h \
		       commands_utils.c commands_utils.h \
		       conf.c conf.h \
		       confile.c confile.h \
		       confile_utils.c confile_utils.h \
		       error.c error.h \
		       file_utils.c file_utils.h \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       initutils.c initutils.h \
		       log.c log.h \
		       lxclock.c lxclock.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       mount_utils.c mount_utils.h \
		       namespace.c namespace.h \
		       network.c network.h \
		       nl.c nl.h \
		       parse.c parse.h \
		       process_utils.c process_utils.h \
		       ringbuf.c ringbuf.h \
		       start.c start.h \
		       state.c state.h \
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
		       terminal.c terminal.h \
		       utils.c utils.h \
		       uuid.c uuid.h \
		       $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_execute_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_execute_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_execute_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_execute_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_execute_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_execute_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_execute_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_execute_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_freeze_SOURCES = tools/lxc_freeze.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_freeze_SOURCES += $(liblxc_la_SOURCES)
lxc_freeze_LDFLAGS = -all-static -pthread
else
lxc_freeze_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_freeze_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_freeze_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_freeze_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_freeze_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_freeze_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_freeze_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_freeze_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_freeze_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_info_SOURCES = tools/lxc_info.c \
		   tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_info_SOURCES += $(liblxc_la_SOURCES)
lxc_info_LDFLAGS = -all-static -pthread
else
lxc_info_SOURCES += af_unix.c af_unix.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		    cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		    commands.c commands.h \
		    commands_utils.c commands_utils.h \
		    conf.c conf.h \
		    confile.c confile.h \
		    confile_utils.c confile_utils.h \
		    error.c error.h \
		    file_utils.c file_utils.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    log.c log.h \
		    lxclock.c lxclock.h \
		    mainloop.c mainloop.h \
		    monitor.c monitor.h \
		    mount_utils.c mount_utils.h \
		    namespace.c namespace.h \
		    network.c network.h \
		    nl.c nl.h \
		    parse.c parse.h \
		    process_utils.c process_utils.h \
		    ringbuf.c ringbuf.h \
		    start.c start.h \
		    state.c state.h \
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
		    terminal.c terminal.h \
		    utils.c utils.h \
		    uuid.c uuid.h \
		    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_info_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_info_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_info_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_info_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_info_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_info_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_info_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_info_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_monitor_SOURCES = tools/lxc_monitor.c \
		      tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_monitor_SOURCES += $(liblxc_la_SOURCES)
lxc_monitor_LDFLAGS = -all-static -pthread
else
lxc_monitor_SOURCES += af_unix.c af_unix.h \
		       caps.c caps.h \
		       cgroups/cgfsng.c \
		       cgroups/cgroup.c cgroups/cgroup.h \
		       cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		       cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		       commands.c commands.h \
		       commands_utils.c commands_utils.h \
		       conf.c conf.h \
		       confile.c confile.h \
		       confile_utils.c confile_utils.h \
		       error.c error.h \
		       file_utils.c file_utils.h \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       initutils.c initutils.h \
		       log.c log.h \
		       lxclock.c lxclock.h \
		       macro.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       mount_utils.c mount_utils.h \
		       namespace.c namespace.h \
		       network.c network.h \
		       nl.c nl.h \
		       parse.c parse.h \
		       process_utils.c process_utils.h \
		       ringbuf.c ringbuf.h \
		       start.c start.h \
		       state.c state.h \
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
		       terminal.c terminal.h \
		       utils.c utils.h \
		       uuid.c uuid.h \
		       $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_monitor_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_monitor_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_monitor_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_monitor_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_monitor_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_monitor_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_monitor_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_monitor_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_ls_SOURCES = tools/lxc_ls.c \
		 tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_ls_SOURCES += $(liblxc_la_SOURCES)
lxc_ls_LDFLAGS = -all-static -pthread
else
lxc_ls_SOURCES += af_unix.c af_unix.h \
		  caps.c caps.h \
		  cgroups/cgfsng.c \
		  cgroups/cgroup.c cgroups/cgroup.h \
		  cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		  cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		  commands.c commands.h \
		  commands_utils.c commands_utils.h \
		  conf.c conf.h \
		  confile.c confile.h \
		  confile_utils.c confile_utils.h \
		  error.c error.h \
		  file_utils.c file_utils.h \
		  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		  initutils.c initutils.h \
		  log.c log.h \
		  lxclock.c lxclock.h \
		  mainloop.c mainloop.h \
		  memory_utils.h \
		  monitor.c monitor.h \
		  mount_utils.c mount_utils.h \
		  namespace.c namespace.h \
		  network.c network.h \
		  nl.c nl.h \
		  parse.c parse.h \
		  process_utils.c process_utils.h \
		  ringbuf.c ringbuf.h \
		  start.c start.h \
		  state.c state.h \
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
		  terminal.c terminal.h \
		  utils.c utils.h \
		  uuid.c uuid.h \
		  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_ls_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_ls_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_ls_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_ls_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_ls_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_ls_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_ls_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_ls_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_copy_SOURCES = tools/lxc_copy.c \
		   tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_copy_SOURCES += $(liblxc_la_SOURCES)
lxc_copy_LDFLAGS = -all-static -pthread
else
lxc_copy_SOURCES += af_unix.c af_unix.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		    cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		    commands.c commands.h \
		    commands_utils.c commands_utils.h \
		    conf.c conf.h \
		    confile.c confile.h \
		    confile_utils.c confile_utils.h \
		    error.c error.h \
		    file_utils.c file_utils.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    log.c log.h \
		    lxclock.c lxclock.h \
		    mainloop.c mainloop.h \
		    monitor.c monitor.h \
		    mount_utils.c mount_utils.h \
		    namespace.c namespace.h \
		    network.c network.h \
		    nl.c nl.h \
		    parse.c parse.h \
		    process_utils.c process_utils.h \
		    ringbuf.c ringbuf.h \
		    start.c start.h \
		    state.c state.h \
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
		    terminal.c terminal.h \
		    utils.c utils.h \
		    uuid.c uuid.h \
		    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_copy_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_copy_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_copy_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_copy_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_copy_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_copy_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_copy_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_copy_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_start_SOURCES = tools/lxc_start.c \
		    tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_start_SOURCES += $(liblxc_la_SOURCES)
lxc_start_LDFLAGS = -all-static -pthread
else
lxc_start_SOURCES += af_unix.c af_unix.h \
		     caps.c caps.h \
		     cgroups/cgfsng.c \
		     cgroups/cgroup.c cgroups/cgroup.h \
		     cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		     cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		     commands.c commands.h \
		     commands_utils.c commands_utils.h \
		     conf.c conf.h \
		     confile.c confile.h \
		     confile_utils.c confile_utils.h \
		     error.c error.h \
		     file_utils.c file_utils.h \
		     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		     initutils.c initutils.h \
		     log.c log.h \
		     lxclock.c lxclock.h \
		     mainloop.c mainloop.h \
		     monitor.c monitor.h \
		     mount_utils.c mount_utils.h \
		     namespace.c namespace.h \
		     network.c network.h \
		     nl.c nl.h \
		     parse.c parse.h \
		     process_utils.c process_utils.h \
		     ringbuf.c ringbuf.h \
		     start.c start.h \
		     state.c state.h \
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
		     terminal.c terminal.h \
		     utils.c utils.h \
		     uuid.c uuid.h \
		     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_start_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_start_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_start_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_start_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_start_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_start_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_start_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_start_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_stop_SOURCES = tools/lxc_stop.c \
		   tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_stop_SOURCES += $(liblxc_la_SOURCES)
lxc_stop_LDFLAGS = -all-static -pthread
else
lxc_stop_SOURCES += af_unix.c af_unix.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		    cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		    commands.c commands.h \
		    commands_utils.c commands_utils.h \
		    conf.c conf.h \
		    confile.c confile.h \
		    confile_utils.c confile_utils.h \
		    error.c error.h \
		    file_utils.c file_utils.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    log.c log.h \
		    lxclock.c lxclock.h \
		    mainloop.c mainloop.h \
		    monitor.c monitor.h \
		    mount_utils.c mount_utils.h \
		    namespace.c namespace.h \
		    network.c network.h \
		    nl.c nl.h \
		    parse.c parse.h \
		    process_utils.c process_utils.h \
		    ringbuf.c ringbuf.h \
		    start.c start.h \
		    state.c state.h \
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
		    terminal.c terminal.h \
		    utils.c utils.h \
		    uuid.c uuid.h \
		    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_stop_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_stop_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_stop_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_stop_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_stop_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_stop_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_stop_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_stop_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_top_SOURCES = tools/lxc_top.c \
		  tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_top_SOURCES += $(liblxc_la_SOURCES)
lxc_top_LDFLAGS = -all-static -pthread
else
lxc_top_SOURCES += af_unix.c af_unix.h \
		   caps.c caps.h \
		   cgroups/cgfsng.c \
		   cgroups/cgroup.c cgroups/cgroup.h \
		   cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		   cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		   commands.c commands.h \
		   commands_utils.c commands_utils.h \
		   conf.c conf.h \
		   confile.c confile.h \
		   confile_utils.c confile_utils.h \
		   error.c error.h \
		   file_utils.c file_utils.h \
		   ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		   initutils.c initutils.h \
		   log.c log.h \
		   lxclock.c lxclock.h \
		   mainloop.c mainloop.h \
		   monitor.c monitor.h \
		   mount_utils.c mount_utils.h \
		   namespace.c namespace.h \
		   network.c network.h \
		   nl.c nl.h \
		   parse.c parse.h \
		   process_utils.c process_utils.h \
		   ringbuf.c ringbuf.h \
		   start.c start.h \
		   state.c state.h \
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
		   terminal.c terminal.h \
		   utils.c utils.h \
		   uuid.c uuid.h \
		   $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_top_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_top_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_top_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_top_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_top_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_top_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_top_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_top_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_unfreeze_SOURCES = tools/lxc_unfreeze.c \
		       tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_unfreeze_SOURCES += $(liblxc_la_SOURCES)
lxc_unfreeze_LDFLAGS = -all-static -pthread
else
lxc_unfreeze_SOURCES += af_unix.c af_unix.h \
			caps.c caps.h \
			cgroups/cgfsng.c \
			cgroups/cgroup.c cgroups/cgroup.h \
			cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			commands.c commands.h \
			commands_utils.c commands_utils.h \
			conf.c conf.h \
			confile.c confile.h \
			confile_utils.c confile_utils.h \
			error.c error.h \
			file_utils.c file_utils.h \
			../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			initutils.c initutils.h \
			log.c log.h \
			lxclock.c lxclock.h \
			mainloop.c mainloop.h \
			monitor.c monitor.h \
			mount_utils.c mount_utils.h \
			namespace.c namespace.h \
			network.c network.h \
			nl.c nl.h \
			parse.c parse.h \
			process_utils.c process_utils.h \
			ringbuf.c ringbuf.h \
			start.c start.h \
			state.c state.h \
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
			terminal.c terminal.h \
			utils.c utils.h \
			uuid.c uuid.h \
			$(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_unfreeze_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_unfreeze_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_unfreeze_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_unfreeze_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_unfreeze_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_unfreeze_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_unfreeze_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_unfreeze_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_unshare_SOURCES = tools/lxc_unshare.c \
		      tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_unshare_SOURCES += $(liblxc_la_SOURCES)
lxc_unshare_LDFLAGS = -all-static -pthread
else
lxc_unshare_SOURCES += af_unix.c af_unix.h \
		       caps.c caps.h \
		       cgroups/cgfsng.c \
		       cgroups/cgroup.c cgroups/cgroup.h \
		       cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		       cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		       commands.c commands.h \
		       commands_utils.c commands_utils.h \
		       conf.c conf.h \
		       confile.c confile.h \
		       confile_utils.c confile_utils.h \
		       error.c error.h \
		       file_utils.c file_utils.h \
		       ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		       initutils.c initutils.h \
		       log.c log.h \
		       lxclock.c lxclock.h \
		       mainloop.c mainloop.h \
		       monitor.c monitor.h \
		       mount_utils.c mount_utils.h \
		       namespace.c namespace.h \
		       network.c network.h \
		       nl.c nl.h \
		       parse.c parse.h \
		       process_utils.c process_utils.h \
		       ringbuf.c ringbuf.h \
		       start.c start.h \
		       state.c state.h \
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
		       syscall_numbers.h \
		       syscall_wrappers.h \
		       terminal.c terminal.h \
		       utils.c utils.h \
		       uuid.c uuid.h \
		       $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_unshare_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_unshare_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_unshare_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_unshare_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_unshare_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_unshare_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_unshare_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_unshare_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_wait_SOURCES = tools/lxc_wait.c \
		   tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_wait_SOURCES += $(liblxc_la_SOURCES)
lxc_wait_LDFLAGS = -all-static -pthread
else
lxc_wait_SOURCES += af_unix.c af_unix.h \
		    caps.c caps.h \
		    cgroups/cgfsng.c \
		    cgroups/cgroup.c cgroups/cgroup.h \
		    cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		    cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		    commands.c commands.h \
		    commands_utils.c commands_utils.h \
		    conf.c conf.h \
		    confile.c confile.h \
		    confile_utils.c confile_utils.h \
		    error.c error.h \
		    file_utils.c file_utils.h \
		    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		    initutils.c initutils.h \
		    log.c log.h \
		    lxclock.c lxclock.h \
		    mainloop.c mainloop.h \
		    monitor.c monitor.h \
		    mount_utils.c mount_utils.h \
		    namespace.c namespace.h \
		    network.c network.h \
		    nl.c nl.h \
		    parse.c parse.h \
		    process_utils.c process_utils.h \
		    ringbuf.c ringbuf.h \
		    start.c start.h \
		    state.c state.h \
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
		    terminal.c terminal.h \
		    utils.c utils.h \
		    uuid.c uuid.h \
		    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_wait_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_wait_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_wait_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_wait_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_wait_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_wait_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_wait_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_wait_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_create_SOURCES = tools/lxc_create.c \
		     tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_create_SOURCES += $(liblxc_la_SOURCES)
lxc_create_LDFLAGS = -all-static -pthread
else
lxc_create_SOURCES += af_unix.c af_unix.h \
		      caps.c caps.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      commands.c commands.h \
		      commands_utils.c commands_utils.h \
		      conf.c conf.h \
		      confile.c confile.h \
		      confile_utils.c confile_utils.h \
		      error.c error.h \
		      file_utils.c file_utils.h \
		      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
		      initutils.c initutils.h \
		      log.c log.h \
		      lxclock.c lxclock.h \
		      mainloop.c mainloop.h \
		      monitor.c monitor.h \
		      mount_utils.c mount_utils.h \
		      namespace.c namespace.h \
		      network.c network.h \
		      nl.c nl.h \
		      parse.c parse.h \
		      process_utils.c process_utils.h \
		      ringbuf.c ringbuf.h \
		      start.c start.h \
		      state.c state.h \
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
		      terminal.c terminal.h \
		      utils.c utils.h \
		      uuid.c uuid.h \
		      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_create_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_create_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_create_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_create_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_create_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_create_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_create_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_create_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_snapshot_SOURCES = tools/lxc_snapshot.c \
		       tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_snapshot_SOURCES += $(liblxc_la_SOURCES)
lxc_snapshot_LDFLAGS = -all-static -pthread
else
lxc_snapshot_SOURCES += af_unix.c af_unix.h \
			caps.c caps.h \
			cgroups/cgfsng.c \
			cgroups/cgroup.c cgroups/cgroup.h \
			cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			commands.c commands.h \
			commands_utils.c commands_utils.h \
			conf.c conf.h \
			confile.c confile.h \
			confile_utils.c confile_utils.h \
			error.c error.h \
			file_utils.c file_utils.h \
			../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			initutils.c initutils.h \
			log.c log.h \
			lxclock.c lxclock.h \
			mainloop.c mainloop.h \
			monitor.c monitor.h \
			mount_utils.c mount_utils.h \
			namespace.c namespace.h \
			network.c network.h \
			nl.c nl.h \
			parse.c parse.h \
			process_utils.c process_utils.h \
			ringbuf.c ringbuf.h \
			start.c start.h \
			state.c state.h \
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
			terminal.c terminal.h \
			utils.c utils.h \
			uuid.c uuid.h \
			$(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_snapshot_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_snapshot_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_snapshot_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_snapshot_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_snapshot_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_snapshot_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_snapshot_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_snapshot_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_checkpoint_SOURCES = tools/lxc_checkpoint.c \
			 tools/arguments.c tools/arguments.h

if ENABLE_STATIC_BINARIES
lxc_checkpoint_SOURCES += $(liblxc_la_SOURCES)
lxc_checkpoint_LDFLAGS = -all-static -pthread
else
lxc_checkpoint_SOURCES += af_unix.c af_unix.h \
			  caps.c caps.h \
			  cgroups/cgfsng.c \
			  cgroups/cgroup.c cgroups/cgroup.h \
			  cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			  cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			  commands.c commands.h \
			  commands_utils.c commands_utils.h \
			  conf.c conf.h \
			  confile.c confile.h \
			  confile_utils.c confile_utils.h \
			  error.c error.h \
			  file_utils.c file_utils.h \
			  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			  initutils.c initutils.h \
			  log.c log.h \
			  lxclock.c lxclock.h \
			  mainloop.c mainloop.h \
			  monitor.c monitor.h \
			  mount_utils.c mount_utils.h \
			  namespace.c namespace.h \
			  network.c network.h \
			  nl.c nl.h \
			  parse.c parse.h \
			  process_utils.c process_utils.h \
			  ringbuf.c ringbuf.h \
			  start.c start.h \
			  state.c state.h \
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
			  terminal.c terminal.h \
			  utils.c utils.h \
			  uuid.c uuid.h \
			  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_checkpoint_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_checkpoint_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_checkpoint_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_checkpoint_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_checkpoint_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_checkpoint_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_checkpoint_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_checkpoint_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif
endif

if ENABLE_COMMANDS
# Binaries shipping with liblxc
init_lxc_SOURCES = cmd/lxc_init.c \
		   af_unix.c af_unix.h \
		   caps.c caps.h \
		   error.c error.h \
		   file_utils.c file_utils.h \
		   initutils.c initutils.h \
		   log.c log.h \
		   macro.h \
		   memory_utils.h \
		   namespace.c namespace.h \
		   string_utils.c string_utils.h

if !HAVE_STRLCPY
init_lxc_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
init_lxc_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

init_lxc_LDFLAGS = -pthread

lxc_monitord_SOURCES = cmd/lxc_monitord.c

if ENABLE_STATIC_BINARIES
lxc_monitord_SOURCES += $(liblxc_la_SOURCES)
lxc_monitord_LDFLAGS = -all-static -pthread
else
lxc_monitord_SOURCES += af_unix.c af_unix.h \
			caps.c caps.h \
			cgroups/cgfsng.c \
			cgroups/cgroup.c cgroups/cgroup.h \
			cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			commands.c commands.h \
			commands_utils.c commands_utils.h \
			conf.c conf.h \
			confile.c confile.h \
			confile_utils.c confile_utils.h \
			error.c error.h \
			file_utils.c file_utils.h \
			../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			initutils.c initutils.h \
			log.c log.h \
			lxclock.c lxclock.h \
			mainloop.c mainloop.h \
			monitor.c monitor.h \
			mount_utils.c mount_utils.h \
			namespace.c namespace.h \
			network.c network.h \
			nl.c nl.h \
			parse.c parse.h \
			process_utils.c process_utils.h \
			ringbuf.c ringbuf.h \
			start.c start.h \
			state.c state.h \
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
			syscall_numbers.h \
			terminal.c terminal.h \
			utils.c utils.h \
			uuid.c uuid.h \
			$(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_monitord_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_monitord_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_monitord_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_monitord_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_monitord_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_monitord_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_monitord_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_monitord_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_user_nic_SOURCES = cmd/lxc_user_nic.c

if ENABLE_STATIC_BINARIES
lxc_user_nic_SOURCES += $(liblxc_la_SOURCES)
lxc_user_nic_LDFLAGS = -all-static -pthread
else
lxc_user_nic_SOURCES += af_unix.c af_unix.h \
			caps.c caps.h \
			cgroups/cgfsng.c \
			cgroups/cgroup.c cgroups/cgroup.h \
			cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			commands.c commands.h \
			commands_utils.c commands_utils.h \
			conf.c conf.h \
			confile.c confile.h \
			confile_utils.c confile_utils.h \
			error.c error.h \
			file_utils.c file_utils.h \
			../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			initutils.c initutils.h \
			log.c log.h \
			lxclock.c lxclock.h \
			mainloop.c mainloop.h \
			memory_utils.h \
			monitor.c monitor.h \
			mount_utils.c mount_utils.h \
			namespace.c namespace.h \
			network.c network.h \
			nl.c nl.h \
			parse.c parse.h \
			process_utils.c process_utils.h \
			ringbuf.c ringbuf.h \
			start.c start.h \
			state.c state.h \
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
			syscall_numbers.h \
			syscall_wrappers.h \
			terminal.c terminal.h \
			utils.c utils.h \
			uuid.c uuid.h \
			$(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_user_nic_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_user_nic_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_user_nic_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_user_nic_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_user_nic_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_user_nic_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_user_nic_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_user_nic_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif

lxc_usernsexec_SOURCES = cmd/lxc_usernsexec.c

if ENABLE_STATIC_BINARIES
lxc_usernsexec_SOURCES += $(liblxc_la_SOURCES)
lxc_usernsexec_LDFLAGS = -all-static -pthread
else
lxc_usernsexec_SOURCES += af_unix.c af_unix.h \
			  caps.c caps.h \
			  cgroups/cgfsng.c \
			  cgroups/cgroup.c cgroups/cgroup.h \
			  cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			  cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			  commands.c commands.h \
			  commands_utils.c commands_utils.h \
			  conf.c conf.h \
			  confile.c confile.h \
			  confile_utils.c confile_utils.h \
			  error.c error.h \
			  file_utils.c file_utils.h \
			  hlist.h \
			  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			  initutils.c initutils.h \
			  list.h \
			  log.c log.h \
			  lxclock.c lxclock.h \
			  macro.h \
			  mainloop.c mainloop.h \
			  memory_utils.h \
			  monitor.c monitor.h \
			  mount_utils.c mount_utils.h \
			  namespace.c namespace.h \
			  network.c network.h \
			  nl.c nl.h \
			  parse.c parse.h \
			  process_utils.c process_utils.h \
			  ringbuf.c ringbuf.h \
			  start.c start.h \
			  state.c state.h \
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
			  terminal.c terminal.h \
			  utils.c utils.h \
			  uuid.c uuid.h \
			  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_usernsexec_SOURCES += seccomp.c lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_usernsexec_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

if !HAVE_STRLCPY
lxc_usernsexec_SOURCES += ../include/strlcpy.c ../include/strlcpy.h
endif

if !HAVE_STRLCAT
lxc_usernsexec_SOURCES += ../include/strlcat.c ../include/strlcat.h
endif

if !HAVE_OPENPTY
lxc_usernsexec_SOURCES += ../include/openpty.c ../include/openpty.h
endif

if IS_BIONIC
lxc_usernsexec_SOURCES += ../include/fexecve.c ../include/fexecve.h \
		../include/lxcmntent.c ../include/lxcmntent.h
endif

if !HAVE_GETGRGID_R
lxc_usernsexec_SOURCES += ../include/getgrgid_r.c ../include/getgrgid_r.h
endif

if !HAVE_PRLIMIT
if HAVE_PRLIMIT64
lxc_usernsexec_SOURCES += ../include/prlimit.c ../include/prlimit.h
endif
endif
endif
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
			  af_unix.c af_unix.h \
			  caps.c caps.h \
			  error.c error.h \
			  file_utils.c file_utils.h \
			  initutils.c initutils.h \
			  log.c log.h \
			  macro.h \
			  memory_utils.h \
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

init_lxc_static_LDFLAGS = -all-static -pthread
init_lxc_static_LDADD = @CAP_LIBS@
init_lxc_static_CFLAGS = $(AM_CFLAGS) -DNO_LXC_CONF
if ENABLE_SANITIZERS
init_lxc_static_CFLAGS += -fno-sanitize=address,undefined
endif
if ENABLE_FUZZERS
init_lxc_static_CFLAGS += -fno-sanitize=fuzzer-no-link
endif
endif
endif

if ENABLE_PAM
if HAVE_PAM
exec_pam_LTLIBRARIES = pam_cgfs.la

pam_cgfs_la_SOURCES = pam/pam_cgfs.c \
		      file_utils.c file_utils.h \
		      macro.h \
		      memory_utils.h \
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
		     $(DLOG_LIBS) \
		     -L$(top_srcdir)

pam_cgfs_la_LDFLAGS = $(AM_LDFLAGS) \
		      -avoid-version \
		      -module \
		      -shared
endif
endif

install-exec-hook:
	mkdir -p $(DESTDIR)$(datadir)/lxc
	install -c -m 644 lxc.functions $(DESTDIR)$(datadir)/lxc
	mv $(shell readlink -f $(DESTDIR)$(libdir)/liblxc.so) $(DESTDIR)$(libdir)/liblxc.so.@LXC_ABI@
	rm -f $(DESTDIR)$(libdir)/liblxc.so $(DESTDIR)$(libdir)/liblxc.so.1
	cd $(DESTDIR)$(libdir); \
	ln -sf liblxc.so.@LXC_ABI@ liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)); \
	ln -sf liblxc.so.$(firstword $(subst ., ,@LXC_ABI@)) liblxc.so
if ENABLE_PAM
if HAVE_PAM
	$(RM) "$(DESTDIR)$(exec_pamdir)/pam_cgfs.la"
	$(RM) "$(DESTDIR)$(exec_pamdir)/pam_cgfs.a"
endif
endif
if ENABLE_COMMANDS
	chmod u+s $(DESTDIR)$(libexecdir)/lxc/lxc-user-nic

if ENABLE_BASH
install-data-local:
	cd $(DESTDIR)$(bashcompdir); \
	for bin in $(bin_PROGRAMS) ; do \
		ln -sf lxc $$bin ; \
	done
endif
endif

uninstall-local:
	$(RM) $(DESTDIR)$(libdir)/liblxc.so*
	$(RM) $(DESTDIR)$(libdir)/liblxc.a
if ENABLE_BASH
	for bin in $(bin_PROGRAMS) ; do \
		$(RM) $(DESTDIR)$(bashcompdir)/$$bin ; \
	done
endif

if ENABLE_PAM
if HAVE_PAM
	$(RM) $(DESTDIR)$(exec_pamdir)/pam_cgfs.so*
endif
endif
