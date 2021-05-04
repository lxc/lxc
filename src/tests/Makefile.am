if ENABLE_TESTS

LDADD = ../lxc/liblxc.la \
	@CAP_LIBS@ \
	@OPENSSL_LIBS@ \
	@SECCOMP_LIBS@ \
	@SELINUX_LIBS@ \
	@DLOG_LIBS@

LSM_SOURCES = ../lxc/lsm/lsm.c \
	      ../lxc/lsm/lsm.h \
	      ../lxc/lsm/nop.c

if ENABLE_APPARMOR
LSM_SOURCES += ../lxc/lsm/apparmor.c
endif

if ENABLE_SELINUX
LSM_SOURCES += ../lxc/lsm/selinux.c
endif

lxc_test_arch_parse_SOURCES = arch_parse.c \
			      lxctest.h \
			      ../lxc/lxc.h \
			      ../lxc/memory_utils.h

lxc_test_api_reboot_SOURCES = api_reboot.c \
			      ../lxc/af_unix.c ../lxc/af_unix.h \
			      ../lxc/caps.c ../lxc/caps.h \
			      ../lxc/cgroups/cgfsng.c \
			      ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			      ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			      ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			      ../lxc/commands.c ../lxc/commands.h \
			      ../lxc/commands_utils.c ../lxc/commands_utils.h \
			      ../lxc/conf.c ../lxc/conf.h \
			      ../lxc/confile.c ../lxc/confile.h \
			      ../lxc/confile_utils.c ../lxc/confile_utils.h \
			      ../lxc/error.c ../lxc/error.h \
			      ../lxc/file_utils.c ../lxc/file_utils.h \
			      ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			      ../lxc/initutils.c ../lxc/initutils.h \
			      ../lxc/log.c ../lxc/log.h \
			      ../lxc/lxclock.c ../lxc/lxclock.h \
			      ../lxc/mainloop.c ../lxc/mainloop.h \
			      ../lxc/monitor.c ../lxc/monitor.h \
			      ../lxc/mount_utils.c ../lxc/mount_utils.h \
			      ../lxc/namespace.c ../lxc/namespace.h \
			      ../lxc/network.c ../lxc/network.h \
			      ../lxc/nl.c ../lxc/nl.h \
			      ../lxc/parse.c ../lxc/parse.h \
			      ../lxc/process_utils.c ../lxc/process_utils.h \
			      ../lxc/ringbuf.c ../lxc/ringbuf.h \
			      ../lxc/start.c ../lxc/start.h \
			      ../lxc/state.c ../lxc/state.h \
			      ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			      ../lxc/storage/dir.c ../lxc/storage/dir.h \
			      ../lxc/storage/loop.c ../lxc/storage/loop.h \
			      ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			      ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			      ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			      ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			      ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			      ../lxc/storage/storage.c ../lxc/storage/storage.h \
			      ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			      ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			      ../lxc/sync.c ../lxc/sync.h \
			      ../lxc/string_utils.c ../lxc/string_utils.h \
			      ../lxc/terminal.c ../lxc/terminal.h \
			      ../lxc/utils.c ../lxc/utils.h \
			      ../lxc/uuid.c ../lxc/uuid.h \
			      $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_api_reboot_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_api_reboot_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_apparmor_SOURCES = aa.c \
			    ../lxc/af_unix.c ../lxc/af_unix.h \
			    ../lxc/caps.c ../lxc/caps.h \
			    ../lxc/cgroups/cgfsng.c \
			    ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			    ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			    ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			    ../lxc/commands.c ../lxc/commands.h \
			    ../lxc/commands_utils.c ../lxc/commands_utils.h \
			    ../lxc/conf.c ../lxc/conf.h \
			    ../lxc/confile.c ../lxc/confile.h \
			    ../lxc/confile_utils.c ../lxc/confile_utils.h \
			    ../lxc/error.c ../lxc/error.h \
			    ../lxc/file_utils.c ../lxc/file_utils.h \
			    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			    ../lxc/initutils.c ../lxc/initutils.h \
			    ../lxc/log.c ../lxc/log.h \
			    ../lxc/lxclock.c ../lxc/lxclock.h \
			    ../lxc/mainloop.c ../lxc/mainloop.h \
			    ../lxc/monitor.c ../lxc/monitor.h \
			    ../lxc/mount_utils.c ../lxc/mount_utils.h \
			    ../lxc/namespace.c ../lxc/namespace.h \
			    ../lxc/network.c ../lxc/network.h \
			    ../lxc/nl.c ../lxc/nl.h \
			    ../lxc/parse.c ../lxc/parse.h \
			    ../lxc/process_utils.c ../lxc/process_utils.h \
			    ../lxc/ringbuf.c ../lxc/ringbuf.h \
			    ../lxc/start.c ../lxc/start.h \
			    ../lxc/state.c ../lxc/state.h \
			    ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			    ../lxc/storage/dir.c ../lxc/storage/dir.h \
			    ../lxc/storage/loop.c ../lxc/storage/loop.h \
			    ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			    ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			    ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			    ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			    ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			    ../lxc/storage/storage.c ../lxc/storage/storage.h \
			    ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			    ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			    ../lxc/sync.c ../lxc/sync.h \
			    ../lxc/string_utils.c ../lxc/string_utils.h \
			    ../lxc/terminal.c ../lxc/terminal.h \
			    ../lxc/utils.c ../lxc/utils.h \
			    ../lxc/uuid.c ../lxc/uuid.h \
			    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_apparmor_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_apparmor_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_attach_SOURCES = attach.c \
			  ../lxc/af_unix.c ../lxc/af_unix.h \
			  ../lxc/caps.c ../lxc/caps.h \
			  ../lxc/cgroups/cgfsng.c \
			  ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			  ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			  ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			  ../lxc/commands.c ../lxc/commands.h \
			  ../lxc/commands_utils.c ../lxc/commands_utils.h \
			  ../lxc/conf.c ../lxc/conf.h \
			  ../lxc/confile.c ../lxc/confile.h \
			  ../lxc/confile_utils.c ../lxc/confile_utils.h \
			  ../lxc/error.c ../lxc/error.h \
			  ../lxc/file_utils.c ../lxc/file_utils.h \
			  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			  ../lxc/initutils.c ../lxc/initutils.h \
			  ../lxc/log.c ../lxc/log.h \
			  ../lxc/lxclock.c ../lxc/lxclock.h \
			  ../lxc/mainloop.c ../lxc/mainloop.h \
			  ../lxc/monitor.c ../lxc/monitor.h \
			  ../lxc/mount_utils.c ../lxc/mount_utils.h \
			  ../lxc/namespace.c ../lxc/namespace.h \
			  ../lxc/network.c ../lxc/network.h \
			  ../lxc/nl.c ../lxc/nl.h \
			  ../lxc/parse.c ../lxc/parse.h \
			  ../lxc/process_utils.c ../lxc/process_utils.h \
			  ../lxc/ringbuf.c ../lxc/ringbuf.h \
			  ../lxc/start.c ../lxc/start.h \
			  ../lxc/state.c ../lxc/state.h \
			  ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			  ../lxc/storage/dir.c ../lxc/storage/dir.h \
			  ../lxc/storage/loop.c ../lxc/storage/loop.h \
			  ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			  ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			  ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			  ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			  ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			  ../lxc/storage/storage.c ../lxc/storage/storage.h \
			  ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			  ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			  ../lxc/sync.c ../lxc/sync.h \
			  ../lxc/string_utils.c ../lxc/string_utils.h \
			  ../lxc/terminal.c ../lxc/terminal.h \
			  ../lxc/utils.c ../lxc/utils.h \
			  ../lxc/uuid.c ../lxc/uuid.h \
			  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_attach_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_attach_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_basic_SOURCES = basic.c
lxc_test_cgpath_SOURCES = cgpath.c \
			  ../lxc/af_unix.c ../lxc/af_unix.h \
			  ../lxc/caps.c ../lxc/caps.h \
			  ../lxc/cgroups/cgfsng.c \
			  ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			  ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			  ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			  ../lxc/commands.c ../lxc/commands.h \
			  ../lxc/commands_utils.c ../lxc/commands_utils.h \
			  ../lxc/conf.c ../lxc/conf.h \
			  ../lxc/confile.c ../lxc/confile.h \
			  ../lxc/confile_utils.c ../lxc/confile_utils.h \
			  ../lxc/error.c ../lxc/error.h \
			  ../lxc/file_utils.c ../lxc/file_utils.h \
			  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			  ../lxc/initutils.c ../lxc/initutils.h \
			  ../lxc/log.c ../lxc/log.h \
			  ../lxc/lxclock.c ../lxc/lxclock.h \
			  ../lxc/mainloop.c ../lxc/mainloop.h \
			  ../lxc/monitor.c ../lxc/monitor.h \
			  ../lxc/mount_utils.c ../lxc/mount_utils.h \
			  ../lxc/namespace.c ../lxc/namespace.h \
			  ../lxc/network.c ../lxc/network.h \
			  ../lxc/nl.c ../lxc/nl.h \
			  ../lxc/parse.c ../lxc/parse.h \
			  ../lxc/process_utils.c ../lxc/process_utils.h \
			  ../lxc/ringbuf.c ../lxc/ringbuf.h \
			  ../lxc/start.c ../lxc/start.h \
			  ../lxc/state.c ../lxc/state.h \
			  ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			  ../lxc/storage/dir.c ../lxc/storage/dir.h \
			  ../lxc/storage/loop.c ../lxc/storage/loop.h \
			  ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			  ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			  ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			  ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			  ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			  ../lxc/storage/storage.c ../lxc/storage/storage.h \
			  ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			  ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			  ../lxc/sync.c ../lxc/sync.h \
			  ../lxc/string_utils.c ../lxc/string_utils.h \
			  ../lxc/terminal.c ../lxc/terminal.h \
			  ../lxc/utils.c ../lxc/utils.h \
			  ../lxc/uuid.c ../lxc/uuid.h \
			  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_cgpath_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_cgpath_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_clonetest_SOURCES = clonetest.c
lxc_test_concurrent_SOURCES = concurrent.c
lxc_test_config_jump_table_SOURCES = config_jump_table.c \
				     lxctest.h \
				     ../lxc/af_unix.c ../lxc/af_unix.h \
				     ../lxc/caps.c ../lxc/caps.h \
				     ../lxc/cgroups/cgfsng.c \
				     ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
				     ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
				     ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
				     ../lxc/commands.c ../lxc/commands.h \
				     ../lxc/commands_utils.c ../lxc/commands_utils.h \
				     ../lxc/conf.c ../lxc/conf.h \
				     ../lxc/confile.c ../lxc/confile.h \
				     ../lxc/confile_utils.c ../lxc/confile_utils.h \
				     ../lxc/error.c ../lxc/error.h \
				     ../lxc/file_utils.c ../lxc/file_utils.h \
				     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
				     ../lxc/initutils.c ../lxc/initutils.h \
				     ../lxc/log.c ../lxc/log.h \
				     ../lxc/lxclock.c ../lxc/lxclock.h \
				     ../lxc/mainloop.c ../lxc/mainloop.h \
				     ../lxc/monitor.c ../lxc/monitor.h \
				     ../lxc/mount_utils.c ../lxc/mount_utils.h \
				     ../lxc/namespace.c ../lxc/namespace.h \
				     ../lxc/network.c ../lxc/network.h \
				     ../lxc/nl.c ../lxc/nl.h \
				     ../lxc/parse.c ../lxc/parse.h \
				     ../lxc/process_utils.c ../lxc/process_utils.h \
				     ../lxc/ringbuf.c ../lxc/ringbuf.h \
				     ../lxc/start.c ../lxc/start.h \
				     ../lxc/state.c ../lxc/state.h \
				     ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
				     ../lxc/storage/dir.c ../lxc/storage/dir.h \
				     ../lxc/storage/loop.c ../lxc/storage/loop.h \
				     ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
				     ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
				     ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
				     ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
				     ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
				     ../lxc/storage/storage.c ../lxc/storage/storage.h \
				     ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
				     ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
				     ../lxc/sync.c ../lxc/sync.h \
				     ../lxc/string_utils.c ../lxc/string_utils.h \
				     ../lxc/terminal.c ../lxc/terminal.h \
				     ../lxc/utils.c ../lxc/utils.h \
				     ../lxc/uuid.c ../lxc/uuid.h \
				     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_config_jump_table_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_config_jump_table_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_console_SOURCES = console.c
lxc_test_console_log_SOURCES = console_log.c lxctest.h
lxc_test_containertests_SOURCES = containertests.c
lxc_test_createtest_SOURCES = createtest.c
lxc_test_criu_check_feature_SOURCES = criu_check_feature.c lxctest.h
lxc_test_cve_2019_5736_SOURCES =  cve-2019-5736.c lxctest.h
lxc_test_destroytest_SOURCES = destroytest.c
lxc_test_device_add_remove_SOURCES = device_add_remove.c \
				     ../lxc/af_unix.c ../lxc/af_unix.h \
				     ../lxc/caps.c ../lxc/caps.h \
				     ../lxc/cgroups/cgfsng.c \
				     ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
				     ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
				     ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
				     ../lxc/commands.c ../lxc/commands.h \
				     ../lxc/commands_utils.c ../lxc/commands_utils.h \
				     ../lxc/conf.c ../lxc/conf.h \
				     ../lxc/confile.c ../lxc/confile.h \
				     ../lxc/confile_utils.c ../lxc/confile_utils.h \
				     ../lxc/error.c ../lxc/error.h \
				     ../lxc/file_utils.c ../lxc/file_utils.h \
				     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
				     ../lxc/initutils.c ../lxc/initutils.h \
				     ../lxc/log.c ../lxc/log.h \
				     ../lxc/lxclock.c ../lxc/lxclock.h \
				     ../lxc/mainloop.c ../lxc/mainloop.h \
				     ../lxc/monitor.c ../lxc/monitor.h \
				     ../lxc/mount_utils.c ../lxc/mount_utils.h \
				     ../lxc/namespace.c ../lxc/namespace.h \
				     ../lxc/network.c ../lxc/network.h \
				     ../lxc/nl.c ../lxc/nl.h \
				     ../lxc/parse.c ../lxc/parse.h \
				     ../lxc/process_utils.c ../lxc/process_utils.h \
				     ../lxc/ringbuf.c ../lxc/ringbuf.h \
				     ../lxc/start.c ../lxc/start.h \
				     ../lxc/state.c ../lxc/state.h \
				     ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
				     ../lxc/storage/dir.c ../lxc/storage/dir.h \
				     ../lxc/storage/loop.c ../lxc/storage/loop.h \
				     ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
				     ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
				     ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
				     ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
				     ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
				     ../lxc/storage/storage.c ../lxc/storage/storage.h \
				     ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
				     ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
				     ../lxc/sync.c ../lxc/sync.h \
				     ../lxc/string_utils.c ../lxc/string_utils.h \
				     ../lxc/terminal.c ../lxc/terminal.h \
				     ../lxc/utils.c ../lxc/utils.h \
				     ../lxc/uuid.c ../lxc/uuid.h \
				     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_device_add_remove_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_device_add_remove_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_getkeys_SOURCES = getkeys.c
lxc_test_get_item_SOURCES = get_item.c \
			    ../lxc/af_unix.c ../lxc/af_unix.h \
			    ../lxc/caps.c ../lxc/caps.h \
			    ../lxc/cgroups/cgfsng.c \
			    ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			    ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			    ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			    ../lxc/commands.c ../lxc/commands.h \
			    ../lxc/commands_utils.c ../lxc/commands_utils.h \
			    ../lxc/conf.c ../lxc/conf.h \
			    ../lxc/confile.c ../lxc/confile.h \
			    ../lxc/confile_utils.c ../lxc/confile_utils.h \
			    ../lxc/error.c ../lxc/error.h \
			    ../lxc/file_utils.c ../lxc/file_utils.h \
			    ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			    ../lxc/initutils.c ../lxc/initutils.h \
			    ../lxc/log.c ../lxc/log.h \
			    ../lxc/lxclock.c ../lxc/lxclock.h \
			    ../lxc/mainloop.c ../lxc/mainloop.h \
			    ../lxc/monitor.c ../lxc/monitor.h \
			    ../lxc/mount_utils.c ../lxc/mount_utils.h \
			    ../lxc/namespace.c ../lxc/namespace.h \
			    ../lxc/network.c ../lxc/network.h \
			    ../lxc/nl.c ../lxc/nl.h \
			    ../lxc/parse.c ../lxc/parse.h \
			    ../lxc/process_utils.c ../lxc/process_utils.h \
			    ../lxc/ringbuf.c ../lxc/ringbuf.h \
			    ../lxc/start.c ../lxc/start.h \
			    ../lxc/state.c ../lxc/state.h \
			    ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			    ../lxc/storage/dir.c ../lxc/storage/dir.h \
			    ../lxc/storage/loop.c ../lxc/storage/loop.h \
			    ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			    ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			    ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			    ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			    ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			    ../lxc/storage/storage.c ../lxc/storage/storage.h \
			    ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			    ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			    ../lxc/sync.c ../lxc/sync.h \
			    ../lxc/string_utils.c ../lxc/string_utils.h \
			    ../lxc/terminal.c ../lxc/terminal.h \
			    ../lxc/utils.c ../lxc/utils.h \
			    ../lxc/uuid.c ../lxc/uuid.h \
			    $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_get_item_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_get_item_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_list_SOURCES = list.c
lxc_test_locktests_SOURCES = locktests.c \
			     ../lxc/af_unix.c ../lxc/af_unix.h \
			     ../lxc/caps.c ../lxc/caps.h \
			     ../lxc/cgroups/cgfsng.c \
			     ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			     ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			     ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			     ../lxc/commands.c ../lxc/commands.h \
			     ../lxc/commands_utils.c ../lxc/commands_utils.h \
			     ../lxc/conf.c ../lxc/conf.h \
			     ../lxc/confile.c ../lxc/confile.h \
			     ../lxc/confile_utils.c ../lxc/confile_utils.h \
			     ../lxc/error.c ../lxc/error.h \
			     ../lxc/file_utils.c ../lxc/file_utils.h \
			     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			     ../lxc/initutils.c ../lxc/initutils.h \
			     ../lxc/log.c ../lxc/log.h \
			     ../lxc/lxclock.c ../lxc/lxclock.h \
			     ../lxc/mainloop.c ../lxc/mainloop.h \
			     ../lxc/monitor.c ../lxc/monitor.h \
			     ../lxc/mount_utils.c ../lxc/mount_utils.h \
			     ../lxc/namespace.c ../lxc/namespace.h \
			     ../lxc/network.c ../lxc/network.h \
			     ../lxc/nl.c ../lxc/nl.h \
			     ../lxc/parse.c ../lxc/parse.h \
			     ../lxc/process_utils.c ../lxc/process_utils.h \
			     ../lxc/ringbuf.c ../lxc/ringbuf.h \
			     ../lxc/start.c ../lxc/start.h \
			     ../lxc/state.c ../lxc/state.h \
			     ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			     ../lxc/storage/dir.c ../lxc/storage/dir.h \
			     ../lxc/storage/loop.c ../lxc/storage/loop.h \
			     ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			     ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			     ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			     ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			     ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			     ../lxc/storage/storage.c ../lxc/storage/storage.h \
			     ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			     ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			     ../lxc/sync.c ../lxc/sync.h \
			     ../lxc/string_utils.c ../lxc/string_utils.h \
			     ../lxc/terminal.c ../lxc/terminal.h \
			     ../lxc/utils.c ../lxc/utils.h \
			     ../lxc/uuid.c ../lxc/uuid.h \
			     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_locktests_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_locktests_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_lxcpath_SOURCES = lxcpath.c
lxc_test_may_control_SOURCES = may_control.c
lxc_test_mount_injection_SOURCES = mount_injection.c \
				   lxctest.h \
				   ../lxc/af_unix.c ../lxc/af_unix.h \
				   ../lxc/caps.c ../lxc/caps.h \
				   ../lxc/cgroups/cgfsng.c \
				   ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
				   ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
				   ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
				   ../lxc/commands.c ../lxc/commands.h \
				   ../lxc/commands_utils.c ../lxc/commands_utils.h \
				   ../lxc/conf.c ../lxc/conf.h \
				   ../lxc/confile.c ../lxc/confile.h \
				   ../lxc/confile_utils.c ../lxc/confile_utils.h \
				   ../lxc/error.c ../lxc/error.h \
				   ../lxc/file_utils.c ../lxc/file_utils.h \
				   ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
				   ../lxc/initutils.c ../lxc/initutils.h \
				   ../lxc/log.c ../lxc/log.h \
				   ../lxc/lxclock.c ../lxc/lxclock.h \
				   ../lxc/mainloop.c ../lxc/mainloop.h \
				   ../lxc/monitor.c ../lxc/monitor.h \
				   ../lxc/mount_utils.c ../lxc/mount_utils.h \
				   ../lxc/namespace.c ../lxc/namespace.h \
				   ../lxc/network.c ../lxc/network.h \
				   ../lxc/nl.c ../lxc/nl.h \
				   ../lxc/parse.c ../lxc/parse.h \
				   ../lxc/process_utils.c ../lxc/process_utils.h \
				   ../lxc/ringbuf.c ../lxc/ringbuf.h \
				   ../lxc/start.c ../lxc/start.h \
				   ../lxc/state.c ../lxc/state.h \
				   ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
				   ../lxc/storage/dir.c ../lxc/storage/dir.h \
				   ../lxc/storage/loop.c ../lxc/storage/loop.h \
				   ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
				   ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
				   ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
				   ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
				   ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
				   ../lxc/storage/storage.c ../lxc/storage/storage.h \
				   ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
				   ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
				   ../lxc/sync.c ../lxc/sync.h \
				   ../lxc/string_utils.c ../lxc/string_utils.h \
				   ../lxc/terminal.c ../lxc/terminal.h \
				   ../lxc/utils.c ../lxc/utils.h \
				   ../lxc/uuid.c ../lxc/uuid.h \
				   $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_mount_injection_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_mount_injection_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_parse_config_file_SOURCES = parse_config_file.c \
				     lxctest.h \
				     ../lxc/af_unix.c ../lxc/af_unix.h \
				     ../lxc/caps.c ../lxc/caps.h \
				     ../lxc/cgroups/cgfsng.c \
				     ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
				     ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
				     ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
				     ../lxc/commands.c ../lxc/commands.h \
				     ../lxc/commands_utils.c ../lxc/commands_utils.h \
				     ../lxc/conf.c ../lxc/conf.h \
				     ../lxc/confile.c ../lxc/confile.h \
				     ../lxc/confile_utils.c ../lxc/confile_utils.h \
				     ../lxc/error.c ../lxc/error.h \
				     ../lxc/file_utils.c ../lxc/file_utils.h \
				     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
				     ../lxc/initutils.c ../lxc/initutils.h \
				     ../lxc/log.c ../lxc/log.h \
				     ../lxc/lxclock.c ../lxc/lxclock.h \
				     ../lxc/mainloop.c ../lxc/mainloop.h \
				     ../lxc/monitor.c ../lxc/monitor.h \
				     ../lxc/mount_utils.c ../lxc/mount_utils.h \
				     ../lxc/namespace.c ../lxc/namespace.h \
				     ../lxc/network.c ../lxc/network.h \
				     ../lxc/nl.c ../lxc/nl.h \
				     ../lxc/parse.c ../lxc/parse.h \
				     ../lxc/process_utils.c ../lxc/process_utils.h \
				     ../lxc/ringbuf.c ../lxc/ringbuf.h \
				     ../lxc/start.c ../lxc/start.h \
				     ../lxc/state.c ../lxc/state.h \
				     ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
				     ../lxc/storage/dir.c ../lxc/storage/dir.h \
				     ../lxc/storage/loop.c ../lxc/storage/loop.h \
				     ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
				     ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
				     ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
				     ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
				     ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
				     ../lxc/storage/storage.c ../lxc/storage/storage.h \
				     ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
				     ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
				     ../lxc/sync.c ../lxc/sync.h \
				     ../lxc/string_utils.c ../lxc/string_utils.h \
				     ../lxc/terminal.c ../lxc/terminal.h \
				     ../lxc/utils.c ../lxc/utils.h \
				     ../lxc/uuid.c ../lxc/uuid.h \
				     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_parse_config_file_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_parse_config_file_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_raw_clone_SOURCES = lxc_raw_clone.c \
			     lxctest.h \
			     ../lxc/af_unix.c ../lxc/af_unix.h \
			     ../lxc/caps.c ../lxc/caps.h \
			     ../lxc/cgroups/cgfsng.c \
			     ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			     ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			     ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			     ../lxc/commands.c ../lxc/commands.h \
			     ../lxc/commands_utils.c ../lxc/commands_utils.h \
			     ../lxc/conf.c ../lxc/conf.h \
			     ../lxc/confile.c ../lxc/confile.h \
			     ../lxc/confile_utils.c ../lxc/confile_utils.h \
			     ../lxc/error.c ../lxc/error.h \
			     ../lxc/file_utils.c ../lxc/file_utils.h \
			     ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			     ../lxc/initutils.c ../lxc/initutils.h \
			     ../lxc/log.c ../lxc/log.h \
			     ../lxc/lxclock.c ../lxc/lxclock.h \
			     ../lxc/mainloop.c ../lxc/mainloop.h \
			     ../lxc/monitor.c ../lxc/monitor.h \
			     ../lxc/mount_utils.c ../lxc/mount_utils.h \
			     ../lxc/namespace.c ../lxc/namespace.h \
			     ../lxc/network.c ../lxc/network.h \
			     ../lxc/nl.c ../lxc/nl.h \
			     ../lxc/parse.c ../lxc/parse.h \
			     ../lxc/process_utils.c ../lxc/process_utils.h \
			     ../lxc/ringbuf.c ../lxc/ringbuf.h \
			     ../lxc/start.c ../lxc/start.h \
			     ../lxc/state.c ../lxc/state.h \
			     ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			     ../lxc/storage/dir.c ../lxc/storage/dir.h \
			     ../lxc/storage/loop.c ../lxc/storage/loop.h \
			     ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			     ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			     ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			     ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			     ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			     ../lxc/storage/storage.c ../lxc/storage/storage.h \
			     ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			     ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			     ../lxc/sync.c ../lxc/sync.h \
			     ../lxc/string_utils.c ../lxc/string_utils.h \
			     ../lxc/terminal.c ../lxc/terminal.h \
			     ../lxc/utils.c ../lxc/utils.h \
			     ../lxc/uuid.c ../lxc/uuid.h \
			     $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_raw_clone_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_raw_clone_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

lxc_test_reboot_SOURCES = reboot.c
lxc_test_saveconfig_SOURCES = saveconfig.c
lxc_test_share_ns_SOURCES = share_ns.c \
			    lxctest.h \
			    ../lxc/compiler.h
lxc_test_shortlived_SOURCES = shortlived.c \
			      ../lxc/file_utils.c ../lxc/file_utils.h \
			      ../lxc/string_utils.c ../lxc/string_utils.h
lxc_test_shutdowntest_SOURCES = shutdowntest.c
lxc_test_snapshot_SOURCES = snapshot.c
lxc_test_startone_SOURCES = startone.c
lxc_test_state_server_SOURCES = state_server.c \
				lxctest.h \
				../lxc/compiler.h
lxc_test_utils_SOURCES = lxc-test-utils.c \
			 lxctest.h \
			  ../lxc/af_unix.c ../lxc/af_unix.h \
			  ../lxc/caps.c ../lxc/caps.h \
			  ../lxc/cgroups/cgfsng.c \
			  ../lxc/cgroups/cgroup.c ../lxc/cgroups/cgroup.h \
			  ../lxc/cgroups/cgroup2_devices.c ../lxc/cgroups/cgroup2_devices.h \
			  ../lxc/cgroups/cgroup_utils.c ../lxc/cgroups/cgroup_utils.h \
			  ../lxc/commands.c ../lxc/commands.h \
			  ../lxc/commands_utils.c ../lxc/commands_utils.h \
			  ../lxc/conf.c ../lxc/conf.h \
			  ../lxc/confile.c ../lxc/confile.h \
			  ../lxc/confile_utils.c ../lxc/confile_utils.h \
			  ../lxc/error.c ../lxc/error.h \
			  ../lxc/file_utils.c ../lxc/file_utils.h \
			  ../include/netns_ifaddrs.c ../include/netns_ifaddrs.h \
			  ../lxc/initutils.c ../lxc/initutils.h \
			  ../lxc/log.c ../lxc/log.h \
			  ../lxc/lxclock.c ../lxc/lxclock.h \
			  ../lxc/mainloop.c ../lxc/mainloop.h \
			  ../lxc/monitor.c ../lxc/monitor.h \
			  ../lxc/mount_utils.c ../lxc/mount_utils.h \
			  ../lxc/namespace.c ../lxc/namespace.h \
			  ../lxc/network.c ../lxc/network.h \
			  ../lxc/nl.c ../lxc/nl.h \
			  ../lxc/parse.c ../lxc/parse.h \
			  ../lxc/process_utils.c ../lxc/process_utils.h \
			  ../lxc/ringbuf.c ../lxc/ringbuf.h \
			  ../lxc/start.c ../lxc/start.h \
			  ../lxc/state.c ../lxc/state.h \
			  ../lxc/storage/btrfs.c ../lxc/storage/btrfs.h \
			  ../lxc/storage/dir.c ../lxc/storage/dir.h \
			  ../lxc/storage/loop.c ../lxc/storage/loop.h \
			  ../lxc/storage/lvm.c ../lxc/storage/lvm.h \
			  ../lxc/storage/nbd.c ../lxc/storage/nbd.h \
			  ../lxc/storage/overlay.c ../lxc/storage/overlay.h \
			  ../lxc/storage/rbd.c ../lxc/storage/rbd.h \
			  ../lxc/storage/rsync.c ../lxc/storage/rsync.h \
			  ../lxc/storage/storage.c ../lxc/storage/storage.h \
			  ../lxc/storage/storage_utils.c ../lxc/storage/storage_utils.h \
			  ../lxc/storage/zfs.c ../lxc/storage/zfs.h \
			  ../lxc/sync.c ../lxc/sync.h \
			  ../lxc/string_utils.c ../lxc/string_utils.h \
			  ../lxc/terminal.c ../lxc/terminal.h \
			  ../lxc/utils.c ../lxc/utils.h \
			  ../lxc/uuid.c ../lxc/uuid.h \
			  $(LSM_SOURCES)
if ENABLE_SECCOMP
lxc_test_utils_SOURCES += ../lxc/seccomp.c ../lxc/lxcseccomp.h
endif

if !HAVE_STRCHRNUL
lxc_test_utils_SOURCES += ../include/strchrnul.c ../include/strchrnul.h
endif

AM_CFLAGS += -DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	     -DLXCPATH=\"$(LXCPATH)\" \
	     -DLXC_GLOBAL_CONF=\"$(LXC_GLOBAL_CONF)\" \
	     -DLXCINITDIR=\"$(LXCINITDIR)\" \
	     -DLIBEXECDIR=\"$(LIBEXECDIR)\" \
	     -DLOGPATH=\"$(LOGPATH)\" \
	     -DLXCTEMPLATEDIR=\"$(LXCTEMPLATEDIR)\" \
	     -DLXC_DEFAULT_CONFIG=\"$(LXC_DEFAULT_CONFIG)\" \
	     -DDEFAULT_CGROUP_PATTERN=\"$(DEFAULT_CGROUP_PATTERN)\" \
	     -DRUNTIME_PATH=\"$(RUNTIME_PATH)\" \
	     -DSBINDIR=\"$(SBINDIR)\" \
	     -I $(top_srcdir)/src \
	     -I $(top_srcdir)/src/lxc \
	     -I $(top_srcdir)/src/lxc/cgroups \
	     -I $(top_srcdir)/src/lxc/tools \
	     -I $(top_srcdir)/src/lxc/storage \
	     -pthread

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
AM_CFLAGS += -DAPPARMOR_CACHE_DIR=\"$(APPARMOR_CACHE_DIR)\"
endif

if ENABLE_SECCOMP
AM_CFLAGS += -DHAVE_SECCOMP \
	     $(SECCOMP_CFLAGS)
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

bin_PROGRAMS = lxc-test-api-reboot \
	       lxc-test-apparmor \
	       lxc-test-arch-parse \
	       lxc-test-attach \
	       lxc-test-basic \
	       lxc-test-cgpath \
	       lxc-test-clonetest \
	       lxc-test-concurrent \
	       lxc-test-config-jump-table \
	       lxc-test-console \
	       lxc-test-console-log \
	       lxc-test-containertests \
	       lxc-test-createtest \
	       lxc-test-criu-check-feature \
	       lxc-test-cve-2019-5736 \
	       lxc-test-destroytest \
	       lxc-test-device-add-remove \
	       lxc-test-getkeys \
	       lxc-test-get_item \
	       lxc-test-list \
	       lxc-test-locktests \
	       lxc-test-lxcpath \
	       lxc-test-may-control \
	       lxc-test-mount-injection \
	       lxc-test-parse-config-file \
	       lxc-test-raw-clone \
	       lxc-test-reboot \
	       lxc-test-saveconfig \
	       lxc-test-share-ns \
	       lxc-test-shortlived \
	       lxc-test-shutdowntest \
	       lxc-test-snapshot \
	       lxc-test-startone \
	       lxc-test-state-server \
	       lxc-test-utils

bin_SCRIPTS =
if ENABLE_TOOLS
bin_SCRIPTS += lxc-test-automount \
	       lxc-test-autostart \
	       lxc-test-cloneconfig \
	       lxc-test-createconfig \
	       lxc-test-exit-code \
	       lxc-test-no-new-privs \
	       lxc-test-rootfs \
	       lxc-test-procsys \
	       lxc-test-usernsexec

if DISTRO_UBUNTU
bin_SCRIPTS += lxc-test-lxc-attach \
	       lxc-test-apparmor-mount \
	       lxc-test-apparmor-generated \
	       lxc-test-checkpoint-restore \
	       lxc-test-snapdeps \
	       lxc-test-symlink \
	       lxc-test-unpriv \
	       lxc-test-usernic
endif
endif

if ENABLE_FUZZERS
LIB_FUZZING_ENGINE ?= -fsanitize=fuzzer

# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements
nodist_EXTRA_fuzz_lxc_config_read_SOURCES = dummy.cxx
fuzz_lxc_config_read_SOURCES = fuzz-lxc-config-read.c
fuzz_lxc_config_read_CFLAGS = $(AM_CFLAGS)
fuzz_lxc_config_read_CXXFLAGS = $(AM_CFLAGS)
fuzz_lxc_config_read_LDFLAGS = $(AM_LDFLAGS) -static
fuzz_lxc_config_read_LDADD = $(LDADD) $(LIB_FUZZING_ENGINE)

nodist_EXTRA_fuzz_lxc_define_load_SOURCES = dummy.cxx
fuzz_lxc_define_load_SOURCES = fuzz-lxc-define-load.c
fuzz_lxc_define_load_CFLAGS = $(AM_CFLAGS)
fuzz_lxc_define_load_CXXFLAGS = $(AM_CFLAGS)
fuzz_lxc_define_load_LDFLAGS = $(AM_LDFLAGS) -static
fuzz_lxc_define_load_LDADD = $(LDADD) $(LIB_FUZZING_ENGINE)

nodist_EXTRA_fuzz_lxc_cgroup_init_SOURCES = dummy.cxx
fuzz_lxc_cgroup_init_SOURCES = fuzz-lxc-cgroup-init.c
fuzz_lxc_cgroup_init_CFLAGS = $(AM_CFLAGS)
fuzz_lxc_cgroup_init_CXXFLAGS = $(AM_CFLAGS)
fuzz_lxc_cgroup_init_LDFLAGS = $(AM_LDFLAGS) -static
fuzz_lxc_cgroup_init_LDADD = $(LDADD) $(LIB_FUZZING_ENGINE)

bin_PROGRAMS += fuzz-lxc-cgroup-init \
		fuzz-lxc-config-read \
		fuzz-lxc-define-load

bin_SCRIPTS += lxc-test-fuzzers
endif
endif

EXTRA_DIST = arch_parse.c \
	     basic.c \
	     cgpath.c \
	     clonetest.c \
	     concurrent.c \
	     config_jump_table.c \
	     console.c \
	     console_log.c \
	     containertests.c \
	     createtest.c \
	     criu_check_feature.c \
	     cve-2019-5736.c \
	     destroytest.c \
	     device_add_remove.c \
	     get_item.c \
	     getkeys.c \
	     list.c \
	     locktests.c \
	     lxcpath.c \
	     lxc_raw_clone.c \
	     lxc-test-lxc-attach \
	     lxc-test-automount \
	     lxc-test-rootfs \
	     lxc-test-procsys \
	     lxc-test-autostart \
	     lxc-test-apparmor-mount \
	     lxc-test-apparmor-generated \
	     lxc-test-checkpoint-restore \
	     lxc-test-cloneconfig \
	     lxc-test-createconfig \
	     lxc-test-exit-code \
	     lxc-test-no-new-privs \
	     lxc-test-snapdeps \
	     lxc-test-symlink \
	     lxc-test-unpriv \
	     lxc-test-usernsexec \
	     lxc-test-utils.c \
	     may_control.c \
	     mount_injection.c \
	     parse_config_file.c \
	     saveconfig.c \
	     shortlived.c \
	     shutdowntest.c \
	     snapshot.c \
	     startone.c \
	     state_server.c \
	     share_ns.c

clean-local:
	rm -f lxc-test-utils-*
	rm -f lxc-parse-config-file-*
