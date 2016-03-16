if ENABLE_TESTS

LDADD = ../lxc/liblxc.so

lxc_test_containertests_SOURCES = containertests.c
lxc_test_locktests_SOURCES = locktests.c
lxc_test_startone_SOURCES = startone.c
lxc_test_destroytest_SOURCES = destroytest.c
lxc_test_saveconfig_SOURCES = saveconfig.c
lxc_test_createtest_SOURCES = createtest.c
lxc_test_shutdowntest_SOURCES = shutdowntest.c
lxc_test_get_item_SOURCES = get_item.c
lxc_test_getkeys_SOURCES = getkeys.c
lxc_test_lxcpath_SOURCES = lxcpath.c
lxc_test_cgpath_SOURCES = cgpath.c
lxc_test_clonetest_SOURCES = clonetest.c
lxc_test_console_SOURCES = console.c
lxc_test_snapshot_SOURCES = snapshot.c
lxc_test_concurrent_SOURCES = concurrent.c
lxc_test_may_control_SOURCES = may_control.c
lxc_test_reboot_SOURCES = reboot.c
lxc_test_list_SOURCES = list.c
lxc_test_attach_SOURCES = attach.c
lxc_test_device_add_remove_SOURCES = device_add_remove.c
lxc_test_apparmor_SOURCES = aa.c

AM_CFLAGS=-I$(top_srcdir)/src \
	-DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	-DLXCPATH=\"$(LXCPATH)\" \
	-DLXC_GLOBAL_CONF=\"$(LXC_GLOBAL_CONF)\" \
	-DLXCINITDIR=\"$(LXCINITDIR)\" \
	-DLXC_DEFAULT_CONFIG=\"$(LXC_DEFAULT_CONFIG)\" \
	-DRUNTIME_PATH=\"$(RUNTIME_PATH)\"

if ENABLE_APPARMOR
AM_CFLAGS += -DHAVE_APPARMOR
endif

if ENABLE_SELINUX
AM_CFLAGS += -DHAVE_SELINUX
endif

bin_PROGRAMS = lxc-test-containertests lxc-test-locktests lxc-test-startone \
	lxc-test-destroytest lxc-test-saveconfig lxc-test-createtest \
	lxc-test-shutdowntest lxc-test-get_item lxc-test-getkeys lxc-test-lxcpath \
	lxc-test-cgpath lxc-test-clonetest lxc-test-console \
	lxc-test-snapshot lxc-test-concurrent lxc-test-may-control \
	lxc-test-reboot lxc-test-list lxc-test-attach lxc-test-device-add-remove \
	lxc-test-apparmor

bin_SCRIPTS = lxc-test-automount lxc-test-autostart lxc-test-cloneconfig \
	lxc-test-createconfig

if DISTRO_UBUNTU
bin_SCRIPTS += \
	lxc-test-lxc-attach \
	lxc-test-apparmor-mount \
	lxc-test-checkpoint-restore \
	lxc-test-snapdeps \
	lxc-test-symlink \
	lxc-test-ubuntu \
	lxc-test-unpriv \
	lxc-test-usernic
endif

endif

EXTRA_DIST = \
	cgpath.c \
	clonetest.c \
	concurrent.c \
	console.c \
	containertests.c \
	createtest.c \
	destroytest.c \
	device_add_remove.c \
	get_item.c \
	getkeys.c \
	list.c \
	locktests.c \
	lxcpath.c \
	lxc-test-lxc-attach \
	lxc-test-automount \
	lxc-test-autostart \
	lxc-test-apparmor-mount \
	lxc-test-checkpoint-restore \
	lxc-test-cloneconfig \
	lxc-test-createconfig \
	lxc-test-snapdeps \
	lxc-test-symlink \
	lxc-test-ubuntu \
	lxc-test-unpriv \
	may_control.c \
	saveconfig.c \
	shutdowntest.c \
	snapshot.c \
	startone.c
