if ENABLE_TESTS

LDADD = ../lxc/liblxc.so

if !IS_BIONIC
LDADD += -lpthread
endif

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

AM_CFLAGS=-I$(top_srcdir)/src \
	-DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	-DLXCPATH=\"$(LXCPATH)\" \
	-DLXC_GLOBAL_CONF=\"$(LXC_GLOBAL_CONF)\" \
	-DLXCINITDIR=\"$(LXCINITDIR)\"

bin_PROGRAMS = lxc-test-containertests lxc-test-locktests lxc-test-startone \
	lxc-test-destroytest lxc-test-saveconfig lxc-test-createtest \
	lxc-test-shutdowntest lxc-test-get_item lxc-test-getkeys lxc-test-lxcpath

endif
