LDADD = ../lxc/liblxc.so -lrt
containertests_SOURCES = containertests.c
locktests_SOURCES = locktests.c
startone_SOURCES = startone.c
destroytest_SOURCES = destroytest.c
saveconfig_SOURCES = saveconfig.c
createtest_SOURCES = createtest.c
shutdowntest_SOURCES = shutdowntest.c
get_item_SOURCES = get_item.c
getkeys_SOURCES = getkeys.c

AM_CFLAGS=-I$(top_srcdir)/src \
	-DLXCROOTFSMOUNT=\"$(LXCROOTFSMOUNT)\" \
	-DLXCPATH=\"$(LXCPATH)\" \
	-DLXCINITDIR=\"$(LXCINITDIR)\"

bin_PROGRAMS = containertests locktests startone destroytest saveconfig createtest shutdowntest get_item getkeys
