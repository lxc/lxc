if ENABLE_TEST

AM_LDFLAGS = -lutil

INCLUDES= -I$(top_srcdir)/src

noinst_PROGRAMS = \
	tst_list \
	confile \
	conf \
	movedev \
	dev \
	forward \
	proxy \
	veth \
	macvlan \
	ipv4_add \
	ipv6_add \
	\
	lxc_create \
	lxc_destroy \
	lxc_start \
	lxc_stop \
	lxc_monitor \
	lxc_low_monitor \
	lxc_state

tst_list_SOURCES = tst_list.c
tst_list_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

confile_SOURCES = confile.c
confile_LDADD = \
	$(top_builddir)/src/lxc/conf.o \
	$(top_builddir)/src/lxc/confile.o \
	$(top_builddir)/src/lxc/liblxc.la

conf_SOURCES = conf.c
conf_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

movedev_SOURCES = movedev.c
movedev_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

dev_SOURCES = dev.c
dev_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

forward_SOURCES = forward.c
forward_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

proxy_SOURCES = proxy.c
proxy_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

veth_SOURCES = veth.c
veth_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

macvlan_SOURCES = macvlan.c
macvlan_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

ipv4_add_SOURCES = ipv4_add.c
ipv4_add_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

ipv6_add_SOURCES = ipv6_add.c
ipv6_add_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_create_SOURCES = lxc_create.c
lxc_create_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_start_SOURCES = lxc_start.c
lxc_start_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitor_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_low_monitor_SOURCES = lxc_low_monitor.c
lxc_low_monitor_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

lxc_state_SOURCES = lxc_state.c
lxc_state_LDADD = \
	$(top_builddir)/src/lxc/liblxc.la

endif
