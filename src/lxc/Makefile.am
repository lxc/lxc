INCLUDES= -I$(top_srcdir)/src/liblxc

bin_SCRIPTS = \
	lxc-ps

bin_PROGRAMS = \
	lxc-create \
	lxc-destroy \
	lxc-stop \
	lxc-start \
	lxc-execute \
	lxc-monitor \
	lxc-console \
	lxc-state \
	lxc-kill \
	lxc-freeze \
	lxc-unfreeze

lxc_create_SOURCES = lxc_create.c config.c config.h
lxc_create_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_start_SOURCES = lxc_start.c
lxc_start_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_execute_SOURCES = lxc_execute.c config.c
lxc_execute_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.a

lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitor_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_console_SOURCES = lxc_console.c
lxc_console_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.a

lxc_state_SOURCES = lxc_state.c
lxc_state_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.a

lxc_kill_SOURCES = lxc_kill.c
lxc_kill_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.a

lxc_freeze_SOURCES = lxc_freeze.c
lxc_freeze_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.a

lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unfreeze_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.a
