INCLUDES= -I$(top_srcdir)/src/liblxc -I$(top_srcdir)/src

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
	lxc-unfreeze \
	lxc-priority

lxc_create_SOURCES = lxc_create.c lxc_config.c lxc_config.h
lxc_create_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_destroy_SOURCES = lxc_destroy.c
lxc_destroy_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_start_SOURCES = lxc_start.c
lxc_start_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_stop_SOURCES = lxc_stop.c
lxc_stop_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_execute_SOURCES = lxc_execute.c
lxc_execute_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la

lxc_monitor_SOURCES = lxc_monitor.c
lxc_monitor_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_console_SOURCES = lxc_console.c
lxc_console_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la

lxc_state_SOURCES = lxc_state.c
lxc_state_LDADD = \
	$(top_builddir)/src/liblxc/liblxc.la

lxc_kill_SOURCES = lxc_kill.c
lxc_kill_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la

lxc_freeze_SOURCES = lxc_freeze.c
lxc_freeze_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la

lxc_unfreeze_SOURCES = lxc_unfreeze.c
lxc_unfreeze_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la

lxc_priority_SOURCES = lxc_priority.c
lxc_priority_LDADD = \
        $(top_builddir)/src/liblxc/liblxc.la
