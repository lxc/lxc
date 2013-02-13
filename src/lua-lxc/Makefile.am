if ENABLE_LUA

luadir=$(datadir)/lua/5.1
sodir=$(libdir)/lua/5.1/lxc

lua_SCRIPTS=lxc.lua
EXTRA_DIST=lxc.lua

so_PROGRAMS = core.so

core_so_SOURCES = core.c

AM_CFLAGS=-I$(top_srcdir)/src $(LUA_CFLAGS) -DVERSION=\"$(VERSION)\" -DLXCPATH=\"$(LXCPATH)\"

core_so_CFLAGS = -fPIC -DPIC $(AM_CFLAGS)

core_so_LDFLAGS = \
	-shared \
	-L$(top_srcdir)/src/lxc \
	-Wl,-soname,core.so.$(firstword $(subst ., ,$(VERSION)))

core_so_LDADD = -llxc $(LUA_LIBS)

lxc.lua:

endif
