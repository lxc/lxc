if ENABLE_LUA

luasharedir=$(LUA_SHAREDIR)
lualibdir=$(LUA_LIBDIR)
luadir=$(luasharedir)
sodir=$(lualibdir)/lxc

lua_DATA=lxc.lua

so_PROGRAMS = core.so

core_so_SOURCES = core.c

AM_CFLAGS=-I$(top_builddir)/src -I$(top_srcdir)/src $(LUA_CFLAGS) -DVERSION=\"$(VERSION)\" -DLXCPATH=\"$(LXCPATH)\"

core_so_CFLAGS = -fPIC -DPIC $(AM_CFLAGS)

core_so_LDFLAGS = \
	-shared \
	-L$(top_builddir)/src/lxc \
	-Wl,-soname,core.so.$(firstword $(subst ., ,$(VERSION)))

core_so_LDADD = -llxc

lxc.lua:

endif

EXTRA_DIST= \
	lxc.lua \
	test/apitest.lua
