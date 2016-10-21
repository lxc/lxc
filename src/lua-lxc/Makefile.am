if ENABLE_LUA

luasharedir=$(LUA_SHAREDIR)
lualibdir=$(LUA_LIBDIR)
luadir=$(luasharedir)
sodir=$(lualibdir)/lxc

lua_DATA=lxc.lua

lib_LTLIBRARIES = libcore.la
libcore_la_SOURCES = core.c

AM_CFLAGS=-I$(top_builddir)/src -I$(top_srcdir)/src $(LUA_CFLAGS) -DVERSION=\"$(VERSION)\" -DLXCPATH=\"$(LXCPATH)\"

libcore_la_CFLAGS = -fPIC -DPIC $(AM_CFLAGS)

libcore_la_LDFLAGS = \
	-shared \
	-L$(top_builddir)/src/lxc \
	-Wl,-soname,core.so.$(firstword $(subst ., ,$(VERSION)))

libcore_la_LIBADD = -llxc

install-exec-local: install-libLTLIBRARIES
	mkdir -p $(DESTDIR)$(lualibdir)/lxc/
	mv $(DESTDIR)$(libdir)/libcore.so.0.0.0 $(DESTDIR)$(lualibdir)/lxc/core.so
	rm $(DESTDIR)$(libdir)/libcore.*

uninstall-local:
	$(RM) $(DESTDIR)$(lualibdir)/lxc/core.so*

lxc.lua:

endif

EXTRA_DIST= \
	lxc.lua \
	test/apitest.lua
