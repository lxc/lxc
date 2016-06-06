if ENABLE_PYTHON

if HAVE_DEBIAN
    DISTSETUPOPTS=--install-layout=deb
else
    DISTSETUPOPTS=
endif

if ENABLE_RPATH
    RPATHOPTS=-R $(libdir)
else
    RPATHOPTS=
endif

CALL_SETUP_PY := cd @srcdir@ && $(PYTHON) setup.py build -b @abs_builddir@/build egg_info -e @abs_builddir@

all:
	$(CALL_SETUP_PY) build_ext -I @abs_top_srcdir@/src -L @abs_top_builddir@/src/lxc $(RPATHOPTS) --no-pkg-config

DESTDIR = / # default

install:
	$(CALL_SETUP_PY) install --prefix=$(prefix) --no-compile $(DISTSETUPOPTS) --root=$(DESTDIR)

clean-local:
	rm -rf @builddir@/build

endif
EXTRA_DIST = \
	setup.py \
	lxc.c \
	lxc/__init__.py \
	examples/api_test.py \
	examples/pyconsole.py \
	examples/pyconsole-vte.py
