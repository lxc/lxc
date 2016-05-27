if ENABLE_PYTHON

if HAVE_DEBIAN
    DISTSETUPOPTS=--install-layout=deb
else
    DISTSETUPOPTS=
endif

INSTALL_OPTS := install --prefix=$(prefix) --no-compile $(DISTSETUPOPTS)
CALL_SETUP_PY := cd @srcdir@ && $(PYTHON) setup.py build -b @abs_builddir@/build

all:
	$(CALL_SETUP_PY) build_ext -I @abs_top_srcdir@/src -L @abs_top_builddir@/src/lxc

install:
	if [ -z "$(DESTDIR)" ]; then \
		$(CALL_SETUP_PY) $(INSTALL_OPTS); \
	else \
		$(CALL_SETUP_PY) $(INSTALL_OPTS) --root=$(DESTDIR); \
	fi

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
