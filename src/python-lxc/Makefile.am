if ENABLE_PYTHON

if HAVE_DEBIAN
    DISTSETUPOPTS=--install-layout=deb
else
    DISTSETUPOPTS=
endif

all:
	CFLAGS="$(CFLAGS) -I ../../src -L../../src/lxc/" $(PYTHON) setup.py build

install:
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup.py install --prefix=$(prefix) --no-compile $(DISTSETUPOPTS); \
	else \
		$(PYTHON) setup.py install --root=$(DESTDIR) --prefix=$(prefix) --no-compile $(DISTSETUPOPTS); \
	fi

clean-local:
	rm -rf build

endif
EXTRA_DIST = \
	setup.py \
	lxc.c \
	lxc/__init__.py \
	examples/api_test.py \
	examples/pyconsole.py \
	examples/pyconsole-vte.py
