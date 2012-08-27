if ENABLE_PYTHON

if HAVE_DEBIAN
    DISTSETUPOPTS=--install-layout=deb
else
    DISTSETUPOPTS=
endif

all:
	CFLAGS="$(CFLAGS) -I ../../src -L../../src/lxc/" $(PYTHON) setup.py build

install:
	python3 setup.py install --root=$(DESTDIR) --prefix=$(PREFIX) --no-compile $(DISTSETUPOPTS)

clean:
	rm -rf build

endif
