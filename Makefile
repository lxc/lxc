# SPDX-License-Identifier: LGPL-2.1+

MESON := meson
NINJA := ninja

BUILDDIR := buildDir
DISTDIR := $(BUILDDIR)/meson-dist

.PHONY: all meson dist install clean rebuild

all: meson
	$(NINJA) -C $(BUILDDIR)

meson:
	@if [ ! -d $(BUILDDIR) ]; then \
		$(MESON) setup $(BUILDDIR); \
	else \
		$(MESON) setup --reconfigure $(BUILDDIR); \
	fi

dist: meson
	$(MESON) dist -C $(BUILDDIR) --formats=gztar
	cp $(DISTDIR)/*.tar.gz .

install:
	DESTDIR=$(DESTDIR) $(NINJA) -C $(BUILDDIR) install

clean:
	rm -rf $(BUILDDIR) *.tar.gz

rebuild:
	$(MAKE) clean
	$(MAKE) all