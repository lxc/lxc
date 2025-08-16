# SPDX-License-Identifier: LGPL-2.1+

BUILDDIR := buildDir
DISTDIR := $(BUILDDIR)/meson-dist

.PHONY: all
all: meson
	ninja -C $(BUILDDIR)

.PHONY: meson
meson:
	@if [ ! -d $(BUILDDIR) ]; then \
		meson setup $(BUILDDIR)/ || exit 1; \
	else \
		meson setup --reconfigure $(BUILDDIR)/ || exit 1; \
	fi

.PHONY: dist
dist: meson
	meson dist -C $(BUILDDIR)/ --formats=gztar || exit 1
	cp $(DISTDIR)/*.tar.gz . || exit 1

.PHONY: install
install:
	DESTDIR=$(DESTDIR) ninja -C $(BUILDDIR) install

.PHONY: clean
clean:
	rm -rf $(BUILDDIR) *.tar.gz

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
