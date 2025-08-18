# SPDX-License-Identifier: LGPL-2.1+

MESON ?= meson
NINJA ?= ninja

BUILDDIR := buildDir
DISTDIR := $(BUILDDIR)/meson-dist

.PHONY: all meson dist install clean rebuild help

help:
	@echo "Available commands:"
	@echo "  all      - Build the project"
	@echo "  meson    - Configure or reconfigure the project with Meson"
	@echo "  dist     - Create the distribution package"
	@echo "  install  - Install the project"
	@echo "  clean    - Remove generated files"
	@echo "  rebuild  - Clean and rebuild everything"
	@echo "  help     - Show this message"

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
	$(RM) -rf $(BUILDDIR) *.tar.gz

rebuild:
	$(MAKE) clean
	$(MAKE) all