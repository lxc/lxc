EXTRA_DIST = Doxyfile

if ENABLE_API_DOCS
html: Doxyfile
	doxygen
endif

.PHONY: html

all-local: html

clean-local:
	$(RM) -rf html
