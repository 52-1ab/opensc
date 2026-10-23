# Project-level entry points. The C wallet lives in lite/ (see lite/Makefile)
# and the Java side builds with maven (pom.xml); this file only drives the
# holistic API docs for the whole project.

DOXYGEN ?= doxygen

.PHONY: docs docs-clean

# Generate HTML + man docs for secure_component.c and the lite public API.
docs:
	mkdir -p build/docs
	$(DOXYGEN) Doxyfile

docs-clean:
	rm -rf build/docs
