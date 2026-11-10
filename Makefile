PY ?= python3

.PHONY: all c test demo bench clean

all: c

c:
	$(MAKE) -C c-library

test: c
	$(MAKE) -C c-library test asan
	$(PY) -m unittest discover -s tests -t . -v

demo: c
	$(PY) -m nexus demo

bench: c
	$(PY) -m nexus bench

clean:
	$(MAKE) -C c-library clean
	rm -rf out
