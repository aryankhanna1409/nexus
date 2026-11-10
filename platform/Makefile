# Aegis-Net top-level Makefile.
# Targets are added milestone by milestone.

C_DIR        := c-library
C_BUILD      := $(C_DIR)/build
C_BUILD_ASAN := $(C_DIR)/build-asan
JOBS         ?= $(shell nproc 2>/dev/null || echo 4)
PYTHON       ?= python3
VENV         := backend/.venv
VENV_PY      := $(VENV)/bin/python
VENV_STAMP   := $(VENV)/.requirements-installed
SEED         ?= 42




.PHONY: demo
.PHONY: frontend-test
.PHONY: env docker-build docker-up docker-down docker-smoke
.PHONY: help c-build c-test c-test-asan py-venv py-test py-test-asan py-typecheck call-logs network-data container-test test clean

help:
	@echo "Targets:"
	@echo "  c-build       Build libcallanalyzer (warnings as errors)"
	@echo "  c-test        Build and run the C test suite"
	@echo "  c-test-asan   Build and run the C tests with ASan/UBSan/LSan"
	@echo "  py-venv       Create backend/.venv with pinned dev tools"
	@echo "  py-test       Run Python tests against the locally built library"
	@echo "  py-test-asan  Run Python tests against the ASan/UBSan library build"
	@echo "  py-typecheck  Run mypy --strict on the binding and generator"
	@echo "  call-logs     Generate data/call_logs/call_logs.csv (SEED=$(SEED))"
	@echo "  network-data  Simulate the seeded incident into data/ (telemetry, events, CDRs)"
	@echo "  container-test  Run C + Python tests in a python:3.12-slim container"
	@echo "  env           Create .env with generated tokens/passwords (never overwrites)"
	@echo "  docker-up     docker compose up --build -d"
	@echo "  docker-smoke  Build, start and smoke-test the Docker stack, then stop it"
	@echo "  docker-down   Stop the stack (keeps volumes)"
	@echo "  frontend-test Type-check, test and build the dashboard in a node:22 container"
	@echo "  demo          Offline end-to-end demo (SQLite, mock LLM, synthetic data)"
	@echo "  test          Run all available test suites"
	@echo "  clean         Remove build artifacts and caches"

c-build:
	cmake -S $(C_DIR) -B $(C_BUILD) -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cmake --build $(C_BUILD) -j $(JOBS)

c-test: c-build
	ctest --test-dir $(C_BUILD) --output-on-failure

c-test-asan:
	cmake -S $(C_DIR) -B $(C_BUILD_ASAN) -DCMAKE_BUILD_TYPE=Debug -DCA_ENABLE_SANITIZERS=ON
	cmake --build $(C_BUILD_ASAN) -j $(JOBS)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		ctest --test-dir $(C_BUILD_ASAN) --output-on-failure

# Stamp file: bin/python is a symlink to the system interpreter and must not be touched.
$(VENV_STAMP): backend/requirements.txt backend/requirements-llm.txt backend/requirements-dev.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --quiet -r backend/requirements-dev.txt
	touch $(VENV_STAMP)

py-venv: $(VENV_STAMP)

# CALL_ANALYZER_LIB is cleared so tests exercise default discovery of the local build.
py-test: c-build py-venv
	cd backend && env -u CALL_ANALYZER_LIB .venv/bin/python -m pytest

# The interpreter is not instrumented, so the sanitizer runtimes are preloaded.
# detect_leaks=0: CPython intentionally leaks at exit; native leaks are covered by
# the C LSan suite, the ownership-spy tests and the glibc heap tests in py-test.
# The glibc heap tests skip themselves here (ASan replaces the allocator).
py-test-asan: c-test-asan py-venv
	cd backend && env -u CALL_ANALYZER_LIB \
		LD_PRELOAD="$$($(CC) -print-file-name=libasan.so) $$($(CC) -print-file-name=libubsan.so)" \
		ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		CALL_ANALYZER_LIB=$(CURDIR)/$(C_BUILD_ASAN)/libcallanalyzer.so \
		.venv/bin/python -m pytest

py-typecheck: py-venv
	cd backend && .venv/bin/mypy

call-logs:
	$(PYTHON) scripts/generate_call_logs.py --seed $(SEED) \
		--output data/call_logs/call_logs.csv --manifest data/call_logs/call_logs.manifest.json

network-data: py-venv
	$(VENV_PY) scripts/generate_network_metrics.py --scenario seeded --seed 7 --out-dir data

demo: c-build py-venv
	$(VENV_PY) scripts/demo.py

# Node is not required on the host: the dashboard is checked inside node:22-alpine.
frontend-test:
	docker run --rm -u "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR)/frontend":/app -w /app node:22-alpine \
		sh -c 'npm ci --no-audit --no-fund >/dev/null && npx tsc -b --noEmit && npx vitest run && npm run build'

env:
	$(PYTHON) scripts/init_env.py

docker-build:
	docker compose build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-smoke:
	scripts/docker_smoke.sh

container-test:
	scripts/container_py312_test.sh

test: c-test c-test-asan py-test py-test-asan py-typecheck frontend-test

clean:
	rm -rf $(C_BUILD) $(C_BUILD_ASAN) data/demo frontend/dist
	find reports -type f ! -name .gitkeep -delete
	find backend scripts -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf backend/.pytest_cache backend/.mypy_cache
