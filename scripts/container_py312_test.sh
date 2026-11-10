#!/usr/bin/env bash
# Runs the C and Python test suites inside python:3.12-slim against a read-only
# copy of the repository (host build directories and virtualenvs are excluded).
# The C library is built with the container's compiler and installed to
# /usr/local/lib, so the binding's documented Docker discovery path is exercised.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -v "$REPO_ROOT":/src:ro python:3.12-slim bash -euo pipefail -c '
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gcc libc6-dev cmake make git >/dev/null 2>&1
echo "python: $(python --version)  gcc: $(gcc -dumpfullversion)  glibc: $(ldd --version | head -1 | grep -o "[0-9.]*$")"
mkdir /work && cd /src && tar --exclude=./c-library/build --exclude=./c-library/build-asan \
    --exclude=./backend/.venv --exclude="*/__pycache__" --exclude=./backend/.pytest_cache \
    --exclude=./backend/.mypy_cache --exclude=./frontend/node_modules -cf - . | tar -C /work -xf -
cd /work
cmake -S c-library -B /tmp/cbuild -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build /tmp/cbuild -j"$(nproc)" 2>&1 | grep -E "warning|error" || echo "C build: no warnings/errors"
ctest --test-dir /tmp/cbuild 2>&1 | grep -E "tests passed|tests failed"
cmake --install /tmp/cbuild --prefix /usr/local >/dev/null && ldconfig
pip install -q --root-user-action=ignore -r backend/requirements-dev.txt 2>&1 | grep -v notice || true
cd backend
echo "binding loads: $(python -c "import call_analyzer; print(call_analyzer.library_path())")"
python -m pytest -q -p no:cacheprovider "$@" 2>&1 | tail -3
mypy 2>&1 | tail -1
' bash "$@"
