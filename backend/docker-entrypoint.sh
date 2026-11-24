#!/bin/sh
# Applies migrations, optionally loads the seeded demo incident, then serves the API.
set -eu
python -c "import call_analyzer; print('libcallanalyzer', call_analyzer.library_version(), 'at', call_analyzer.library_path())"
alembic upgrade head
if [ "${AEGIS_BOOTSTRAP_DEMO:-false}" = "true" ]; then
  python -m app.bootstrap
fi
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-server-header
