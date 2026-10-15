#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python_bin=.venv-mac/bin/python
[ -x "$python_bin" ] || python_bin=.venv/bin/python
if [ "$(uname -s)" = Darwin ]; then
    omp_dir="$($python_bin -c 'import importlib.util; from pathlib import Path; print(Path(importlib.util.find_spec("sklearn").origin).parent / ".dylibs")')"
    export DYLD_LIBRARY_PATH="$omp_dir${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi
exec "$python_bin" -m pytest -q --basetemp=data/pytest-local "$@"
