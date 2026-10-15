#!/bin/sh
# macOS/Linux launcher. Uses only dependencies in this project's environment.
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" = Darwin ]; then
    runtime_python=".venv-mac/bin/python"
else
    runtime_python=".venv/bin/python"
fi
if [ ! -x "$runtime_python" ]; then
    echo "Create the project virtual environment and install requirements.txt first." >&2
    exit 1
fi
if [ "$(uname -s)" = Darwin ]; then
    omp_dir="$($runtime_python -c 'import importlib.util; from pathlib import Path; print(Path(importlib.util.find_spec("sklearn").origin).parent / ".dylibs")')"
    if [ -f "$omp_dir/libomp.dylib" ]; then
        export DYLD_LIBRARY_PATH="$omp_dir${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    fi
fi
exec "$runtime_python" -m dsof "${@:-run}"
