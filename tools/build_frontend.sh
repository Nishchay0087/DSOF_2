#!/bin/sh
set -eu
cd "$(dirname "$0")/../frontend"
if command -v node >/dev/null 2>&1; then
    node_bin="$(command -v node)"
else
    node_bin="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
fi
[ -x "$node_bin" ] || { echo 'Install Node.js 22 or newer first.' >&2; exit 1; }
[ -f node_modules/typescript/bin/tsc ] || { echo 'Install frontend packages with pnpm install from frontend/ first.' >&2; exit 1; }
"$node_bin" node_modules/typescript/bin/tsc --noEmit
"$node_bin" node_modules/vite/bin/vite.js build
