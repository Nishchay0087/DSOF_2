#!/bin/sh
set -eu
cd "$(dirname "$0")/../frontend"
command -v node >/dev/null 2>&1 || { echo 'Install Node.js 22 or newer and put it on PATH.' >&2; exit 1; }
[ -f node_modules/typescript/bin/tsc ] || { echo 'Run pnpm install --frozen-lockfile in frontend/ first.' >&2; exit 1; }
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build
