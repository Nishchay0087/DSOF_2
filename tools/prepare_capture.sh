#!/bin/sh
# Creates only an owner-readable FIFO; no administrator privileges needed.
set -eu
cd "$(dirname "$0")/.."
mkdir -p data
if [ -e data/capture.pipe ]; then
    [ -p data/capture.pipe ] || { echo 'data/capture.pipe exists and is not a pipe'; exit 1; }
else
    (umask 077; mkfifo data/capture.pipe)
fi
printf '%s\n' 'Capture pipe prepared. Start the dashboard with DSOF_CAPTURE_MODE=fifo.'
printf '%s\n' 'Then in a separate terminal run: sh tools/capture_macos.sh'
