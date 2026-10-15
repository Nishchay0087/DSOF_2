#!/bin/sh
# The administrator password goes to sudo, never to Python or the dashboard.
# Only tcpdump runs privileged. No permissions or system settings are changed.
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Darwin ] || { echo 'This helper is for macOS.'; exit 1; }
[ -p data/capture.pipe ] || { echo 'Run sh tools/prepare_capture.sh first.'; exit 1; }
printf '%s\n' 'Capturing loopback TCP/UDP only. Start DSOF first. Ctrl+C stops capture.'
sudo /usr/sbin/tcpdump -i lo0 -n -U -s 65535 -w - '((tcp or udp) and (net 127.0.0.0/8 or host ::1))' > data/capture.pipe
