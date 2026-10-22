#!/bin/sh
# Release build of the static ARMv7-A musl binary.
set -eu
cd "$(dirname "$0")/.."
export PATH="${HOME}/opt/armv7l-linux-musleabihf-cross/bin:${PATH}"
if ! command -v armv7l-linux-musleabihf-gcc >/dev/null 2>&1; then
    echo "armv7l-linux-musleabihf-gcc is not on PATH; run scripts/bootstrap-arm-musl.sh" >&2
    exit 1
fi
exec cargo build --release --target armv7-unknown-linux-musleabihf "$@"
