#!/bin/sh
# Confirm the release binary is a static 32-bit ARM ELF with no interpreter
# and no shared-library dependencies.
set -eu
cd "$(dirname "$0")/.."
bin="${1:-target/armv7-unknown-linux-musleabihf/release/dhxpro}"

if [ ! -f "${bin}" ]; then
    echo "missing ${bin}; run scripts/arm-release.sh first" >&2
    exit 1
fi

file "${bin}"
machine="$(readelf -h "${bin}" | awk '/Machine:/ { print $2 }')"
class="$(readelf -h "${bin}" | awk '/Class:/ { print $2 }')"
if [ "${class}" != "ELF32" ] || [ "${machine}" != "ARM" ]; then
    echo "expected ELF32 ARM, found class=${class} machine=${machine}" >&2
    exit 1
fi

if readelf -l "${bin}" | grep -q ' INTERP'; then
    echo "dynamic interpreter is present" >&2
    readelf -l "${bin}"
    exit 1
fi

if readelf -d "${bin}" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "shared library dependencies are present" >&2
    readelf -d "${bin}"
    exit 1
fi

echo "static ELF32 ARM binary: ${bin}"
