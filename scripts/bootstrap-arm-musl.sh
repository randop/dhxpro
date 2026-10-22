#!/bin/sh
# Install the armv7 musl cross linker used by .cargo/config.toml and the
# Rust armv7-unknown-linux-musleabihf target.
set -eu

prefix="${HOME}/opt/armv7l-linux-musleabihf-cross"
gcc="${prefix}/bin/armv7l-linux-musleabihf-gcc"

if [ ! -x "${gcc}" ]; then
    url="https://musl.cc/armv7l-linux-musleabihf-cross.tgz"
    tmp="$(mktemp)"
    echo "downloading ${url}"
    curl -fsSL -o "${tmp}" "${url}"
    mkdir -p "${HOME}/opt"
    tar -C "${HOME}/opt" -xzf "${tmp}"
    rm -f "${tmp}"
fi

rustup target add armv7-unknown-linux-musleabihf
echo "linker: ${gcc}"
echo "add to PATH: ${prefix}/bin"
