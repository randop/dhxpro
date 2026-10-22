#!/bin/sh
# Install the armv7 musl cross linker used by .cargo/config.toml and the
# Rust armv7-unknown-linux-musleabihf target.
set -eu

prefix="${HOME}/opt/armv7l-linux-musleabihf-cross"
gcc="${prefix}/bin/armv7l-linux-musleabihf-gcc"

if [ ! -x "${gcc}" ]; then
    # GCC 11.2.1 archive, verified against the publisher's SHA512SUMS at
    # https://more.musl.cc/11.2.1/x86_64-linux-musl/SHA512SUMS.
    url="https://more.musl.cc/11.2.1/x86_64-linux-musl/armv7l-linux-musleabihf-cross.tgz"
    sha256="d13e616bba82c174c5dd20994141b07331952245acc8a2bf3c1243c56c1d6438"
    tmp="$(mktemp)"
    trap 'rm -f "${tmp}"' EXIT HUP INT TERM
    echo "downloading ${url}"
    curl -fsSL -o "${tmp}" "${url}"
    printf '%s  %s\n' "${sha256}" "${tmp}" | sha256sum -c -
    mkdir -p "${HOME}/opt"
    tar -C "${HOME}/opt" -xzf "${tmp}"
    rm -f "${tmp}"
fi

rustup target add armv7-unknown-linux-musleabihf
echo "linker: ${gcc}"
echo "add to PATH: ${prefix}/bin"
