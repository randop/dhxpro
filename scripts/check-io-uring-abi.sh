#!/bin/sh
# Verify that the io_uring kernel ABI structs used by dhxpro have the same
# layout on ARMv7 as the x86_64 definitions shipped by io-uring 0.7.15.
#
# io-uring 0.7.15 rejects 32-bit targets at compile time. dhxpro bypasses that
# check for armv7-unknown-linux-musleabihf (see .cargo/config.toml) only after
# this check confirms the fixed-width kernel ABI is identical.
set -eu
cd "$(dirname "$0")/.."

gcc="${CROSS_GCC:-${HOME}/opt/armv7l-linux-musleabihf-cross/bin/armv7l-linux-musleabihf-gcc}"
if [ ! -x "${gcc}" ]; then
    gcc="$(command -v armv7l-linux-musleabihf-gcc || true)"
fi
if [ -z "${gcc}" ]; then
    echo "armv7l-linux-musleabihf-gcc not found; run scripts/bootstrap-arm-musl.sh" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
cat > "${tmp}/io_uring_abi.c" <<'EOF'
#include <linux/io_uring.h>
#include <linux/time_types.h>
#include <stddef.h>

#define CHECK_LAYOUT(t, s, a) \
    _Static_assert(sizeof(struct t) == (s), #t " size"); \
    _Static_assert(_Alignof(struct t) == (a), #t " alignment")

CHECK_LAYOUT(io_sqring_offsets, 40, 8);
CHECK_LAYOUT(io_cqring_offsets, 40, 8);
CHECK_LAYOUT(io_uring_params, 120, 8);
CHECK_LAYOUT(io_uring_sqe, 64, 8);
CHECK_LAYOUT(io_uring_cqe, 16, 8);
CHECK_LAYOUT(io_uring_rsrc_update, 16, 8);
CHECK_LAYOUT(io_uring_rsrc_update2, 32, 8);
CHECK_LAYOUT(io_uring_files_update, 16, 8);
CHECK_LAYOUT(io_uring_getevents_arg, 24, 8);
CHECK_LAYOUT(__kernel_timespec, 16, 8);

_Static_assert(offsetof(struct io_uring_params, sq_off) == 40, "params.sq_off");
_Static_assert(offsetof(struct io_uring_params, cq_off) == 80, "params.cq_off");
_Static_assert(offsetof(struct io_uring_sqe, user_data) == 32, "sqe.user_data");
_Static_assert(offsetof(struct io_uring_cqe, res) == 8, "cqe.res");
_Static_assert(offsetof(struct io_uring_cqe, flags) == 12, "cqe.flags");
_Static_assert(offsetof(struct io_uring_getevents_arg, ts) == 16, "getevents.ts");

int main(void) { return 0; }
EOF

"${gcc}" -static -o "${tmp}/io_uring_abi" "${tmp}/io_uring_abi.c"
echo "io_uring ARMv7 ABI layout matches the io-uring 0.7.15 definitions"
