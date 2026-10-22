# dhxpro

dhxpro is a static ARMv7-A musl DHCPv4 server for embedded Linux. All DHCP
packet I/O is performed through Linux `io_uring`; all reservations, leases and
allocator state live in FeOxDB. There is no socket or storage fallback.

The primary target is the Luckfox Pico Pro / Max running a Buildroot kernel
with `io_uring` enabled.

## Architecture

- `src/net.rs` owns the UDP socket, `IP_PKTINFO` ancillary data, io_uring
  `RECVMSG`/`SENDMSG`/`TIMEOUT`/`ASYNC_CANCEL` operations, send buffer
  lifetimes, signal-driven shutdown and operation cancellation.
- `src/dhcp.rs` is a purpose-built DHCPv4 codec. It parses and validates
  packets and builds OFFER, ACK, NAK and INFORM replies without a DHCP crate
  dependency. It performs no network I/O.
- `src/server.rs` implements subnet/relay selection and the DHCP state machine.
- `src/alloc.rs` applies one eligibility policy to incremental and random
  allocation, reservations, offers, renewals, releases, declines and expiry.
- `src/storage/` wraps FeOxDB in a single-writer coordinator with an exclusive
  process lock and a durable redo journal.
- `src/config.rs` validates the complete YAML document before any network or
  storage I/O.
- `src/admin.rs` and `src/main.rs` implement the offline reservation CLI.

`preflight` and `smoke-test` create an io_uring instance, verify
`RECVMSG`, `SENDMSG`, `TIMEOUT`, `ASYNC_CANCEL` and `IP_PKTINFO`, and perform a
loopback exchange. `serve` runs the same probe before opening the store and
binding port 67, and fails startup if any capability is unavailable. Required
capabilities are never replaced by another backend.

## Storage model

MAC addresses are normalized to 12 lowercase hexadecimal characters. The
record keys are exactly:

| Record | Key |
| --- | --- |
| Reservation | `dhxpro:reservation:v1:<machex>` |
| Lease | `dhxpro:lease:v1:<machex>` |
| IP owner index | `dhxpro:ip-owner:v1:<ipv4>` |
| Subnet cursor | `dhxpro:subnet:v1:<subnet-id>` |
| Journal intent | `dhxpro:txn:v1:<sequence>` |

Subnet IDs and DHCP client identifiers are fields inside the record value,
never part of a reservation or lease key suffix. A single MAC can hold
independent `entries_by_subnet` entries for multiple subnet scopes while
retaining exactly one reservation key and one lease key.

Multi-key changes use this protocol:

1. Write and flush a versioned intent containing every put/delete.
2. Apply the operations idempotently.
3. Flush the applied state.
4. Retire the intent and flush the retirement.

Any intent left by a crash is replayed at startup before traffic is served.
After replay, the server checks ownership, lease and reservation consistency
and refuses to serve if problems remain. A DHCPACK is emitted only after lease
and IP-owner state have been durably flushed. Storage failures stop new
allocations until replay succeeds.

FeOxDB has no cross-process lock, so dhxpro takes a non-blocking exclusive
`flock` on `<store>.lock`. The server and reservation commands cannot run
against the same store simultaneously.

## Build

Host debug and tests:

```sh
cargo build
cargo test
cargo clippy --all-targets
```

Static ARMv7-A musl release:

```sh
scripts/bootstrap-arm-musl.sh   # once, downloads the musl.cc toolchain
scripts/check-io-uring-abi.sh   # verifies the ARM io_uring ABI layout
scripts/arm-release.sh
scripts/check-static-arm.sh
```

The resulting binary is
`target/armv7-unknown-linux-musleabihf/release/dhxpro`. The check script
requires an `ELF32` ARM file with no `INTERP` and no `NEEDED` entries.

`io-uring` 0.7.15 only ships prebuilt ABI definitions for 64-bit architectures.
The ARM build therefore sets `--cfg io_uring_skip_arch_check`. This is used
only after `scripts/check-io-uring-abi.sh` confirms that the core io_uring
kernel structs have identical sizes, alignments and field offsets on ARMv7.
Do not remove that check when updating the io-uring crate.

FeOxDB is pinned to `=0.6.0` with default features disabled and the
`io_uring`, `persistent` and `system-alloc` features enabled. jemalloc is not
part of this build.

## Target compatibility

The current static ARM release is **1,080,128 bytes** stripped. It is
`ELF32` ARM EABI5, statically linked, with no interpreter or `NEEDED` entries.
ARM test binaries also cross-compile; run them with the toolchain on `PATH`
(the release script adds it automatically):

```sh
export PATH="$HOME/opt/armv7l-linux-musleabihf-cross/bin:$PATH"
cargo test --no-run --target armv7-unknown-linux-musleabihf
```

Target requirements and assumptions:

- ARMv7-A, little-endian, EABI5 hard-float, static musl runtime.
- Linux kernel with `CONFIG_IO_URING=y` and the `RECVMSG`, `SENDMSG`, `TIMEOUT`
  and `ASYNC_CANCEL` operations used by the event loop.
- `IP_PKTINFO` ancillary data on the DHCP receive path.
- A writable persistent filesystem for `storage.path`; the store file is
  preallocated to `storage.file_size_mib` and must fit on that filesystem.
- No competing DHCP server on configured direct interfaces.

The target firmware/kernel version, actual power-loss durability, runtime RSS
and reboot behavior still need to be measured on Luckfox hardware. Those items
remain open in `plans/project.md`.

## Configuration

See `config/dhxpro.example.yaml`. The schema defines storage sizing,
authoritative mode, one or more subnets and optional relay mappings.

Each subnet has:

- a stable `id` (stored in record values and subnet metadata keys),
- an optional `interface` (omit for relay-only subnets),
- a CIDR, server identifier, inclusive dynamic range and exclusions,
- router, DNS and domain options,
- lease, offer-hold and decline-hold timings,
- `incremental` or `random` allocation.

Each relay mapping binds one `giaddr` to a relay-only subnet. Direct scopes
must not overlap; relay mappings must be usable host addresses inside their
target CIDR. A relay gateway is automatically excluded from the dynamic
pool and from fixed reservations. Relayed requests are accepted through their
configured `giaddr` mapping even when they arrive on an interface that has no
direct DHCP subnet; only non-relayed traffic is restricted to configured
direct interfaces. Duplicate subnet IDs, server identifiers, overlapping
CIDRs, ambiguous interface/scope mappings and invalid options are rejected
before startup.

Validate without touching the network or store:

```sh
dhxpro --config /etc/dhxpro.yaml config-check
```

`preflight` additionally probes io_uring, opens and replays the store, checks
storage capabilities and state integrity, verifies each direct interface and
confirms each server identifier is assigned to its interface. It exits
non-zero when not ready. Run it while the server is stopped because it takes
the exclusive store lock.

`serve` runs the same readiness checks itself before opening the store for
service or binding port 67: configuration, io_uring loopback exchange,
exclusive store access/capabilities, state integrity, direct interfaces and
server identifiers. It then repeats the post-replay integrity check; cursor
initialization or reset only happens after that check passes. A failure is
fatal.

`smoke-test` performs the persistent put/get/flush/reopen check and the
io_uring loopback exchange. It also takes the exclusive store lock, so run it
while the server is stopped. It is the recommended post-deployment test:

```sh
dhxpro --config /etc/dhxpro.yaml preflight
dhxpro --config /etc/dhxpro.yaml smoke-test
```

## Running

```sh
sudo dhxpro --config /etc/dhxpro.yaml serve
```

Port 67 requires root or `CAP_NET_BIND_SERVICE`. The server logs diagnostics
to stderr and exits non-zero on startup failure, including validation,
readiness, storage-lock, integrity, io_uring probe and bind failures.
SIGINT/SIGTERM trigger a bounded cancellation and drain of pending ring
operations.

### Luckfox / Buildroot deployment

1. Install the static binary at `/usr/sbin/dhxpro`.
2. Install `config/dhxpro.example.yaml` as `/etc/dhxpro.yaml` and edit it.
3. Create the storage directory with permissions for the service account,
   for example `mkdir -p /var/lib/dhxpro && chmod 750 /var/lib/dhxpro`.
4. Install `packaging/init.d/S99dhxpro` as `/etc/init.d/S99dhxpro` and make it
   executable. It logs to `/var/log/dhxpro.log`, uses `/var/run/dhxpro.pid`
   and runs an explicit `preflight` before starting `serve` (which also runs
   its own readiness checks).
5. Ensure the kernel exposes `io_uring` (`CONFIG_IO_URING=y`) and that no
   other DHCP server is active on the configured interfaces.
6. Run `dhxpro --config /etc/dhxpro.yaml preflight` and `smoke-test`, then
   start the service.

## Reservations

The reservation CLI is offline and takes the exclusive store lock. Stop the
server first.

```sh
dhxpro --config /etc/dhxpro.yaml reservation list
dhxpro --config /etc/dhxpro.yaml reservation add \
    --mac aa:bb:cc:dd:ee:ff --subnet lan --ip 192.168.1.50 --hostname printer
dhxpro --config /etc/dhxpro.yaml reservation update \
    --mac aabbccddeeff --subnet lan --ip 192.168.1.51
dhxpro --config /etc/dhxpro.yaml reservation disable \
    --mac aabbccddeeff --subnet lan
dhxpro --config /etc/dhxpro.yaml reservation enable \
    --mac aabbccddeeff --subnet lan
dhxpro --config /etc/dhxpro.yaml reservation remove \
    --mac aabbccddeeff --subnet lan
```

MAC input accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`,
`aabb.ccdd.eeff` or `aabbccddeeff`. Addresses must be usable hosts inside the
subnet CIDR and must not be the server identifier, a relay gateway, an
exclusion, another reservation or a live dynamic lease. Disabled reservations
remain stored but do not claim their address and are never allocated.

## Recovery and backup

- On startup, incomplete journal intents are replayed before DHCP is served.
- Expired offers, leases and declines are scanned every 10 seconds. Cleanup
  checks the lease generation before deleting an owner entry. If the address
  still has an enabled fixed reservation, cleanup restores that reservation as
  the permanent owner instead of deleting it.
- Storage health is checked on every mutation. A failure stops new offers and
  ACKs until replay recovery succeeds. A failed startup replay or an
  inconsistent post-replay state is fatal rather than a warning.
- Stop the service before copying the FeOxDB file and its `.lock`/journal
  state. A backup taken while the service is running is not guaranteed
  consistent. Restore the entire storage directory, not individual keys.
- The store file is preallocated to `file_size_mib`; size it for the expected
  reservation/lease count before deployment.

## Test status

Host validation currently covers 132 unit tests: raw DHCP wire validation,
the in-tree DHCP codec, DHCP state machine, relay routing, allocation,
reservations, quarantine restoration, journal crash boundaries, replay,
storage locking, configuration validation, io_uring loopback/cancellation and
preflight.
`cargo clippy --all-targets -- -D warnings` is clean.

The `validator/` package adds a pnpm-driven DHCPv4 end-to-end suite that boots
the real release binary on an isolated veth/network namespace and exchanges
packets on UDP ports 67 and 68. It covers direct and relayed DORA, reservations,
authoritative NAKs, RELEASE, DECLINE quarantine, INFORM, renewal, option 82 and
restart persistence. No npm runtime dependencies are required.

```sh
cd validator
pnpm install
pnpm test
```

The runner builds `target/release/dhxpro` first and enters its own network
namespace. It works without host root when unprivileged user namespaces are
enabled; otherwise run it as root. See `validator/README.md` for environment
overrides and current limitations.

The ARM cross-build and ABI check pass locally and the ELF is a static
`ELF32` ARM executable with no dynamic section. Running on the actual Luckfox
kernel/filesystem, power-loss durability and measured target RSS are still
required before claiming production readiness. See `plans/project.md` for the
remaining target milestones.
