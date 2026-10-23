# dhxpro

- Identifier: P-RAN-10
- Status: In Progress

## Summary

Static ARM musl DHCPv4 server using io_uring networking and FeOxDB, with prefixed MAC-keyed reservations/leases, multi-subnet ranges, incremental/random allocation, and YAML configuration.

## Project description

### Goal

Implement dhxpro, a Rust DHCPv4 server for Luckfox Pico Pro / Max embedded Linux. Deliver a statically linked ARM musl executable, multi-subnet inclusive address ranges, per-subnet incremental/random allocation, and FeOxDB persistent key-value storage.

### Required I/O architecture

Use Linux `io_uring` as the only DHCP network I/O backend and FeOxDB's supported `io_uring`-enabled persistent storage path. Do not implement a `std::net::UdpSocket`, blocking `recvfrom`/`sendto` loop, epoll networking backend, or runtime fallback. If required `io_uring` operations are unavailable, fail startup with a clear diagnostic.

Use a completion-driven DHCP event loop and only kernel features verified on the target. Do not assume newer multishot or buffer-ring features.

### Storage design — FeOxDB only, prefixed MAC keys

Use FeOxDB as the sole storage engine.

Normalize MAC addresses to **12 lowercase hexadecimal characters without separators** (for example, `aabbccddeeff`). MAC address is the primary key identity for reservation and lease records. Use these versioned key formats exactly:

- Reservation: `dhxpro:reservation:v1:<machex>`
- Lease: `dhxpro:lease:v1:<machex>`
- IP ownership/conflict index: `dhxpro:ip-owner:v1:<ipv4>` -> owning subnet, MAC and state/role.
- Subnet allocator metadata/cursor: `dhxpro:subnet:v1:<subnet-id>`.
- Recovery journal intents: `dhxpro:txn:v1:<sequence>`.

Do **not** add subnet ID or DHCP client identifier to the reservation/lease key suffix. Each key's value is a versioned record with an `entries_by_subnet` map; each entry contains `subnet_id`, assigned IP, DHCP client identifier where relevant, state and timestamps. This permits the same MAC to have independent reservation/lease entries in multiple configured subnet scopes while keeping exactly one reservation key and one lease key per MAC. Keep DHCP client identifier as a validation attribute, not the primary storage key.

FeOxDB provides atomic single-key operations but not multi-record transactions. Since one lease update may need to modify a MAC-keyed lease, an IP-owner index, and a subnet cursor together, implement a serialized, idempotent redo journal:

1. Write a versioned intent describing the complete logical mutation and flush it durably.
2. Apply its puts/deletes to the prefixed MAC record(s), IP-owner index and subnet metadata; flush.
3. Retire the intent only after the applied state is durably flushed; flush that change.
4. On startup, replay any remaining intents idempotently before serving DHCP.

Only one dhxpro process may own the store. Verify the pinned FeOxDB version's exact-key access, prefix iteration, CAS/update and flush APIs; if the required semantics cannot be implemented reliably, block release rather than weakening lease safety.

Call and verify `flush()` at durability-critical boundaries. Do not send `DHCPACK` until active lease and IP-owner state have been updated consistently and their flush succeeds. If storage update or flush fails, do not ACK and stop creating new allocations until storage health is restored. Revalidate every DHCPREQUEST against durable current state; a pending offer alone must never authorize an ACK after restart.

FeOxDB documents write-behind buffering and an explicit blocking `flush()`. Verify persistence and crash/power-loss behavior on the target filesystem before production release.

### Functional scope

- Support multiple directly connected IPv4 subnets; resolve scope unambiguously from interface and destination metadata.
- Support configured relay-agent subnet selection using `giaddr` and reply to the correct relay.
- Configure one contiguous inclusive dynamic range per subnet, exclusions, server identifier, router/DNS/domain options, lease duration and offer/decline timeouts.
- Support per-subnet `incremental` allocation with a persistent cursor and wraparound, and `random` allocation with bounded random attempts plus full-range fallback.
- Honor MAC-based reservations, preserve valid existing leases, track pending offers and decline quarantine, and prevent duplicate IP assignments.
- Implement DHCPDISCOVER/OFFER, DHCPREQUEST/ACK/NAK, DHCPDECLINE, DHCPRELEASE and DHCPINFORM.
- Build a static ARMv7-A musl executable using FeOxDB's verified io_uring/persistence features and the system allocator for the initial embedded build.

### Architecture

Separate YAML validation, io_uring socket/event handling, DHCP parsing/state machine, allocation, and FeOxDB storage coordination. Use a single state coordinator/single writer for all mutations. Reservation and lease records are canonically keyed by prefixed MAC keys; IP-owner keys provide uniqueness checks; versioned intent records make multi-key changes recoverable. Commit and durably flush lease state before sending DHCPACK.

### Reliability and security requirements

- Verify io_uring networking and FeOxDB persistent io_uring storage on the exact Luckfox firmware/kernel; fail closed if unavailable.
- Reject invalid or ambiguous subnet/interface mappings before accepting traffic.
- Validate CIDRs, ranges, exclusions, server identifiers, reservation collisions and allocation strategies.
- Handle malformed packets, exhaustion, storage errors, restart recovery, invalid system time and interrupted multi-key mutations without panic or unsafe reuse.
- Test crashes before/after intent flush, between mutation writes, after state flush and before intent retirement; verify startup replay restores consistency.
- Restrict service to configured interfaces and use io_uring for DHCP network receive/send. FeOxDB manages persistent storage through its supported implementation.
- Verify static linkage, ABI/kernel compatibility, storage durability and real packet behavior on target hardware.

### Out of scope for the first release

DHCPv6, a web UI, distributed storage, multiple disjoint ranges per subnet, automatic management of server interfaces and unverified newer io_uring features.

### Definition of done

dhxpro builds as a static ARM musl executable, runs on the Luckfox firmware, uses io_uring exclusively for DHCP network I/O and FeOxDB for persistent storage, uses prefixed MAC-keyed reservation/lease records, prevents duplicate IP allocations, durably recovers multi-key updates, and passes protocol, fault-injection, concurrency and target-hardware tests.

**Assisted By:** OpenAI GPT-6

---

## Milestones

Host verification snapshot (2026-10-21):

- `cargo test`: 132 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: clean.
- DHCPv4 codec is implemented in-tree with no DHCP-crate dependency.
- `scripts/check-io-uring-abi.sh`: ARMv7 io_uring ABI layout check passed.
- `scripts/arm-release.sh` + `scripts/check-static-arm.sh`: static `ELF32`
  ARM binary, 1,080,128 bytes stripped, no `INTERP` or `NEEDED` entries.
- ARM `cargo test --no-run --target armv7-unknown-linux-musleabihf`: passed.
- Host CLI lifecycle (`config-check`, `preflight`, `smoke-test`, reservation add/list/update/disable/enable/remove): passed.
- `validator/` pnpm DHCPv4 end-to-end suite in an isolated network namespace: 11/11 passed (direct/relayed DORA, both allocation strategies, reservations, NAK, RELEASE, DECLINE quarantine, INFORM, renewal, option 82, per-subnet state for one MAC, restart persistence).
- Target hardware, power-loss durability and target RSS have not been run because this host lacks target hardware.

### M1 — Target Build & Platform Proof

Progress: 60%

#### Outcome

Prove the static ARMv7-A musl build, io_uring networking and FeOxDB persistent storage on the actual Luckfox Pico Pro / Max firmware.

#### Exit criteria

- Cargo pins FeOxDB and documents supported `io_uring`, `persistent`, and `system-alloc` features; exclude jemalloc for the initial target build.
- ARM musl toolchain builds all native/transitive components consistently; ELF has no dynamic interpreter/shared-library dependencies.
- Target smoke test verifies FeOxDB open, prefixed key put/get, flush, reopen, and crash/recovery replay; UDP receive/send uses dhxpro's io_uring path.
- Verify FeOxDB supports ARMv7-A musl and the target storage io_uring path.
- Verify prefix iteration, CAS/update, and durable flush APIs required by the MAC-keyed data model and redo journal.
- Ring or storage incompatibility is a release blocker, not a reason to weaken the required architecture.
- Firmware kernel/config, ABI assumptions, storage path and init method are documented.

**Assisted By:** OpenAI GPT-6

### M2 — FeOxDB State Model & Configuration

Progress: 100%

#### Outcome

Define validated multi-subnet YAML configuration and the prefixed MAC-keyed FeOxDB state model.

#### Exit criteria

- YAML defines stable subnet IDs, interface, CIDR, inclusive range, exclusions, DHCP options, lease timings and allocation strategy.
- Reservation keys use `dhxpro:reservation:v1:<machex>`; lease keys use `dhxpro:lease:v1:<machex>`. MAC is normalized to 12 lowercase hex characters without separators, and the key suffix contains only that MAC.
- Each MAC key stores a versioned value with an `entries_by_subnet` map; each entry holds subnet ID, assigned IP, client identifier where relevant, state, hostname and timestamps.
- This permits a MAC to have independent reservation/lease entries in multiple configured scopes while maintaining exactly one reservation key and one lease key per MAC.
- IP-owner index uses `dhxpro:ip-owner:v1:<ipv4>`; allocator metadata uses `dhxpro:subnet:v1:<subnet-id>`; redo intents use `dhxpro:txn:v1:<sequence>`.
- A single-writer coordinator and durable, idempotent redo journal protect multi-key changes without assuming transaction support in FeOxDB.
- Serialization/versioning, prefix iteration, conflict checks, startup replay and flush-error recovery are documented and tested.

**Assisted By:** OpenAI GPT-6

### M3 — Subnet Selection & Address Allocation

Progress: 100%

#### Outcome

Implement subnet-aware allocation using io_uring exclusively for DHCP network receive/send and prefixed FeOxDB MAC-keyed reservation/lease records.

#### Exit criteria

- Direct requests are scoped using interface and destination metadata; configured relays use giaddr mapping and relay replies use io_uring.
- Reservation and lease records use exactly `dhxpro:reservation:v1:<machex>` and `dhxpro:lease:v1:<machex>`; subnet ID is stored in the value, not the key.
- The IP-owner index prevents an IPv4 address from being allocated or reserved to multiple MACs.
- Incremental cursor is persisted in subnet metadata; random mode has bounded attempts plus full-range fallback.
- All multi-key allocations use the durable intent journal, single-writer coordinator and idempotent replay; concurrent tests prove no duplicate assignments.
- No IP-primary lease records, standard-socket networking or blocking network fallback exists.

**Assisted By:** OpenAI GPT-6

### M4 — DHCPv4 Protocol & FeOxDB Durability

Progress: 100%

#### Outcome

Deliver the DHCPv4 state machine and ensure FeOxDB-backed lease changes are durably recoverable before client acknowledgement.

#### Exit criteria

- Implement DISCOVER/OFFER, selecting DHCPREQUEST, INIT-REBOOT, renewal/rebinding, DECLINE, RELEASE and INFORM.
- All DHCP packet receive/send and response lifecycle handling uses io_uring only.
- Use `dhxpro:reservation:v1:<machex>` and `dhxpro:lease:v1:<machex>`; subnet, assigned IP and client identity are fields in the value.
- Active lease and IP-owner index updates use the durable redo journal. Flush intent, apply changes, flush state, then retire the intent; replay remaining intents at startup.
- DHCPACK is submitted only after active lease state and IP ownership are durably consistent. On failed flush or unresolved state, do not ACK or allocate new leases.
- Revalidate DHCPREQUEST against durable state; a lost pending offer alone never authorizes an ACK.
- Test storage interruption at every journal boundary, renewal, release, decline, clock-invalid recovery, shutdown and ring errors.

**Assisted By:** OpenAI GPT-6

### M5 — Integration, Hardening & Luckfox Release

Progress: 40%

#### Outcome

Validate io_uring-only networking and FeOxDB prefixed-MAC state on realistic Linux topologies and on Luckfox hardware.

#### Exit criteria

- Namespace/veth tests exercise multiple subnets using the io_uring network backend.
- Target test validates FeOxDB persistent io_uring storage, prefix iteration, flush, reopen and startup recovery on the exact firmware/kernel/filesystem.
- Tests cover MAC-keyed reservations/leases, IP-owner uniqueness, journal replay, flush failure, crashes during multi-key updates and power-loss behavior where feasible.
- Both allocation modes, DHCP lifecycle, exhaustion, concurrency, restart recovery, relay handling and packet fields pass.
- Static ARM musl linkage, RAM use, executable/storage footprint, backup/recovery procedure and target compatibility are recorded.
- Init script, example YAML, reservation administration and troubleshooting docs are provided.

**Assisted By:** OpenAI GPT-6

---

## Issues

### RAN-168 — Bootstrap Rust crate and ARMv7-A musl cross-build

- Status: Done
- Priority: High

#### Goal

Create the Rust service skeleton and reproducible ARM musl cross-compilation toolchain for dhxpro, using io_uring for DHCP networking and FeOxDB for persistent key-value storage.

#### Tasks

- Set up modules for configuration, io_uring networking/event loop, DHCP state machine, subnet allocator, and FeOxDB state coordination.
- Pin dependencies in Cargo.lock, including FeOxDB, the io_uring network crate, YAML parser and serialization format; the DHCP codec is in-tree with no DHCP-crate dependency.
- Configure `armv7-unknown-linux-musleabihf` and the required ARM musl linker/toolchain for all native/transitive components.
- Configure FeOxDB with default features disabled and explicitly enable `io_uring`, `persistent`, and `system-alloc` as supported by the pinned version; exclude jemalloc for the first embedded build.
- Add size-oriented release settings and repeatable build documentation.
- Use FeOxDB as the sole persistence engine and keep DHCP packet I/O on io_uring.

#### Acceptance criteria

- Host debug/test build succeeds.
- Clean ARM release build is reproducible.
- ELF inspection confirms the expected 32-bit ARM ABI and no dynamic interpreter/shared-library requirements.
- FeOxDB compiles with the target feature set; any ARMv7/musl incompatibility is identified as a blocker instead of silently replacing the storage backend.
- Architecture docs state that io_uring is mandatory for DHCP networking and FeOxDB persistence, with startup failing clearly when required capabilities are unavailable.

**Assisted By:** OpenAI GPT-6

### RAN-169 — Verify FeOxDB io_uring build, ARMv7 compatibility, and persistence

- Status: In Progress
- Verification: ARM static build and host smoke tests pass; actual Luckfox firmware/kernel persistence and power-loss behavior remain to be run on target hardware.
- Priority: High

#### Goal

Prove the pinned FeOxDB version and its persistent io_uring path compile for static ARM musl and work on the Luckfox Pico Pro / Max filesystem.

#### Tasks

- Use FeOxDB with the pinned version and required `io_uring`, `persistent`, and `system-alloc` features (confirm exact feature names/API before implementation).
- Verify cross-compilation to `armv7-unknown-linux-musleabihf` and inspect all transitive/native dependencies.
- Add a target smoke-test command that opens a store, writes and reads a prefixed key, calls flush, closes/reopens, and verifies the value.
- Verify prefix iteration, atomic CAS/update behavior, and flush errors needed by MAC-keyed records and recovery-journal replay.
- Test unexpected process termination and reboot/reopen recovery, documenting what has and has not been proven about power-loss durability.
- Record binary size and inspect runtime dependencies.
- Verify the configured persistent directory exists and is writable on the actual firmware.

#### Acceptance criteria

- Static ARM binary includes FeOxDB and has no unexpected dynamic dependencies.
- Store open/write/read/flush/reopen succeeds on actual target firmware.
- The prefixed-key APIs and CAS/update semantics used by dhxpro work with the pinned FeOxDB release.
- Storage-path, flush, crash recovery and backup limitations are documented; failure is reported clearly.
- Incompatibility with ARMv7/musl or the target kernel is a release blocker; keep the selected FeOxDB storage architecture fixed.

**Assisted By:** OpenAI GPT-6

### RAN-170 — Implement validated YAML configuration for multiple subnets

- Status: Done
- Priority: High

#### Goal

Load and validate all server and per-subnet configuration before initializing network I/O or mutating persistent state.

#### Tasks

- Define typed YAML models with schema version, FeOxDB storage path, authoritative mode, stable subnet ID, interface, CIDR, server identifier, inclusive address range, excluded addresses, routers, DNS servers, domain name, lease time, offer hold, decline hold, and allocation strategy.
- Support exactly `incremental` and `random` strategy values.
- Validate CIDR/range containment, range order, network/broadcast/server exclusions, overlap across subnets/ranges, unique IDs and server identifiers, interface/scope ambiguity, and option/timing values.
- Provide an example YAML and a `config-check` CLI command.
- Keep subnet IDs stable because they are persisted in values and subnet metadata keys. Reservation/lease key suffixes are MAC only.
- Keep io_uring availability as a runtime/platform preflight rather than a per-subnet configuration option.

#### Acceptance criteria

- Valid multi-subnet fixture parses as expected.
- Invalid/overlapping/ambiguous configurations fail with field-specific errors before DHCP traffic is accepted.
- Each subnet's values are available as validated immutable runtime configuration.
- Unit tests cover boundaries, exclusions, missing fields, unknown strategies, and duplicate subnets.
- Configuration examples use the documented FeOxDB storage path and key-value record model.

**Assisted By:** OpenAI GPT-6

### RAN-171 — Implement FeOxDB prefixed MAC-keyed reservation and lease storage

- Status: Done
- Priority: High

#### Goal

Implement the durable FeOxDB key model for MAC-address-keyed reservations and leases using versioned key-value records and a recovery journal.

#### Canonical key format

Normalize MAC addresses to 12 lowercase hexadecimal characters without separators (e.g. `aabbccddeeff`). Use these versioned keys exactly:

- Reservation: `dhxpro:reservation:v1:<machex>`
- Lease: `dhxpro:lease:v1:<machex>`
- IP ownership/conflict index: `dhxpro:ip-owner:v1:<ipv4>` → owning subnet, MAC and state/role
- Subnet cursor/allocator metadata: `dhxpro:subnet:v1:<subnet-id>`
- Redo journal intent: `dhxpro:txn:v1:<sequence>`

The reservation and lease keys' suffix is the MAC address only. Do not append subnet ID or DHCP client identifier to those keys. Each MAC key stores a versioned value with an `entries_by_subnet` map; each entry carries `subnet_id`, assigned IP, DHCP client identifier (option 61), lease/reservation state, hostname and timestamps. This lets one MAC have independent reservation/lease entries across multiple subnet scopes while retaining exactly one prefixed reservation key and one prefixed lease key per MAC.

#### Tasks

- Define versioned typed records for reservation, lease, IP owner, subnet metadata and mutation journal.
- Pick and document a deterministic compact serialization format; reject malformed/unknown record versions safely.
- Verify the pinned FeOxDB API for exact-key get/put, prefix iteration, CAS/update and flush.
- Implement a single-writer state coordinator.
- Implement an idempotent redo journal for mutations that touch more than one key: durably write and flush intent; apply puts/deletes; flush applied state; then retire and flush the intent.
- Replay incomplete intents on startup before accepting DHCP traffic.
- Define safe behavior for corrupted values, flush failures, version migration and exclusive store ownership.

#### Acceptance criteria

- Reservation and lease key names exactly follow the specified prefix + normalized-MAC format, with no subnet suffix.
- An IP can have at most one owner, even though canonical reservation/lease records are MAC-keyed.
- Subnet scope and assigned IP are fields in each `entries_by_subnet` entry, not part of the MAC record keys; tests prove that one MAC can be represented in multiple scopes.
- Multi-key changes recover idempotently after interruption at every journal boundary.
- No correctness assumption relies on an unsupported multi-key FeOxDB transaction.
- FeOxDB is the sole persistence engine; the implementation uses versioned key-value records and the documented recovery journal.

**Assisted By:** OpenAI GPT-6

### RAN-172 — Add MAC reservation management and validation commands

- Status: Done
- Priority: Medium

#### Goal

Provide minimal CLI commands to inspect and administer fixed MAC-to-IP reservations stored in FeOxDB.

#### Tasks

- Add commands to list, add, disable/enable, update and remove reservations.
- Normalize MAC inputs to 12 lowercase hexadecimal characters without separators.
- Store each MAC's reservation record at `dhxpro:reservation:v1:<machex>`; keep a versioned `entries_by_subnet` map in the value with subnet ID, IP, enabled state, optional hostname and timestamps for each scope.
- Require a subnet ID when the scope cannot be inferred safely.
- Check `dhxpro:ip-owner:v1:<ipv4>` before reserving an address and update reservation/IP ownership through the durable intent journal.
- Validate the IP is within the selected subnet, not a network/broadcast/server/excluded address, and does not conflict with another reservation or dynamic lease.
- Ensure changes go through the single-writer state coordinator, or run offline while the server exclusively owns the store.

#### Acceptance criteria

- Duplicate MAC/IP assignments are rejected with useful errors.
- One MAC has one reservation key; its value can hold independent reservation entries for multiple subnets keyed by subnet ID.
- Disabled reservations remain stored but are never allocated.
- Success is reported only after intended state is applied and durably flushed.
- Successful reservation changes are visible to subsequent DHCP allocations after state is durably flushed.

**Assisted By:** OpenAI GPT-6

### RAN-173 — Implement interface-aware DHCP socket and direct subnet selection

- Status: Done
- Priority: High

#### Goal

Receive and transmit all direct-client DHCP traffic through io_uring, resolving each request to exactly one configured subnet. io_uring is the only network I/O backend.

#### Tasks

- Create and configure the UDP socket using the necessary Linux setup syscalls, bind port 67, and submit receive operations through io_uring.
- Use io_uring-supported `RECVMSG`/equivalent receive operations with ancillary data to obtain `IP_PKTINFO` or equivalent destination/interface metadata.
- Restrict traffic to configured interfaces and map ingress interface plus local destination address to a subnet.
- Submit responses through io_uring send operations, preserving required source address, outgoing interface, broadcast/unicast flags and destination port.
- Keep low-level Linux socket setup and ancillary-data handling isolated behind a small networking module; do not use `std::net::UdpSocket`, blocking `recvfrom`/`sendto`, or an alternate network backend for packet I/O.
- Implement explicit operation context/user_data tracking, completion handling, receive re-arming, error handling and clean cancellation/shutdown.
- Reject packets where the subnet cannot be selected uniquely rather than guessing based on requested IP or MAC.

#### Acceptance criteria

- Requests arriving on each configured interface map to the expected subnet.
- Ancillary metadata needed for subnet selection is available through the io_uring receive path on the target kernel.
- Responses leave through the correct interface with the intended source address and destination.
- Ambiguous/unconfigured interface traffic is safely ignored and logged.
- Socket tests and a target smoke test confirm the required io_uring opcodes, bind and packet-info behavior.
- Ring setup or required-operation failure terminates startup clearly; there is no standard-socket fallback.

**Assisted By:** OpenAI GPT-6

### RAN-174 — Add DHCP relay subnet mapping and relay reply routing

- Status: Done
- Priority: Medium

#### Goal

Support DHCPv4 relay-agent requests for explicitly configured remote subnet scopes while using io_uring for all DHCP packet receive/send operations.

#### Tasks

- Receive relay packets through the io_uring event loop and parse/validate non-zero `giaddr`.
- Select a subnet using a deterministic configured relay/CIDR mapping; do not infer a scope solely from the requested IP or client MAC.
- Ensure relay mappings cannot conflict with direct interface scopes or other mappings.
- Submit replies to the relay agent through io_uring send operations, preserving the selected subnet's server identifier and options.
- Safely reject unsupported, unknown, or ambiguous relay mappings and log why.
- Preserve ingress and destination metadata needed for correct response routing.

#### Acceptance criteria

- Relay requests select only the configured matching subnet.
- Responses are sent through io_uring to the relay rather than broadcast directly onto the wrong network.
- Tests cover valid, unknown, ambiguous, and mismatched giaddr cases.
- No standard-socket receive/send path is introduced for relay traffic.

**Assisted By:** OpenAI GPT-6

### RAN-175 — Implement shared IP eligibility and reservation conflict checks

- Status: Done
- Priority: High

#### Goal

Implement one common address-eligibility policy for incremental/random allocation and all DHCP lease transitions, using MAC-keyed FeOxDB records.

#### Tasks

- Resolve an enabled reservation from `dhxpro:reservation:v1:<machex>`.
- Resolve/reuse a client's lease from `dhxpro:lease:v1:<machex>` when protocol state permits.
- Resolve the selected subnet's entry inside each MAC-keyed record's `entries_by_subnet` map; do not assume the whole MAC record belongs to one subnet.
- Check `dhxpro:ip-owner:v1:<ipv4>` and exclude configured exclusions, network/broadcast/server addresses, reservations owned by another MAC, active leases, pending offers and addresses still in decline quarantine.
- Keep option 61 client identifier and other validation data in the lease value; MAC remains the canonical storage key.
- Serialize allocation mutations in a single state coordinator.
- For changes to a MAC lease, IP-owner key, or subnet cursor together, write a durable redo intent, apply all changes idempotently, flush, then retire the intent.
- Treat any storage/CAS/flush error as allocation failure; do not return an address whose ownership cannot be made consistent.

#### Acceptance criteria

- Both allocation strategies use identical eligibility logic.
- A reserved or active IP is never offered to another MAC.
- Concurrent allocation requests cannot create duplicate IP ownership.
- Fault-injection tests cover CAS conflicts, partial multi-key updates, flush failures and startup replay.
- Multi-key updates use the redo journal and recovery mechanism to preserve consistency.

**Assisted By:** OpenAI GPT-6

### RAN-176 — Implement incremental per-subnet allocator with persistent cursor

- Status: Done
- Priority: High

#### Goal

Allocate new addresses sequentially within each subnet's inclusive range and persist the cursor in FeOxDB.

#### Tasks

- Store each subnet's next candidate in `dhxpro:subnet:v1:<subnet-id>`.
- Scan from the cursor, skip IPs claimed in the IP-owner index, configured exclusions, invalid addresses, reservations and unexpired offers/leases.
- The selected lease record is `dhxpro:lease:v1:<machex>`; update the entry for the selected subnet within its `entries_by_subnet` map, storing subnet and assigned IP in that entry.
- Make the selected MAC-keyed lease record, IP-owner index and cursor update recoverable as one logical operation using the redo journal.
- Advance cursor only as part of that operation; safely recover if process termination occurs during mutation.
- Validate or reset stale cursor data through the journal when a configured range changes.
- Keep existing valid leases and reservations unchanged.

#### Acceptance criteria

- New allocations proceed incrementally and wrap correctly.
- Cursor and lease/IP ownership survive restart according to verified FeOxDB durability semantics.
- Interrupted operations replay without duplicate IP assignment or cursor corruption.
- Full ranges return a clean exhaustion result.
- Cursor state is stored in versioned FeOxDB metadata keys.

**Assisted By:** OpenAI GPT-6

### RAN-177 — Implement random per-subnet allocator with exhaustion fallback

- Status: Done
- Priority: High

#### Goal

Add randomized candidate selection for subnets configured with `allocation_strategy: random`, using FeOxDB MAC-keyed leases and IP-owner conflict checks.

#### Tasks

- Choose candidates uniformly within the configured inclusive range using a suitable random source.
- Attempt a bounded number of candidates and check `dhxpro:ip-owner:v1:<ipv4>`, the MAC-keyed reservation record and lease state.
- When random attempts fail, scan the full range to find any remaining free address.
- Store the lease at `dhxpro:lease:v1:<machex>`; update the selected subnet's entry in `entries_by_subnet`, including assigned IP, client identifier, state and expiry.
- Use the redo journal to persist the MAC-keyed lease, IP-owner index and any required subnet metadata consistently.
- Avoid overflow and handle one-address ranges; preserve valid existing leases and fixed reservations.
- Flush state at durability-critical points before confirming a lease.

#### Acceptance criteria

- No candidate falls outside the configured range.
- Exclusions, reservations, active/pending leases and declined addresses are respected.
- A nearly exhausted range can still find its remaining free address via fallback.
- Storage failures never result in a DHCPACK for a lease that is not durable.
- FeOxDB is the sole storage backend for randomized allocation state.

**Assisted By:** OpenAI GPT-6

### RAN-178 — Implement DHCPv4 packet parsing, option encoding, and validation

- Status: Done
- Verification: clean-room codec in `src/dhcp.rs`; no DHCP crate dependency, with round-trip, malformed-wire, relay-option and size-limit tests.
- Priority: High

#### Goal

Create safe, testable parsing and response-building primitives for DHCPv4 messages and options, independent of the io_uring transport mechanism.

#### Tasks

- Keep server policy out of the DHCP codec layer; the wire codec is implemented in-tree for the specific DHCPv4 features dhxpro serves.
- Validate packet minimum size, op/htype/hlen, magic cookie, option bounds, duplicate/conflicting critical options and message type.
- Encode message type, server identifier, subnet mask, router, DNS, lease time, T1/T2, broadcast address, and relevant client options.
- Respect client maximum-message-size where supported, handle option overload only if implemented safely, and ignore unsupported options.
- Preserve transaction ID, client hardware address and required flags/relay fields.
- Accept owned or borrowed packet bytes from an io_uring completion and produce response bytes/options for the networking layer to submit through io_uring; keep the protocol module free of socket syscalls.

#### Acceptance criteria

- Valid fixtures round-trip correctly.
- Truncated, malformed and oversized packets are dropped without panic.
- Option encoding is checked against packet fixtures or an independent DHCP client/parser.
- Protocol code is deterministic and independent of ring submission/completion mechanics.
- No network I/O is performed by this module.

**Assisted By:** OpenAI GPT-6

### RAN-179 — Implement DHCPDISCOVER and journaled DHCPOFFER allocation

- Status: Done
- Priority: High

#### Goal

Respond to DHCPDISCOVER with a valid offer while preventing two MACs from owning the same IP. All network receive/send operations use io_uring.

#### Tasks

- Process DISCOVER packets delivered by io_uring completions and select the subnet from ingress/relay context.
- Normalize client MAC and resolve records with the prefixed MAC-only keys:
  - `dhxpro:reservation:v1:<machex>`
  - `dhxpro:lease:v1:<machex>`
- Resolve the selected subnet's entry in `entries_by_subnet` before reusing a reservation or lease. Honor reservations and eligible existing leases before running the configured allocator.
- Create/update the selected subnet's entry in the MAC-keyed lease value with offered state, IP and offer deadline; coordinate IP ownership through `dhxpro:ip-owner:v1:<ipv4>`.
- Use the redo journal for multi-key mutations and flush according to the documented offer durability policy.
- Submit DHCPOFFER through io_uring only after offer state and ownership are consistent.
- Handle retransmitted DISCOVER packets idempotently and fail closed on storage errors or exhaustion.

#### Acceptance criteria

- Standard clients receive a valid offer for each configured scope.
- No offer conflicts with another MAC's reservation, active lease, pending offer or declined address.
- Retried discovery does not needlessly consume additional addresses.
- Storage/CAS/flush errors do not produce an offer for inconsistent ownership.
- Offers use the shared FeOxDB state coordinator and journal; network packets use io_uring only.

**Assisted By:** OpenAI GPT-6

### RAN-180 — Implement DHCPREQUEST state classification and durable ACK/NAK

- Status: Done
- Priority: High

#### Goal

Handle DHCPREQUEST for selecting, INIT-REBOOT, renewal and rebinding states, using MAC-keyed FeOxDB state and io_uring response transmission.

#### Tasks

- Distinguish request forms using server identifier, requested IP option, ciaddr, relay context, client MAC and current lease state.
- Ignore a selecting request naming another server; do not send an incorrect DHCPNAK.
- Resolve the current lease via `dhxpro:lease:v1:<machex>`, select the entry for the active subnet, and verify the requested IP matches the client's binding and reservation.
- Atomically-in-effect update the MAC-keyed lease and IP-owner index through a durably flushed intent journal; do not assume FeOxDB supports multi-key transactions.
- Submit DHCPACK through io_uring only after the active binding is consistent and durable.
- Submit DHCPNAK only where protocol state and configured authority permit.
- Handle send completion errors without pretending a response succeeded.

#### Acceptance criteria

- Selecting, INIT-REBOOT, renewal and rebinding paths have dedicated tests.
- The server never ACKs a lease whose update or required flush failed.
- Requests selecting another DHCP server are ignored.
- Invalid address requests are responded to or ignored according to their DHCP state.
- All replies use io_uring and durable FeOxDB lease state.

**Assisted By:** OpenAI GPT-6

### RAN-181 — Implement lease renewals, release, decline, INFORM, expiry and recovery

- Status: Done
- Priority: High

#### Goal

Complete the lease lifecycle and recover MAC-keyed FeOxDB state safely across restarts while keeping DHCP network traffic on io_uring.

#### Tasks

- Renew the selected subnet's lease entry in `dhxpro:lease:v1:<machex>`, preserving its IP when allowed; subnet ID is the entry's key inside `entries_by_subnet`.
- Release only a matching MAC/subnet/address binding and update the IP-owner index through the journal.
- Quarantine a declined address in the selected subnet's entry within the MAC-keyed lease value and IP-owner index until the configured hold expires.
- Respond to DHCPINFORM with subnet options without allocating an address.
- Drive receives, responses, timer expirations and operation lifecycle through the io_uring event/completion loop.
- Expire stale offers/leases and clear IP-owner entries only when they still belong to the same MAC and binding generation.
- Define recovery for invalid wall clock, clock rollback, FeOxDB/CAS/flush errors, and startup reconciliation after reservation/range changes.
- Replay pending redo intents before serving clients; cleanly cancel/drain ring operations at shutdown.

#### Acceptance criteria

- Lease transitions are idempotent and cannot mutate another MAC's binding.
- Offers and declined addresses become reusable only after policy deadlines and safe ownership-index cleanup.
- Active MAC-keyed lease state survives restart within the verified FeOxDB durability model.
- Invalid system time does not trigger blanket lease deletion or unsafe reuse.
- Release, decline, INFORM, expiry, interruption/replay, flush failure and ring-error paths have tests.
- Networking and persistent state use the specified io_uring/FeOxDB architecture.

**Assisted By:** OpenAI GPT-6

### RAN-182 — Add configuration, FeOxDB, allocator, and concurrency test coverage

- Status: Done
- Priority: High

#### Goal

Build deterministic tests around configuration, prefixed MAC-keyed FeOxDB state, allocation and recovery.

#### Tasks

- Add valid/invalid YAML fixtures and boundary/property tests for subnet CIDRs and address ranges.
- Test FeOxDB open/reopen, prefixed key formatting, record serialization versions, prefix scans, CAS conflicts, flush behavior and corruption handling.
- Test reservation keys `dhxpro:reservation:v1:<machex>`, lease keys `dhxpro:lease:v1:<machex>`, `entries_by_subnet` serialization for the same MAC across multiple subnets, IP-owner uniqueness, subnet cursor metadata and single-writer enforcement.
- Test both allocation strategies, wraparound, exclusions, reservations, exhaustion and decline quarantine.
- Inject interruptions before intent flush, between multi-key writes, after state flush and before intent retirement; verify idempotent startup replay.
- Test concurrency with multiple DHCP client requests routed through the serialized state coordinator.
- Unit-test io_uring completion dispatch, send failures, receive re-arming, cancellation and shutdown; verify required-op failure never triggers fallback.
- Inject storage errors and invalid clocks to prove failure-safe behavior.

#### Acceptance criteria

- Core domain tests run without privileged networking or physical hardware where possible; FeOxDB-specific io_uring tests run on supported Linux.
- No duplicate IP ownership appears under concurrent allocation.
- Incomplete journaled updates recover to a consistent state after restart.
- Critical failures return typed errors and do not panic.
- Tests and exact commands are documented.

**Assisted By:** OpenAI GPT-6

### RAN-183 — Add network-namespace DHCP integration and packet-capture tests

- Status: In Progress
- Verification: `validator/` runs the real release binary in an isolated user/network namespace with a veth pair and real UDP ports 67/68. `pnpm test` passes 11/11 scenarios covering direct and relayed DORA, incremental and random allocation, reservations, NAK, RELEASE, DECLINE quarantine, INFORM, renewal, option 82, separate per-subnet state for one MAC, and restart persistence. VLAN interfaces, pool exhaustion, capture files, key-layout inspection, forced journal interruption, denied io_uring behavior and target hardware remain open.
- Priority: High

#### Goal

Validate end-to-end DHCP exchanges and subnet behavior using io_uring-only networking and prefixed MAC-keyed FeOxDB state.

#### Tasks

- Build repeatable network-namespace/veth tests for at least two independent subnet scopes.
- Run server packet receive/send through io_uring only; no `std::net` or blocking socket fallback.
- Exercise discover/offer, selecting, renewal, release, decline, INFORM and exhaustion using a real DHCP client.
- Cover direct interface mapping, VLAN interfaces, broadcast/unicast behavior and relay giaddr mapping.
- Capture packets and validate message type, transaction ID, server identifier, ports, destination, assigned IP and options.
- Verify reservation/lease keys use exactly `dhxpro:reservation:v1:<machex>` and `dhxpro:lease:v1:<machex>`; confirm subnet ID is an `entries_by_subnet` entry key in the value, not part of the MAC-key suffix.
- Simulate state update/flush interruption and restart; verify journal recovery and IP-owner uniqueness.
- Test unsupported/denied io_uring behavior and confirm clean failure without an alternate backend.
- Ensure cleanup removes namespaces, interfaces, routes and temporary FeOxDB state files even after failures.

#### Acceptance criteria

- Both allocation strategies pass end-to-end tests.
- Each subnet gets only its configured range and options.
- No IP is assigned to two MAC addresses; one MAC can retain distinct, correct state entries in separate subnet scopes.
- Relay replies target the correct relay when enabled.
- Test host prerequisites are reported clearly and tests remain isolated from production networking.

**Assisted By:** OpenAI GPT-6

### RAN-184 — Harden target runtime and package Luckfox service, config, and documentation

- Status: In Progress
- Verification: Static ARM package, example config, init script, and docs are present; target reboot/RSS measurements remain outstanding.
- Priority: High

#### Goal

Deliver a repeatable installation and reliable io_uring-only networking plus FeOxDB storage runtime on Luckfox Pico Pro / Max.

#### Tasks

- Add a BusyBox/Buildroot-compatible init script or match the firmware's actual service manager.
- Package binary, sample YAML, storage directory/permissions, logs and reservation administration instructions.
- Confirm competing DHCP services are not active on configured interfaces.
- At startup, verify io_uring ring creation and the required network/storage functionality; fail clearly if unavailable.
- DHCP network I/O is exclusively implemented with io_uring; FeOxDB is the persistent state backend.
- Test reboot startup order, graceful shutdown, durable flush behavior, read-only/missing storage and corrupted state/journal recovery.
- Measure stripped binary size and runtime RSS on target; record CPU/ABI/kernel and io_uring capability assumptions.
- Document prefix key formats, MAC normalization, reservation administration, state backup/recovery, subnet/VLAN and relay setup, kernel prerequisites and troubleshooting.

#### Acceptance criteria

- Static ARM musl binary works on firmware with io_uring enabled and survives service restart.
- DHCP packet I/O uses io_uring exclusively; reservations and leases are stored under the documented prefixed MAC keys in FeOxDB.
- Startup rejects invalid config, unavailable io_uring, incompatible FeOxDB, and storage errors clearly.
- Reproducible deployment and recovery instructions are checked in.

**Assisted By:** OpenAI GPT-6

### RAN-185 — Probe target io_uring support and fail closed when unavailable

- Status: In Progress
- Verification: Host preflight and loopback io_uring smoke tests pass; target io_uring/FeOxDB capability and storage probe remain outstanding.
- Priority: High

#### Goal

Verify that the exact Luckfox Buildroot kernel permits required io_uring networking operations and that FeOxDB's persistent io_uring storage path works on the target.

#### Tasks

- Record target firmware/kernel version and inspect kernel configuration where exposed.
- Attempt ring creation at startup and verify UDP send/receive plus ancillary packet metadata required for interface-aware DHCP through io_uring.
- Cross-compile and run a FeOxDB storage probe for ARMv7 musl using the selected persistent/io_uring/system-allocator features.
- Verify prefixed key put/get, prefix iteration, CAS/update and durable flush/reopen behavior.
- Exercise interrupted writes/restart recovery and document the actual persistence limitations of the pinned FeOxDB version.
- Distinguish unsupported/disabled io_uring, permission restrictions, resource exhaustion, and storage failures in diagnostics.
- Fail startup clearly when required network or storage capability is unavailable; do not fall back to an alternate backend.

#### Acceptance criteria

- On the supported firmware, io_uring networking and FeOxDB persistent storage pass the documented smoke tests.
- Reservation/lease prefix API needs (get, put, iteration, CAS/update) and flush semantics are verified.
- Unsupported/blocked ring or storage support exits non-zero with a clear diagnostic.
- The selected io_uring and FeOxDB backends are the only runtime implementations.
- Tested kernel, firmware, features and recovery results are documented.

**Assisted By:** OpenAI GPT-6
