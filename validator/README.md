# dhxpro DHCPv4 end-to-end validator

This package boots the real `dhxpro ... serve` binary on a private Linux
network namespace and drives it with an independent DHCPv4 client implemented
in Node.js. It does not import or call the Rust DHCP codec, and it does not
mock the network or storage layers.

The suite uses a veth pair:

- the test process has the client/relay side (`10.55.0.2`, relay
  `192.168.50.1`);
- `dhxpro` runs in a child network namespace on the server side
  (`10.55.0.1`);
- the direct subnet is `10.55.0.0/24` with a `.100`-`.110` pool;
- the relay-only subnet is `192.168.50.0/24` with a `.100`-`.110` pool and a
  giaddr mapping of `192.168.50.1 -> branch`.

DHCP traffic uses the real UDP ports 67 and 68. The ports, routes and veth pair
exist only inside the test network namespace, not in the host network.

## Requirements

- Linux with network namespaces.
- Node.js 20 or newer and pnpm.
- `ip`, `nsenter`, `unshare`, `timeout` and a POSIX shell.
- Rust/Cargo if the release binary needs to be built.
- No npm runtime dependencies.

The runner works without host root when unprivileged user namespaces are
available. If they are disabled, run it as root. The runner rejects an
environment where it cannot create the isolated namespace.

## Usage

From this directory:

```sh
pnpm install
pnpm test
```

By default the runner builds `target/release/dhxpro` before entering the
network namespace, then re-executes itself under `unshare`. To reuse an
existing binary:

```sh
DHXPRO_SKIP_BUILD=1 pnpm test
```

To select another binary:

```sh
DHXPRO_BIN=/path/to/dhxpro DHXPRO_SKIP_BUILD=1 pnpm test
```

On failure the runner prints the latest server log and keeps the temporary
configuration, FeOxDB store and logs. Set `DHXPRO_E2E_KEEP=1` to keep them
after a successful run as well. The printed path contains `config.yaml`,
`server-N.log`, `server.pid` and `store/state.feox`.

## Coverage

The suite verifies:

- malformed DHCP input is dropped and the server remains available;
- DISCOVER/OFFER/REQUEST/ACK with server identifier, subnet mask, routers,
  DNS, domain name, broadcast address, lease, T1 and T2 options;
- duplicate DISCOVER idempotency;
- authoritative NAK for an unknown INIT-REBOOT, and RELEASE removing the
  binding;
- a fixed reservation seeded through the offline `reservation add` CLI;
- DECLINE quarantine: a later DISCOVER skips the declined address;
- options trimming against option 57 maximum message size;
- INFORM configuration-only ACK without lease timers;
- unicast renewal through `ciaddr`;
- relayed DISCOVER/REQUEST via `giaddr`, branch-subnet selection and option 82
  echoing;
- the same MAC holding distinct bindings in the direct and relayed scopes;
- both `incremental` and `random` allocation strategies;
- lease and reservation persistence across a full server stop/start.

## Limitations

- The suite does not yet cover VLAN interfaces, pool exhaustion, broadcast
  relays, packet capture, forced journal interruption, or FeOxDB key-layout
  inspection.
- It validates host behavior only. Luckfox hardware, target kernel io_uring
  support, power-loss durability, target RSS and target runtime behavior still
  require hardware or qemu-arm.

## Layout

- `lib/dhcp4.js` — independent DHCPv4 encoder/decoder.
- `lib/harness.js` — config generation, reservation seeding, server process
  lifecycle, UDP peers and namespace settings.
- `test/dhcp4.e2e.test.js` — protocol scenarios.
- `scripts/run-e2e.sh` — build, network-namespace setup and cleanup.
