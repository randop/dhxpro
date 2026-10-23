#!/usr/bin/env bash
set -Eeuo pipefail

VALIDATOR_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd -- "$VALIDATOR_DIR/.." && pwd)
SELF="$VALIDATOR_DIR/scripts/run-e2e.sh"
DHXPRO_BIN=${DHXPRO_BIN:-"$REPO_ROOT/target/release/dhxpro"}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "dhxpro e2e: required command not found: $1" >&2
    exit 1
  fi
}

# Build before entering the isolated network namespace: the namespace has no
# route to the network and must not be needed to fetch or compile dependencies.
if [[ -z "${DHXPRO_E2E_IN_NETNS:-}" ]]; then
  require_command node
  require_command unshare
  require_command ip
  require_command nsenter

  node -e '
    const major = Number(process.versions.node.split(".")[0]);
    if (major < 20) {
      console.error(`dhxpro e2e: Node.js >= 20 is required, found ${process.version}`);
      process.exit(1);
    }
  '

  if [[ "${DHXPRO_SKIP_BUILD:-0}" != "1" ]]; then
    require_command cargo
    (cd "$REPO_ROOT" && cargo build --release --locked)
  elif [[ ! -x "$DHXPRO_BIN" ]]; then
    echo "dhxpro e2e: DHXPRO_SKIP_BUILD=1 but binary is missing: $DHXPRO_BIN" >&2
    exit 1
  fi

  if [[ ! -x "$DHXPRO_BIN" ]]; then
    echo "dhxpro e2e: release binary is not executable: $DHXPRO_BIN" >&2
    exit 1
  fi

  BASH_BIN=$(command -v bash)
  if [[ "$(id -u)" -eq 0 ]]; then
    exec env DHXPRO_E2E_IN_NETNS=1 DHXPRO_BIN="$DHXPRO_BIN" \
      unshare --net "$BASH_BIN" "$SELF" "$@"
  fi

  if ! unshare --user --map-root-user --net true >/dev/null 2>&1; then
    echo "dhxpro e2e: unprivileged user namespaces are unavailable; run this suite as root" >&2
    exit 1
  fi
  exec env DHXPRO_E2E_IN_NETNS=1 DHXPRO_BIN="$DHXPRO_BIN" \
    unshare --user --map-root-user --net "$BASH_BIN" "$SELF" "$@"
fi

require_command ip
require_command nsenter
require_command node
require_command mktemp
require_command timeout

if [[ "$(id -u)" -ne 0 ]]; then
  echo "dhxpro e2e: expected root inside the test network namespace" >&2
  exit 1
fi

CLIENT_IF="veth-e2e-client"
SERVER_IF="veth-e2e-server"
SERVER_IP="10.55.0.1"
CLIENT_IP="10.55.0.2"
RELAY_IP="192.168.50.1"

WORKDIR=$(mktemp -d -t dhxpro-e2e.XXXXXXXX)
NS_PID=""
SERVER_PID_FILE="$WORKDIR/server.pid"

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  if [[ -f "$SERVER_PID_FILE" ]]; then
    local server_pid=""
    server_pid=$(<"$SERVER_PID_FILE") || true
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
      kill -TERM "$server_pid" 2>/dev/null || true
      for _ in $(seq 1 20); do
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -KILL "$server_pid" 2>/dev/null || true
    fi
  fi

  if [[ -n "$NS_PID" ]]; then
    kill "$NS_PID" 2>/dev/null || true
    wait "$NS_PID" 2>/dev/null || true
  fi

  if [[ $status -ne 0 ]]; then
    for log in "$WORKDIR"/server-*.log; do
      if [[ -f "$log" ]]; then
        echo "dhxpro e2e: last server log ($log):" >&2
        tail -n 40 "$log" >&2 || true
      fi
    done
  fi

  if [[ $status -eq 0 && "${DHXPRO_E2E_KEEP:-0}" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "dhxpro e2e: artifacts kept in $WORKDIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip link set lo up
unshare --net sleep infinity &
NS_PID=$!

for _ in $(seq 1 100); do
  if ! kill -0 "$NS_PID" 2>/dev/null; then
    break
  fi
  if [[ -e "/proc/$NS_PID/ns/net" ]]; then
    child_netns=$(readlink "/proc/$NS_PID/ns/net")
    current_netns=$(readlink "/proc/self/ns/net")
    if [[ "$child_netns" != "$current_netns" ]]; then
      break
    fi
  fi
  sleep 0.02
done
if ! kill -0 "$NS_PID" 2>/dev/null \
  || [[ ! -e "/proc/$NS_PID/ns/net" ]] \
  || [[ "$(readlink "/proc/$NS_PID/ns/net")" == "$(readlink "/proc/self/ns/net")" ]]; then
  echo "dhxpro e2e: server network namespace did not become ready" >&2
  exit 1
fi

ip link add "$CLIENT_IF" type veth peer name "$SERVER_IF"
ip link set "$SERVER_IF" netns "$NS_PID"
ip addr add "$CLIENT_IP/24" dev "$CLIENT_IF"
ip addr add "$RELAY_IP/32" dev "$CLIENT_IF"
ip link set "$CLIENT_IF" up
ip route add 255.255.255.255/32 dev "$CLIENT_IF"

nsenter -t "$NS_PID" -n ip link set lo up
nsenter -t "$NS_PID" -n ip addr add "$SERVER_IP/24" dev "$SERVER_IF"
nsenter -t "$NS_PID" -n ip link set "$SERVER_IF" up
nsenter -t "$NS_PID" -n ip route add 255.255.255.255/32 dev "$SERVER_IF"
nsenter -t "$NS_PID" -n ip route add 192.168.50.0/24 via "$CLIENT_IP" dev "$SERVER_IF"

export DHXPRO_E2E_WORKDIR="$WORKDIR"
export DHXPRO_E2E_BIN="$DHXPRO_BIN"
export DHXPRO_E2E_SERVER_NS_PID="$NS_PID"
export DHXPRO_E2E_CLIENT_IF="$CLIENT_IF"
export DHXPRO_E2E_SERVER_IF="$SERVER_IF"
export DHXPRO_E2E_SERVER_IP="$SERVER_IP"
export DHXPRO_E2E_CLIENT_IP="$CLIENT_IP"
export DHXPRO_E2E_RELAY_IP="$RELAY_IP"

echo "dhxpro e2e: server namespace pid=$NS_PID"
echo "dhxpro e2e: direct subnet 10.55.0.0/24 server=$SERVER_IP client=$CLIENT_IP"
echo "dhxpro e2e: relay subnet 192.168.50.0/24 gateway/server-id=$RELAY_IP"
echo "dhxpro e2e: artifacts in $WORKDIR"

cd "$VALIDATOR_DIR"
timeout 180s node --test --test-concurrency=1 --test-reporter=spec \
  test/dhcp4.e2e.test.js
