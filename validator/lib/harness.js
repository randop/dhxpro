import { execFileSync, spawn } from 'node:child_process';
import dgram from 'node:dgram';
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import {
  BOOTREPLY,
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  decodeMessage,
  ipv4Buffer,
} from './dhcp4.js';

export const DIRECT_RANGE = Object.freeze({
  start: '10.55.0.100',
  end: '10.55.0.110',
});

export const BRANCH_RANGE = Object.freeze({
  start: '192.168.50.100',
  end: '192.168.50.110',
});

export const RESERVED = Object.freeze({
  mac: '02:aa:bb:cc:dd:01',
  ip: '10.55.0.105',
  hostname: 'reserved-e2e',
});

const REQUIRED_ENV = [
  'DHXPRO_E2E_WORKDIR',
  'DHXPRO_E2E_BIN',
  'DHXPRO_E2E_SERVER_NS_PID',
  'DHXPRO_E2E_SERVER_IF',
  'DHXPRO_E2E_SERVER_IP',
  'DHXPRO_E2E_CLIENT_IP',
  'DHXPRO_E2E_CLIENT_IF',
  'DHXPRO_E2E_RELAY_IP',
];

export function readEnvironment() {
  const missing = REQUIRED_ENV.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(
      `missing validator environment: ${missing.join(', ')}; run \`pnpm test\` from validator/`,
    );
  }

  const env = {
    workdir: path.resolve(process.env.DHXPRO_E2E_WORKDIR),
    bin: path.resolve(process.env.DHXPRO_E2E_BIN),
    serverNsPid: Number(process.env.DHXPRO_E2E_SERVER_NS_PID),
    serverIf: process.env.DHXPRO_E2E_SERVER_IF,
    serverIp: process.env.DHXPRO_E2E_SERVER_IP,
    clientIp: process.env.DHXPRO_E2E_CLIENT_IP,
    clientIf: process.env.DHXPRO_E2E_CLIENT_IF,
    relayIp: process.env.DHXPRO_E2E_RELAY_IP,
  };

  if (!Number.isInteger(env.serverNsPid) || env.serverNsPid <= 0) {
    throw new Error(`invalid DHXPRO_E2E_SERVER_NS_PID: ${process.env.DHXPRO_E2E_SERVER_NS_PID}`);
  }
  for (const field of ['serverIp', 'clientIp', 'relayIp']) {
    ipv4Buffer(env[field]);
  }
  if (!existsSync(env.bin)) {
    throw new Error(`dhxpro binary does not exist: ${env.bin}`);
  }
  if (!existsSync(env.workdir)) {
    throw new Error(`validator workdir does not exist: ${env.workdir}`);
  }

  return env;
}

export function writeConfig(env) {
  const storeDir = path.join(env.workdir, 'store');
  mkdirSync(storeDir, { recursive: true });
  const storePath = path.join(storeDir, 'state.feox');
  const configPath = path.join(env.workdir, 'config.yaml');

  const yaml = `schema_version: 1
storage:
  path: ${JSON.stringify(storePath)}
  file_size_mib: 16
  max_memory_mib: 16
  hash_bits: 12
authoritative: true
subnets:
  - id: lan
    interface: ${env.serverIf}
    cidr: 10.55.0.0/24
    server_identifier: ${env.serverIp}
    range:
      start: ${DIRECT_RANGE.start}
      end: ${DIRECT_RANGE.end}
    exclusions: []
    routers:
      - ${env.serverIp}
    dns_servers:
      - 1.1.1.1
    domain_name: e2e.test
    lease_seconds: 600
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: incremental
  - id: branch
    cidr: 192.168.50.0/24
    server_identifier: ${env.relayIp}
    range:
      start: ${BRANCH_RANGE.start}
      end: ${BRANCH_RANGE.end}
    exclusions: []
    routers:
      - ${env.relayIp}
    dns_servers:
      - 1.1.1.1
    domain_name: branch.e2e.test
    lease_seconds: 300
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: random
relays:
  - giaddr: ${env.relayIp}
    subnet_id: branch
`;

  writeFileSync(configPath, yaml);
  return { configPath, storePath };
}

function runCli(env, configPath, args) {
  try {
    return execFileSync(env.bin, ['--config', configPath, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = [error.stdout, error.stderr, error.message].filter(Boolean).join('\n');
    throw new Error(`dhxpro ${args.join(' ')} failed:\n${detail}`);
  }
}

export function seedReservation(env, configPath) {
  runCli(env, configPath, [
    'reservation',
    'add',
    '--subnet',
    'lan',
    '--mac',
    RESERVED.mac,
    '--ip',
    RESERVED.ip,
    '--hostname',
    RESERVED.hostname,
  ]);
  const listing = runCli(env, configPath, ['reservation', 'list']);
  if (!listing.includes('02aabbccdd01') || !listing.includes(RESERVED.ip)) {
    throw new Error(`reservation was not persisted:\n${listing}`);
  }
}

export function addLocalAddress(address, interfaceName = process.env.DHXPRO_E2E_CLIENT_IF) {
  if (!interfaceName) {
    throw new Error('DHXPRO_E2E_CLIENT_IF is not set');
  }
  try {
    execFileSync('ip', ['addr', 'add', `${address}/32`, 'dev', interfaceName], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = [error.stdout, error.stderr, error.message].filter(Boolean).join('\n');
    if (!/file exists/i.test(detail)) {
      throw new Error(`failed to add local address ${address}:\n${detail}`);
    }
  }
}

async function waitForExit(child, timeoutMs) {
  let timer;
  const exited = new Promise((resolve) => child.once('exit', () => resolve(true)));
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  const result = await Promise.race([exited, timeout]);
  clearTimeout(timer);
  return result;
}

export class ServerProcess {
  constructor(env, configPath) {
    this.env = env;
    this.configPath = configPath;
    this.child = null;
    this.logPath = null;
    this.startCount = 0;
    this.pidPath = path.join(env.workdir, 'server.pid');
  }

  async start() {
    if (this.child) {
      throw new Error('server is already running');
    }
    this.startCount += 1;
    this.logPath = path.join(this.env.workdir, `server-${this.startCount}.log`);
    const logFd = openSync(this.logPath, 'w');
    const child = spawn(
      'nsenter',
      ['-t', String(this.env.serverNsPid), '-n', this.env.bin, '--config', this.configPath, 'serve'],
      { stdio: ['ignore', logFd, logFd] },
    );
    closeSync(logFd);
    this.child = child;
    writeFileSync(this.pidPath, `${child.pid}\n`);

    try {
      await new Promise((resolve, reject) => {
        child.once('spawn', resolve);
        child.once('error', reject);
      });
      await this.waitUntilReady();
    } catch (error) {
      await this.stop();
      throw error;
    }
    return this;
  }

  async waitUntilReady(timeoutMs = 15_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const log = this.readLog();
      if (log.includes('serving DHCP on UDP port 67 via io_uring')) {
        return;
      }
      if (this.child && this.child.exitCode !== null) {
        throw new Error(
          `dhxpro exited with code ${this.child.exitCode} during startup:\n${log}`,
        );
      }
      await sleep(50);
    }
    throw new Error(`dhxpro did not become ready within ${timeoutMs}ms:\n${this.readLog()}`);
  }

  readLog() {
    if (!this.logPath || !existsSync(this.logPath)) {
      return '';
    }
    return readFileSync(this.logPath, 'utf8');
  }

  async stop() {
    const child = this.child;
    this.child = null;
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      const exited = await waitForExit(child, 5_000);
      if (!exited) {
        child.kill('SIGKILL');
        await waitForExit(child, 1_000);
      }
    }
    if (existsSync(this.pidPath)) {
      unlinkSync(this.pidPath);
    }
  }

  async restart() {
    await this.stop();
    await this.start();
  }
}

export class DhcpPeer {
  constructor({ address = '0.0.0.0', port = DHCP_CLIENT_PORT, reuseAddr = false } = {}) {
    this.address = address;
    this.port = port;
    this.reuseAddr = reuseAddr;
    this.socket = null;
    this.messages = [];
    this.waiters = [];
    this.error = null;
  }

  async open() {
    if (this.socket) {
      return this;
    }
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: this.reuseAddr });
    this.socket = socket;

    socket.on('message', (data, rinfo) => {
      let message;
      try {
        message = decodeMessage(data);
      } catch {
        return;
      }
      const entry = { data: Buffer.from(data), message, rinfo };
      for (let index = 0; index < this.waiters.length; index += 1) {
        const waiter = this.waiters[index];
        if (!waiter.predicate(entry)) {
          continue;
        }
        this.waiters.splice(index, 1);
        clearTimeout(waiter.timer);
        waiter.resolve(entry);
        return;
      }
      this.messages.push(entry);
      if (this.messages.length > 256) {
        this.messages.shift();
      }
    });

    socket.on('error', (error) => {
      this.error = error;
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(error);
      }
    });

    await new Promise((resolve, reject) => {
      const onError = (error) => {
        socket.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        socket.off('error', onError);
        resolve();
      };
      socket.once('error', onError);
      socket.once('listening', onListening);
      socket.bind({ address: this.address, port: this.port, exclusive: true });
    });
    socket.setBroadcast(true);
    return this;
  }

  async send(packet, { address = '255.255.255.255', port = DHCP_SERVER_PORT } = {}) {
    if (!this.socket) {
      throw new Error('DHCP peer is not open');
    }
    await new Promise((resolve, reject) => {
      this.socket.send(packet, port, address, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }

  async next(predicate, timeoutMs = 2_000) {
    const index = this.messages.findIndex(predicate);
    if (index >= 0) {
      return this.messages.splice(index, 1)[0];
    }
    if (this.error) {
      throw this.error;
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        resolve,
        reject,
        timer: null,
      };
      waiter.timer = setTimeout(() => {
        const position = this.waiters.indexOf(waiter);
        if (position >= 0) {
          this.waiters.splice(position, 1);
        }
        const error = new Error(`timed out after ${timeoutMs}ms waiting for a DHCP reply`);
        error.code = 'E_DHCP_TIMEOUT';
        reject(error);
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  async exchange(packet, { address = '255.255.255.255', port = DHCP_SERVER_PORT, timeoutMs = 2_000 } = {}) {
    const xid = packet.readUInt32BE(4);
    const reply = this.next(
      ({ message }) => message.op === BOOTREPLY && message.xid === xid,
      timeoutMs,
    );
    await this.send(packet, { address, port });
    return reply;
  }

  async expectSilence(xid, timeoutMs = 500) {
    try {
      const reply = await this.next(
        ({ message }) => message.op === BOOTREPLY && message.xid === xid,
        timeoutMs,
      );
      throw new Error(
        `unexpected DHCP reply type ${reply.message.options.get(53)?.[0]?.[0]} for xid ${xid}`,
      );
    } catch (error) {
      if (error.code === 'E_DHCP_TIMEOUT') {
        return;
      }
      throw error;
    }
  }

  drain() {
    this.messages.length = 0;
  }

  async close() {
    const socket = this.socket;
    this.socket = null;
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      const error = new Error('DHCP peer closed');
      error.code = 'E_DHCP_CLOSED';
      waiter.reject(error);
    }
    if (!socket) {
      return;
    }
    try {
      await new Promise((resolve) => socket.close(resolve));
    } catch {
      // A socket that failed during bind may already be closed.
    }
  }
}

export async function createHarness() {
  const env = readEnvironment();
  const { configPath, storePath } = writeConfig(env);
  seedReservation(env, configPath);

  const server = new ServerProcess(env, configPath);
  const direct = new DhcpPeer({ port: DHCP_CLIENT_PORT });
  const relay = new DhcpPeer({ address: env.relayIp, port: DHCP_SERVER_PORT });
  let opened = false;

  try {
    await server.start();
    await direct.open();
    await relay.open();
    opened = true;
  } catch (error) {
    await direct.close();
    await relay.close();
    await server.stop();
    throw error;
  }

  return {
    env,
    configPath,
    storePath,
    server,
    direct,
    relay,
    async close() {
      if (!opened) {
        return;
      }
      opened = false;
      await direct.close();
      await relay.close();
      await server.stop();
    },
  };
}
