import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import {
  BOOTREPLY,
  BROADCAST_FLAG,
  MESSAGE,
  OPTION,
  clientIdentifier,
  encodeMessage,
  ipv4Buffer,
  macHex,
  messageType,
  option,
  optionIpv4,
  optionIpv4List,
  optionString,
  optionUint32,
  optionValue,
  randomXid,
  u16,
} from '../lib/dhcp4.js';
import {
  BRANCH_RANGE,
  DIRECT_RANGE,
  RESERVED,
  addLocalAddress,
  createHarness,
} from '../lib/harness.js';

const MAC_DORA = '02:11:22:33:44:01';
const MAC_SECOND = '02:11:22:33:44:02';
const MAC_UNKNOWN = '02:11:22:33:44:03';
const MAC_DECLINE = '02:11:22:33:44:04';
const MAC_AFTER_DECLINE = '02:11:22:33:44:05';
const MAC_INFORM = '02:11:22:33:44:06';
const MAC_LIMITED = '02:11:22:33:44:07';
const MAC_RELAY = '02:11:22:33:44:08';
const MAC_MALFORMED = '02:11:22:33:44:09';
const MAC_CROSS = '02:11:22:33:44:0a';

const PARAMETER_REQUEST_LIST = [
  OPTION.SUBNET_MASK,
  OPTION.ROUTER,
  OPTION.DNS,
  OPTION.DOMAIN_NAME,
  OPTION.BROADCAST,
  OPTION.LEASE_TIME,
  OPTION.RENEWAL_T1,
  OPTION.REBINDING_T2,
];

const RELAY_AGENT_INFORMATION = Buffer.from([1, 6, ...Buffer.from('port-1')]);
const INFORM_ADDRESS = '10.55.0.250';

let harness;
const state = {};

function clientOptions(mac, hostname, maxMessageSize = 1500) {
  return [
    option(OPTION.CLIENT_ID, clientIdentifier(mac)),
    option(OPTION.HOSTNAME, Buffer.from(hostname)),
    option(OPTION.PARAMETER_REQUEST_LIST, Buffer.from(PARAMETER_REQUEST_LIST)),
    option(OPTION.MAX_MESSAGE_SIZE, u16(maxMessageSize)),
  ];
}

function buildDiscover({
  mac,
  hostname,
  xid = randomXid(),
  flags = BROADCAST_FLAG,
  hops = 0,
  giaddr = '0.0.0.0',
  maxMessageSize = 1500,
  extraOptions = [],
}) {
  return encodeMessage({
    type: MESSAGE.DISCOVER,
    xid,
    mac,
    flags,
    hops,
    giaddr,
    options: [...clientOptions(mac, hostname, maxMessageSize), ...extraOptions],
  });
}

function buildRequest({
  mac,
  hostname,
  xid = randomXid(),
  ciaddr = '0.0.0.0',
  serverId,
  requestedIp,
  flags = BROADCAST_FLAG,
  hops = 0,
  giaddr = '0.0.0.0',
  maxMessageSize = 1500,
  extraOptions = [],
}) {
  const options = clientOptions(mac, hostname, maxMessageSize);
  if (serverId) {
    options.push(option(OPTION.SERVER_ID, ipv4Buffer(serverId)));
  }
  if (requestedIp) {
    options.push(option(OPTION.REQUESTED_IP, ipv4Buffer(requestedIp)));
  }
  options.push(...extraOptions);
  return encodeMessage({
    type: MESSAGE.REQUEST,
    xid,
    mac,
    ciaddr,
    flags,
    hops,
    giaddr,
    options,
  });
}

function buildDecline({ mac, hostname, serverId, requestedIp, xid = randomXid() }) {
  return encodeMessage({
    type: MESSAGE.DECLINE,
    xid,
    mac,
    flags: BROADCAST_FLAG,
    options: [
      option(OPTION.CLIENT_ID, clientIdentifier(mac)),
      option(OPTION.HOSTNAME, Buffer.from(hostname)),
      option(OPTION.SERVER_ID, ipv4Buffer(serverId)),
      option(OPTION.REQUESTED_IP, ipv4Buffer(requestedIp)),
    ],
  });
}

function buildRelease({ mac, hostname, serverId, ciaddr, xid = randomXid() }) {
  return encodeMessage({
    type: MESSAGE.RELEASE,
    xid,
    mac,
    ciaddr,
    flags: 0,
    options: [
      option(OPTION.CLIENT_ID, clientIdentifier(mac)),
      option(OPTION.HOSTNAME, Buffer.from(hostname)),
      option(OPTION.SERVER_ID, ipv4Buffer(serverId)),
    ],
  });
}

function buildInform({ mac, hostname, ciaddr, xid = randomXid() }) {
  return encodeMessage({
    type: MESSAGE.INFORM,
    xid,
    mac,
    ciaddr,
    flags: 0,
    options: clientOptions(mac, hostname),
  });
}

function assertReply(entry, { type, xid, mac }) {
  const message = entry.message;
  assert.equal(message.op, BOOTREPLY);
  assert.equal(message.htype, 1);
  assert.equal(message.hlen, 6);
  assert.equal(message.xid, xid);
  assert.equal(message.mac, macHex(mac));
  assert.equal(messageType(message), type);
  assert.equal(entry.rinfo.port, 67);
  return message;
}

function assertInRange(address, range) {
  const value = ipv4Buffer(address).readUInt32BE(0);
  const start = ipv4Buffer(range.start).readUInt32BE(0);
  const end = ipv4Buffer(range.end).readUInt32BE(0);
  assert.ok(value >= start && value <= end, `${address} is outside ${range.start}..${range.end}`);
}

before(async () => {
  harness = await createHarness();
});

after(async () => {
  if (harness) {
    await harness.close();
  }
});

test('drops malformed DHCP while remaining available', async () => {
  harness.direct.drain();
  const xid = randomXid();
  const packet = buildDiscover({ mac: MAC_MALFORMED, hostname: 'malformed-e2e', xid });
  // Option 53 starts at byte 240. Make its claimed length run past the packet.
  assert.equal(packet[240], OPTION.MESSAGE_TYPE);
  packet[241] = 250;

  await harness.direct.send(packet);
  await harness.direct.expectSilence(xid, 600);
  assert.equal(harness.server.child.exitCode, null);
});

test('completes DISCOVER/OFFER/REQUEST/ACK with requested options and idempotent offers', async () => {
  harness.direct.drain();
  const discoverXid = randomXid();
  const offerEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_DORA, hostname: 'dora-one', xid: discoverXid }),
  );
  const offer = assertReply(offerEntry, {
    type: MESSAGE.OFFER,
    xid: discoverXid,
    mac: MAC_DORA,
  });

  assert.equal(offerEntry.rinfo.address, harness.env.serverIp);
  assert.equal(offer.ciaddr, '0.0.0.0');
  assert.equal(offer.giaddr, '0.0.0.0');
  assert.equal(offer.yiaddr, DIRECT_RANGE.start);
  assert.equal(optionIpv4(offer, OPTION.SERVER_ID), harness.env.serverIp);
  assert.equal(optionIpv4(offer, OPTION.SUBNET_MASK), '255.255.255.0');
  assert.deepEqual(optionIpv4List(offer, OPTION.ROUTER), [harness.env.serverIp]);
  assert.deepEqual(optionIpv4List(offer, OPTION.DNS), ['1.1.1.1']);
  assert.equal(optionString(offer, OPTION.DOMAIN_NAME), 'e2e.test');
  assert.equal(optionIpv4(offer, OPTION.BROADCAST), '10.55.0.255');
  assert.equal(optionUint32(offer, OPTION.LEASE_TIME), 600);
  assert.equal(optionUint32(offer, OPTION.RENEWAL_T1), 300);
  assert.equal(optionUint32(offer, OPTION.REBINDING_T2), 525);
  assert.ok(offerEntry.data.length >= 300);

  const requestXid = randomXid();
  const ackEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_DORA,
      hostname: 'dora-one',
      xid: requestXid,
      serverId: harness.env.serverIp,
      requestedIp: offer.yiaddr,
    }),
  );
  const ack = assertReply(ackEntry, {
    type: MESSAGE.ACK,
    xid: requestXid,
    mac: MAC_DORA,
  });
  assert.equal(ackEntry.rinfo.address, harness.env.serverIp);
  assert.equal(ack.yiaddr, offer.yiaddr);
  assert.equal(optionIpv4(ack, OPTION.SERVER_ID), harness.env.serverIp);
  assert.equal(optionUint32(ack, OPTION.LEASE_TIME), 600);
  assert.equal(optionValue(ack, OPTION.MESSAGE), undefined);

  const replayXid = randomXid();
  const replayEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_DORA, hostname: 'dora-one', xid: replayXid }),
  );
  const replay = assertReply(replayEntry, {
    type: MESSAGE.OFFER,
    xid: replayXid,
    mac: MAC_DORA,
  });
  assert.equal(replay.yiaddr, offer.yiaddr);

  state.dora = { mac: MAC_DORA, hostname: 'dora-one', ip: offer.yiaddr };
});

test('leases the next address, NAKs an unknown INIT-REBOOT, and releases cleanly', async () => {
  harness.direct.drain();
  const discoverXid = randomXid();
  const offerEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_SECOND, hostname: 'dora-two', xid: discoverXid }),
  );
  const offer = assertReply(offerEntry, {
    type: MESSAGE.OFFER,
    xid: discoverXid,
    mac: MAC_SECOND,
  });
  assert.equal(offer.yiaddr, '10.55.0.101');

  const requestXid = randomXid();
  const ackEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_SECOND,
      hostname: 'dora-two',
      xid: requestXid,
      serverId: harness.env.serverIp,
      requestedIp: offer.yiaddr,
    }),
  );
  const ack = assertReply(ackEntry, {
    type: MESSAGE.ACK,
    xid: requestXid,
    mac: MAC_SECOND,
  });
  assert.equal(ack.yiaddr, offer.yiaddr);

  const nakXid = randomXid();
  const nakEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_UNKNOWN,
      hostname: 'unknown-e2e',
      xid: nakXid,
      requestedIp: '10.55.0.109',
    }),
  );
  const nak = assertReply(nakEntry, {
    type: MESSAGE.NAK,
    xid: nakXid,
    mac: MAC_UNKNOWN,
  });
  assert.equal(nak.yiaddr, '0.0.0.0');
  assert.equal(optionIpv4(nak, OPTION.SERVER_ID), harness.env.serverIp);
  assert.ok(optionString(nak, OPTION.MESSAGE).length > 0);
  assert.equal(nak.options.has(OPTION.LEASE_TIME), false);
  assert.equal(nak.options.has(OPTION.SUBNET_MASK), false);
  assert.equal(nak.flags & BROADCAST_FLAG, BROADCAST_FLAG);

  const releaseXid = randomXid();
  await harness.direct.send(
    buildRelease({
      mac: MAC_SECOND,
      hostname: 'dora-two',
      serverId: harness.env.serverIp,
      ciaddr: offer.yiaddr,
      xid: releaseXid,
    }),
  );
  await harness.direct.expectSilence(releaseXid, 600);

  const afterReleaseXid = randomXid();
  const afterReleaseEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_SECOND,
      hostname: 'dora-two',
      xid: afterReleaseXid,
      requestedIp: offer.yiaddr,
    }),
  );
  const afterRelease = assertReply(afterReleaseEntry, {
    type: MESSAGE.NAK,
    xid: afterReleaseXid,
    mac: MAC_SECOND,
  });
  assert.equal(afterRelease.yiaddr, '0.0.0.0');
});

test('honours a persisted fixed reservation', async () => {
  harness.direct.drain();
  const discoverXid = randomXid();
  const offerEntry = await harness.direct.exchange(
    buildDiscover({ mac: RESERVED.mac, hostname: RESERVED.hostname, xid: discoverXid }),
  );
  const offer = assertReply(offerEntry, {
    type: MESSAGE.OFFER,
    xid: discoverXid,
    mac: RESERVED.mac,
  });
  assert.equal(offer.yiaddr, RESERVED.ip);
  assert.equal(optionIpv4(offer, OPTION.SERVER_ID), harness.env.serverIp);

  const requestXid = randomXid();
  const ackEntry = await harness.direct.exchange(
    buildRequest({
      mac: RESERVED.mac,
      hostname: RESERVED.hostname,
      xid: requestXid,
      serverId: harness.env.serverIp,
      requestedIp: RESERVED.ip,
    }),
  );
  const ack = assertReply(ackEntry, {
    type: MESSAGE.ACK,
    xid: requestXid,
    mac: RESERVED.mac,
  });
  assert.equal(ack.yiaddr, RESERVED.ip);
  assert.equal(optionUint32(ack, OPTION.LEASE_TIME), 600);

  state.reserved = { ip: ack.yiaddr, mac: RESERVED.mac, hostname: RESERVED.hostname };
});

test('quarantines a declined address', async () => {
  harness.direct.drain();
  const discoverXid = randomXid();
  const offerEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_DECLINE, hostname: 'decline-e2e', xid: discoverXid }),
  );
  const offer = assertReply(offerEntry, {
    type: MESSAGE.OFFER,
    xid: discoverXid,
    mac: MAC_DECLINE,
  });
  assertInRange(offer.yiaddr, DIRECT_RANGE);
  assert.notEqual(offer.yiaddr, RESERVED.ip);

  const requestXid = randomXid();
  const ackEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_DECLINE,
      hostname: 'decline-e2e',
      xid: requestXid,
      serverId: harness.env.serverIp,
      requestedIp: offer.yiaddr,
    }),
  );
  const ack = assertReply(ackEntry, {
    type: MESSAGE.ACK,
    xid: requestXid,
    mac: MAC_DECLINE,
  });
  assert.equal(ack.yiaddr, offer.yiaddr);

  const declineXid = randomXid();
  await harness.direct.send(
    buildDecline({
      mac: MAC_DECLINE,
      hostname: 'decline-e2e',
      serverId: harness.env.serverIp,
      requestedIp: offer.yiaddr,
      xid: declineXid,
    }),
  );
  await harness.direct.expectSilence(declineXid, 600);

  const nextXid = randomXid();
  const nextEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_AFTER_DECLINE, hostname: 'after-decline-e2e', xid: nextXid }),
  );
  const next = assertReply(nextEntry, {
    type: MESSAGE.OFFER,
    xid: nextXid,
    mac: MAC_AFTER_DECLINE,
  });
  assertInRange(next.yiaddr, DIRECT_RANGE);
  assert.notEqual(next.yiaddr, offer.yiaddr);
  assert.notEqual(next.yiaddr, RESERVED.ip);
});

test('trims replies to the client maximum message size', async () => {
  harness.direct.drain();
  const xid = randomXid();
  const entry = await harness.direct.exchange(
    buildDiscover({
      mac: MAC_LIMITED,
      hostname: 'limited-e2e',
      xid,
      maxMessageSize: 300,
    }),
  );
  const offer = assertReply(entry, {
    type: MESSAGE.OFFER,
    xid,
    mac: MAC_LIMITED,
  });
  assert.ok(entry.data.length <= 300, `reply is ${entry.data.length} bytes`);
  assert.ok(entry.data.length > 240);
  assert.equal(optionIpv4(offer, OPTION.SERVER_ID), harness.env.serverIp);
  assert.equal(optionIpv4(offer, OPTION.SUBNET_MASK), '255.255.255.0');
  assert.equal(optionUint32(offer, OPTION.LEASE_TIME), 600);
});

test('answers INFORM with configuration and no lease', async () => {
  harness.direct.drain();
  addLocalAddress(INFORM_ADDRESS);
  const xid = randomXid();
  const entry = await harness.direct.exchange(
    buildInform({
      mac: MAC_INFORM,
      hostname: 'inform-e2e',
      ciaddr: INFORM_ADDRESS,
      xid,
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const ack = assertReply(entry, {
    type: MESSAGE.ACK,
    xid,
    mac: MAC_INFORM,
  });
  assert.equal(entry.rinfo.address, harness.env.serverIp);
  assert.equal(ack.yiaddr, '0.0.0.0');
  assert.equal(optionIpv4(ack, OPTION.SERVER_ID), harness.env.serverIp);
  assert.equal(optionIpv4(ack, OPTION.SUBNET_MASK), '255.255.255.0');
  assert.deepEqual(optionIpv4List(ack, OPTION.ROUTER), [harness.env.serverIp]);
  assert.equal(ack.options.has(OPTION.LEASE_TIME), false);
  assert.equal(ack.options.has(OPTION.RENEWAL_T1), false);
  assert.equal(ack.options.has(OPTION.REBINDING_T2), false);
});

test('renews a reserved binding via unicast to ciaddr', async () => {
  harness.direct.drain();
  addLocalAddress(RESERVED.ip);
  const xid = randomXid();
  const entry = await harness.direct.exchange(
    buildRequest({
      mac: RESERVED.mac,
      hostname: RESERVED.hostname,
      xid,
      ciaddr: RESERVED.ip,
      flags: 0,
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const ack = assertReply(entry, {
    type: MESSAGE.ACK,
    xid,
    mac: RESERVED.mac,
  });
  assert.equal(ack.yiaddr, RESERVED.ip);
  assert.equal(optionUint32(ack, OPTION.LEASE_TIME), 600);
  assert.equal(optionUint32(ack, OPTION.RENEWAL_T1), 300);
});

test('routes a relayed exchange through giaddr and echoes option 82', async () => {
  harness.relay.drain();
  const discoverXid = randomXid();
  const offerEntry = await harness.relay.exchange(
    buildDiscover({
      mac: MAC_RELAY,
      hostname: 'relay-e2e',
      xid: discoverXid,
      flags: 0,
      hops: 1,
      giaddr: harness.env.relayIp,
      extraOptions: [option(OPTION.RELAY_AGENT, RELAY_AGENT_INFORMATION)],
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const offer = assertReply(offerEntry, {
    type: MESSAGE.OFFER,
    xid: discoverXid,
    mac: MAC_RELAY,
  });
  assert.equal(offerEntry.rinfo.address, harness.env.serverIp);
  assert.equal(offer.giaddr, harness.env.relayIp);
  assertInRange(offer.yiaddr, BRANCH_RANGE);
  assert.equal(optionIpv4(offer, OPTION.SERVER_ID), harness.env.relayIp);
  assert.equal(optionIpv4(offer, OPTION.SUBNET_MASK), '255.255.255.0');
  assert.deepEqual(optionIpv4List(offer, OPTION.ROUTER), [harness.env.relayIp]);
  assert.deepEqual(optionValue(offer, OPTION.RELAY_AGENT), RELAY_AGENT_INFORMATION);

  const requestXid = randomXid();
  const ackEntry = await harness.relay.exchange(
    buildRequest({
      mac: MAC_RELAY,
      hostname: 'relay-e2e',
      xid: requestXid,
      flags: 0,
      hops: 1,
      giaddr: harness.env.relayIp,
      serverId: harness.env.relayIp,
      requestedIp: offer.yiaddr,
      extraOptions: [option(OPTION.RELAY_AGENT, RELAY_AGENT_INFORMATION)],
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const ack = assertReply(ackEntry, {
    type: MESSAGE.ACK,
    xid: requestXid,
    mac: MAC_RELAY,
  });
  assert.equal(ack.giaddr, harness.env.relayIp);
  assert.equal(ack.yiaddr, offer.yiaddr);
  assert.equal(optionIpv4(ack, OPTION.SERVER_ID), harness.env.relayIp);
  assert.deepEqual(optionValue(ack, OPTION.RELAY_AGENT), RELAY_AGENT_INFORMATION);

  state.relay = { ip: ack.yiaddr, mac: MAC_RELAY };
});

test('keeps distinct per-subnet bindings for the same MAC', async () => {
  harness.direct.drain();
  harness.relay.drain();

  const directDiscoverXid = randomXid();
  const directOfferEntry = await harness.direct.exchange(
    buildDiscover({ mac: MAC_CROSS, hostname: 'cross-e2e', xid: directDiscoverXid }),
  );
  const directOffer = assertReply(directOfferEntry, {
    type: MESSAGE.OFFER,
    xid: directDiscoverXid,
    mac: MAC_CROSS,
  });
  assertInRange(directOffer.yiaddr, DIRECT_RANGE);
  assert.notEqual(directOffer.yiaddr, RESERVED.ip);

  const directRequestXid = randomXid();
  const directAckEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_CROSS,
      hostname: 'cross-e2e',
      xid: directRequestXid,
      serverId: harness.env.serverIp,
      requestedIp: directOffer.yiaddr,
    }),
  );
  const directAck = assertReply(directAckEntry, {
    type: MESSAGE.ACK,
    xid: directRequestXid,
    mac: MAC_CROSS,
  });
  assert.equal(directAck.yiaddr, directOffer.yiaddr);

  const relayDiscoverXid = randomXid();
  const branchOfferEntry = await harness.relay.exchange(
    buildDiscover({
      mac: MAC_CROSS,
      hostname: 'cross-e2e',
      xid: relayDiscoverXid,
      flags: 0,
      hops: 1,
      giaddr: harness.env.relayIp,
      extraOptions: [option(OPTION.RELAY_AGENT, RELAY_AGENT_INFORMATION)],
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const branchOffer = assertReply(branchOfferEntry, {
    type: MESSAGE.OFFER,
    xid: relayDiscoverXid,
    mac: MAC_CROSS,
  });
  assertInRange(branchOffer.yiaddr, BRANCH_RANGE);

  const branchRequestXid = randomXid();
  const branchAckEntry = await harness.relay.exchange(
    buildRequest({
      mac: MAC_CROSS,
      hostname: 'cross-e2e',
      xid: branchRequestXid,
      flags: 0,
      hops: 1,
      giaddr: harness.env.relayIp,
      serverId: harness.env.relayIp,
      requestedIp: branchOffer.yiaddr,
      extraOptions: [option(OPTION.RELAY_AGENT, RELAY_AGENT_INFORMATION)],
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const branchAck = assertReply(branchAckEntry, {
    type: MESSAGE.ACK,
    xid: branchRequestXid,
    mac: MAC_CROSS,
  });
  assert.equal(branchAck.yiaddr, branchOffer.yiaddr);
  assert.notEqual(branchAck.yiaddr, directAck.yiaddr);

  const directRebootXid = randomXid();
  const directRebootEntry = await harness.direct.exchange(
    buildRequest({
      mac: MAC_CROSS,
      hostname: 'cross-e2e',
      xid: directRebootXid,
      requestedIp: directAck.yiaddr,
    }),
  );
  const directReboot = assertReply(directRebootEntry, {
    type: MESSAGE.ACK,
    xid: directRebootXid,
    mac: MAC_CROSS,
  });
  assert.equal(directReboot.yiaddr, directAck.yiaddr);

  const branchRebootXid = randomXid();
  const branchRebootEntry = await harness.relay.exchange(
    buildRequest({
      mac: MAC_CROSS,
      hostname: 'cross-e2e',
      xid: branchRebootXid,
      flags: 0,
      hops: 1,
      giaddr: harness.env.relayIp,
      requestedIp: branchAck.yiaddr,
      extraOptions: [option(OPTION.RELAY_AGENT, RELAY_AGENT_INFORMATION)],
    }),
    { address: harness.env.serverIp, port: 67 },
  );
  const branchReboot = assertReply(branchRebootEntry, {
    type: MESSAGE.ACK,
    xid: branchRebootXid,
    mac: MAC_CROSS,
  });
  assert.equal(branchReboot.yiaddr, branchAck.yiaddr);
  assert.deepEqual(optionValue(branchReboot, OPTION.RELAY_AGENT), RELAY_AGENT_INFORMATION);
});

test('preserves leases and reservations across a server restart', async () => {
  assert.ok(state.dora, 'DORA state is missing');
  await harness.server.restart();
  assert.equal(harness.server.startCount, 2);
  assert.match(harness.server.readLog(), /serving DHCP on UDP port 67 via io_uring/);

  harness.direct.drain();
  const xid = randomXid();
  const entry = await harness.direct.exchange(
    buildRequest({
      mac: state.dora.mac,
      hostname: state.dora.hostname,
      xid,
      requestedIp: state.dora.ip,
    }),
  );
  const ack = assertReply(entry, {
    type: MESSAGE.ACK,
    xid,
    mac: state.dora.mac,
  });
  assert.equal(ack.yiaddr, state.dora.ip);
  assert.equal(optionUint32(ack, OPTION.LEASE_TIME), 600);

  const reservedXid = randomXid();
  const reservedEntry = await harness.direct.exchange(
    buildDiscover({
      mac: RESERVED.mac,
      hostname: RESERVED.hostname,
      xid: reservedXid,
    }),
  );
  const reservedOffer = assertReply(reservedEntry, {
    type: MESSAGE.OFFER,
    xid: reservedXid,
    mac: RESERVED.mac,
  });
  assert.equal(reservedOffer.yiaddr, RESERVED.ip);
});
