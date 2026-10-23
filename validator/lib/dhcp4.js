import { randomInt } from 'node:crypto';

export const DHCP_SERVER_PORT = 67;
export const DHCP_CLIENT_PORT = 68;

export const BOOTREQUEST = 1;
export const BOOTREPLY = 2;

export const MESSAGE = Object.freeze({
  DISCOVER: 1,
  OFFER: 2,
  REQUEST: 3,
  DECLINE: 4,
  ACK: 5,
  NAK: 6,
  RELEASE: 7,
  INFORM: 8,
});

export const OPTION = Object.freeze({
  SUBNET_MASK: 1,
  ROUTER: 3,
  DNS: 6,
  HOSTNAME: 12,
  DOMAIN_NAME: 15,
  BROADCAST: 28,
  REQUESTED_IP: 50,
  LEASE_TIME: 51,
  OVERLOAD: 52,
  MESSAGE_TYPE: 53,
  SERVER_ID: 54,
  PARAMETER_REQUEST_LIST: 55,
  MESSAGE: 56,
  MAX_MESSAGE_SIZE: 57,
  RENEWAL_T1: 58,
  REBINDING_T2: 59,
  CLIENT_ID: 61,
  RELAY_AGENT: 82,
});

export const BROADCAST_FLAG = 0x8000;

const MAGIC_COOKIE = Buffer.from([0x63, 0x82, 0x53, 0x63]);
const HEADER_LEN = 240;

export function parseMac(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== 6) {
      throw new Error(`MAC must be 6 bytes, got ${value.length}`);
    }
    return Buffer.from(value);
  }
  const compact = String(value).replace(/[:-]/g, '').replace(/\./g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(compact)) {
    throw new Error(`invalid MAC address: ${value}`);
  }
  return Buffer.from(compact, 'hex');
}

export function macHex(value) {
  return parseMac(value).toString('hex');
}

export function ipv4Buffer(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4) {
    throw new Error(`invalid IPv4 address: ${value}`);
  }
  return Buffer.from(
    parts.map((part) => {
      const octet = Number(part);
      if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
        throw new Error(`invalid IPv4 address: ${value}`);
      }
      return octet;
    }),
  );
}

export function ipv4String(buffer) {
  if (buffer.length !== 4) {
    throw new Error(`IPv4 buffer must be 4 bytes, got ${buffer.length}`);
  }
  return [...buffer].join('.');
}

export function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

export function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0);
  return out;
}

export function option(code, value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (!Number.isInteger(code) || code < 0 || code > 255) {
    throw new Error(`invalid DHCP option code: ${code}`);
  }
  if (data.length > 255) {
    throw new Error(`DHCP option ${code} payload is ${data.length} bytes`);
  }
  return Buffer.concat([Buffer.from([code, data.length]), data]);
}

export function clientIdentifier(mac) {
  return Buffer.concat([Buffer.from([1]), parseMac(mac)]);
}

export function randomXid() {
  return randomInt(1, 0x7fffffff);
}

export function encodeMessage({
  type,
  xid = randomXid(),
  mac,
  flags = BROADCAST_FLAG,
  hops = 0,
  ciaddr = '0.0.0.0',
  giaddr = '0.0.0.0',
  options = [],
}) {
  const packet = Buffer.alloc(HEADER_LEN);
  packet[0] = BOOTREQUEST;
  packet[1] = 1; // Ethernet
  packet[2] = 6; // chaddr length
  packet[3] = hops;
  packet.writeUInt32BE(xid >>> 0, 4);
  packet.writeUInt16BE(flags, 10);
  ipv4Buffer(ciaddr).copy(packet, 12);
  ipv4Buffer(giaddr).copy(packet, 24);
  parseMac(mac).copy(packet, 28);
  MAGIC_COOKIE.copy(packet, 236);

  return Buffer.concat([
    packet,
    option(OPTION.MESSAGE_TYPE, [type]),
    ...options,
    Buffer.from([255]),
  ]);
}

export function decodeMessage(packet) {
  if (packet.length < HEADER_LEN) {
    throw new Error(`DHCP packet is ${packet.length} bytes, expected at least ${HEADER_LEN}`);
  }
  if (!packet.subarray(236, 240).equals(MAGIC_COOKIE)) {
    throw new Error('DHCP magic cookie is missing or incorrect');
  }

  const options = new Map();
  let offset = HEADER_LEN;
  while (offset < packet.length) {
    const code = packet[offset++];
    if (code === 0) {
      continue;
    }
    if (code === 255) {
      break;
    }
    if (offset >= packet.length) {
      throw new Error(`DHCP option ${code} is missing its length byte`);
    }
    const length = packet[offset++];
    const end = offset + length;
    if (end > packet.length) {
      throw new Error(
        `DHCP option ${code} claims ${length} bytes but only ${packet.length - offset} remain`,
      );
    }
    if (!options.has(code)) {
      options.set(code, []);
    }
    options.get(code).push(packet.subarray(offset, end));
    offset = end;
  }

  return {
    op: packet[0],
    htype: packet[1],
    hlen: packet[2],
    hops: packet[3],
    xid: packet.readUInt32BE(4),
    secs: packet.readUInt16BE(8),
    flags: packet.readUInt16BE(10),
    ciaddr: ipv4String(packet.subarray(12, 16)),
    yiaddr: ipv4String(packet.subarray(16, 20)),
    siaddr: ipv4String(packet.subarray(20, 24)),
    giaddr: ipv4String(packet.subarray(24, 28)),
    mac: packet.subarray(28, 34).toString('hex'),
    options,
  };
}

export function messageType(message) {
  const value = optionValue(message, OPTION.MESSAGE_TYPE);
  return value ? value[0] : undefined;
}

export function optionValues(message, code) {
  return message.options.get(code) ?? [];
}

export function optionValue(message, code) {
  return message.options.get(code)?.[0];
}

export function optionIpv4(message, code) {
  const value = optionValue(message, code);
  if (!value || value.length !== 4) {
    throw new Error(`option ${code} is not a 4-byte IPv4 address`);
  }
  return ipv4String(value);
}

export function optionIpv4List(message, code) {
  const value = optionValue(message, code);
  if (!value || value.length === 0 || value.length % 4 !== 0) {
    throw new Error(`option ${code} is not a list of IPv4 addresses`);
  }
  const addresses = [];
  for (let offset = 0; offset < value.length; offset += 4) {
    addresses.push(ipv4String(value.subarray(offset, offset + 4)));
  }
  return addresses;
}

export function optionUint16(message, code) {
  const value = optionValue(message, code);
  if (!value || value.length !== 2) {
    throw new Error(`option ${code} is not a 16-bit integer`);
  }
  return value.readUInt16BE(0);
}

export function optionUint32(message, code) {
  const value = optionValue(message, code);
  if (!value || value.length !== 4) {
    throw new Error(`option ${code} is not a 32-bit integer`);
  }
  return value.readUInt32BE(0);
}

export function optionString(message, code) {
  const value = optionValue(message, code);
  if (!value) {
    throw new Error(`option ${code} is missing`);
  }
  return value.toString('utf8');
}
