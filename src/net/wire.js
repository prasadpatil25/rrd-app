// Frame encoding and decoding. No state, no I/O, no clock.
//
// Everything here is a pure function over bytes, which is what makes the stack
// above it testable: a test can hand-build the guest's half of a conversation
// and compare our half byte for byte, the way test-nbd builds NBD requests.
//
// Only what the guest actually needs is here. There is no IPv6, no fragment
// reassembly, no UDP: the guest talks to one peer over a link that cannot drop
// or reorder in transit, and a smaller surface is a surface that can be read.

export const ETH_HEADER = 14;
export const IP_HEADER = 20;   // no options; we neither send nor honour any
export const TCP_HEADER = 20;  // without options

export const ETHERTYPE = { IPV4: 0x0800, ARP: 0x0806 };
export const PROTO = { ICMP: 1, TCP: 6 };
export const ARP_OP = { REQUEST: 1, REPLY: 2 };
export const ICMP = { ECHO_REPLY: 0, ECHO_REQUEST: 8 };

/** TCP control bits, in the order they sit in the byte. */
export const FLAG = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20 };

/** The largest payload that fits a 1500-byte link with no options on either header. */
export const MSS = 1460;

export const BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";

// --- addresses ---------------------------------------------------------------

export function macToBytes(mac) {
  const parts = String(mac).split(":");
  if (parts.length !== 6) throw new RangeError(`not a MAC address: ${mac}`);
  return Uint8Array.from(parts, (p) => {
    const n = parseInt(p, 16);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError(`not a MAC address: ${mac}`);
    return n;
  });
}

export function macToString(bytes, offset = 0) {
  let out = "";
  for (let i = 0; i < 6; i++) {
    out += (i ? ":" : "") + bytes[offset + i].toString(16).padStart(2, "0");
  }
  return out;
}

export function ipToBytes(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) throw new RangeError(`not an IPv4 address: ${ip}`);
  return Uint8Array.from(parts, (p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError(`not an IPv4 address: ${ip}`);
    return n;
  });
}

export function ipToString(bytes, offset = 0) {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

// --- checksums ---------------------------------------------------------------

/**
 * The ones' complement sum every IP-family header uses.
 *
 * Accumulating in a Number and folding at the end is safe here: a frame is at
 * most 1514 bytes, so the running total cannot reach 2^53 however the carries
 * fall.
 */
export function checksum(...parts) {
  let sum = 0;
  for (const bytes of parts) {
    let i = 0;
    for (; i + 1 < bytes.length; i += 2) sum += (bytes[i] << 8) | bytes[i + 1];
    if (i < bytes.length) sum += bytes[i] << 8;   // odd tail is padded with a zero
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

// --- ethernet ----------------------------------------------------------------

/**
 * @param {Object} f
 * @param {string} f.dst destination MAC
 * @param {string} f.src source MAC
 * @param {number} f.type an ETHERTYPE
 * @param {Uint8Array} f.payload
 */
export function encodeEthernet({ dst, src, type, payload }) {
  // Pad short frames to the 60-byte minimum. A real NIC does this in hardware
  // and a receiver trims by the length in the IP header, so the padding is
  // invisible; without it an ARP reply is 42 bytes and some drivers drop it.
  const length = Math.max(ETH_HEADER + payload.length, 60);
  const frame = new Uint8Array(length);
  frame.set(macToBytes(dst), 0);
  frame.set(macToBytes(src), 6);
  frame[12] = type >>> 8;
  frame[13] = type & 0xff;
  frame.set(payload, ETH_HEADER);
  return frame;
}

export function decodeEthernet(frame) {
  if (frame.length < ETH_HEADER) return null;
  return {
    dst: macToString(frame, 0),
    src: macToString(frame, 6),
    type: (frame[12] << 8) | frame[13],
    payload: frame.subarray(ETH_HEADER)
  };
}

// --- arp ---------------------------------------------------------------------

export function encodeArp({ op, senderMac, senderIp, targetMac, targetIp }) {
  const p = new Uint8Array(28);
  p[0] = 0; p[1] = 1;            // ethernet
  p[2] = 0x08; p[3] = 0x00;      // IPv4
  p[4] = 6; p[5] = 4;
  p[6] = op >>> 8; p[7] = op & 0xff;
  p.set(macToBytes(senderMac), 8);
  p.set(ipToBytes(senderIp), 14);
  p.set(macToBytes(targetMac), 18);
  p.set(ipToBytes(targetIp), 24);
  return p;
}

export function decodeArp(payload) {
  if (payload.length < 28) return null;
  const hardware = (payload[0] << 8) | payload[1];
  const protocol = (payload[2] << 8) | payload[3];
  // Anything that is not ethernet-over-IPv4 is not ours to answer.
  if (hardware !== 1 || protocol !== ETHERTYPE.IPV4 || payload[4] !== 6 || payload[5] !== 4) return null;
  return {
    op: (payload[6] << 8) | payload[7],
    senderMac: macToString(payload, 8),
    senderIp: ipToString(payload, 14),
    targetMac: macToString(payload, 18),
    targetIp: ipToString(payload, 24)
  };
}

// --- ipv4 --------------------------------------------------------------------

export function encodeIp({ src, dst, protocol, payload, id = 0, ttl = 64 }) {
  const packet = new Uint8Array(IP_HEADER + payload.length);
  packet[0] = 0x45;                       // version 4, 5 words of header
  packet[1] = 0;
  packet[2] = (packet.length >>> 8) & 0xff;
  packet[3] = packet.length & 0xff;
  packet[4] = (id >>> 8) & 0xff;
  packet[5] = id & 0xff;
  packet[6] = 0x40;                       // don't fragment, offset zero
  packet[7] = 0;
  packet[8] = ttl;
  packet[9] = protocol;
  packet.set(ipToBytes(src), 12);
  packet.set(ipToBytes(dst), 16);
  const sum = checksum(packet.subarray(0, IP_HEADER));
  packet[10] = (sum >>> 8) & 0xff;
  packet[11] = sum & 0xff;
  packet.set(payload, IP_HEADER);
  return packet;
}

export function decodeIp(payload) {
  if (payload.length < IP_HEADER) return null;
  if ((payload[0] >>> 4) !== 4) return null;
  const headerLength = (payload[0] & 0x0f) * 4;
  if (headerLength < IP_HEADER || payload.length < headerLength) return null;

  const total = (payload[2] << 8) | payload[3];
  // Trust the header's length over the frame's: the frame may carry ethernet
  // padding, and handing that padding on as TCP payload corrupts the stream.
  const end = total >= headerLength && total <= payload.length ? total : payload.length;

  // A fragment is not something this stack reassembles. Reporting it lets the
  // caller drop it deliberately rather than parse a fragment as a whole packet.
  const fragmented = (payload[6] & 0x20) !== 0 || (((payload[6] & 0x1f) << 8) | payload[7]) !== 0;

  return {
    protocol: payload[9],
    src: ipToString(payload, 12),
    dst: ipToString(payload, 16),
    fragmented,
    payload: payload.subarray(headerLength, end)
  };
}

// --- icmp --------------------------------------------------------------------

export function decodeIcmp(payload) {
  if (payload.length < 4) return null;
  return { type: payload[0], code: payload[1], rest: payload.subarray(4) };
}

/** Turn an echo request into its reply, which is the same packet with a new type. */
export function icmpEchoReply(request) {
  const reply = new Uint8Array(request);
  reply[0] = ICMP.ECHO_REPLY;
  reply[2] = 0; reply[3] = 0;
  const sum = checksum(reply);
  reply[2] = (sum >>> 8) & 0xff;
  reply[3] = sum & 0xff;
  return reply;
}

// --- tcp ---------------------------------------------------------------------

/** The twelve bytes of addressing TCP borrows from IP to checksum over. */
function pseudoHeader(src, dst, length) {
  const p = new Uint8Array(12);
  p.set(ipToBytes(src), 0);
  p.set(ipToBytes(dst), 4);
  p[8] = 0;
  p[9] = PROTO.TCP;
  p[10] = (length >>> 8) & 0xff;
  p[11] = length & 0xff;
  return p;
}

export function encodeTcp({
  src, dst, srcPort, dstPort, seq, ack = 0, flags,
  window = 0xffff, payload = new Uint8Array(0), mss = null
}) {
  const options = mss === null ? new Uint8Array(0)
    : Uint8Array.from([2, 4, (mss >>> 8) & 0xff, mss & 0xff, 0, 0, 0, 0]); // MSS, then NOPs to a word
  const header = TCP_HEADER + options.length;
  const segment = new Uint8Array(header + payload.length);

  segment[0] = (srcPort >>> 8) & 0xff; segment[1] = srcPort & 0xff;
  segment[2] = (dstPort >>> 8) & 0xff; segment[3] = dstPort & 0xff;
  writeU32(segment, 4, seq);
  writeU32(segment, 8, ack);
  segment[12] = (header / 4) << 4;
  segment[13] = flags;
  segment[14] = (window >>> 8) & 0xff; segment[15] = window & 0xff;
  segment.set(options, TCP_HEADER);
  segment.set(payload, header);

  const sum = checksum(pseudoHeader(src, dst, segment.length), segment);
  segment[16] = (sum >>> 8) & 0xff;
  segment[17] = sum & 0xff;
  return segment;
}

export function decodeTcp(payload) {
  if (payload.length < TCP_HEADER) return null;
  const dataOffset = (payload[12] >>> 4) * 4;
  if (dataOffset < TCP_HEADER || payload.length < dataOffset) return null;
  return {
    srcPort: (payload[0] << 8) | payload[1],
    dstPort: (payload[2] << 8) | payload[3],
    seq: readU32(payload, 4),
    ack: readU32(payload, 8),
    flags: payload[13],
    window: (payload[14] << 8) | payload[15],
    payload: payload.subarray(dataOffset)
  };
}

/** Whether a decoded segment's checksum is the one the sender computed. */
export function tcpChecksumValid(src, dst, segment) {
  return checksum(pseudoHeader(src, dst, segment.length), segment) === 0;
}

// --- sequence numbers --------------------------------------------------------
//
// Sequence space is 32 bits and wraps. Comparing with < would put a connection
// that has moved a few gigabytes into a state where every arriving segment looks
// like the past, so every comparison goes through these.

export const seqAdd = (a, b) => (a + b) >>> 0;

/** True when a is before b, deciding by the shorter way round the circle. */
export const seqLt = (a, b) => ((a - b) >>> 0) > 0x80000000;
export const seqLte = (a, b) => a === b || seqLt(a, b);
export const seqGt = (a, b) => seqLt(b, a);
export const seqGte = (a, b) => a === b || seqLt(b, a);

function writeU32(bytes, offset, value) {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

function readU32(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
          (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}
