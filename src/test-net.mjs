// Tests for the tab-local network.
//
// Two halves, and neither of them mocks the thing under test. The stack is
// driven by a guest that speaks the server half of TCP over real frames, built
// from the same wire format the stack encodes with but with its own,
// independent state machine -- so a segment either satisfies a peer that was
// written separately or it does not. The HTTP parser is fed the bytes of a real
// node HTTP server, over a real socket, because a hand-written sample of a
// protocol only proves the parser agrees with whoever wrote the sample.
//
// Run with: node src/test-net.mjs

import http from "node:http";
import net from "node:net";
import { NetStack, STATE } from "./net/stack.js";
import { RequestParser, ResponseParser, encodeRequest, encodeResponse, request, serve } from "./net/http.js";
import {
  ARP_OP, ETHERTYPE, FLAG, ICMP, MSS, PROTO,
  checksum, decodeArp, decodeEthernet, decodeIcmp, decodeIp, decodeTcp,
  encodeArp, encodeEthernet, encodeIp, encodeTcp,
  ipToBytes, ipToString, macToBytes, macToString,
  seqAdd, seqGt, seqLt, tcpChecksumValid
} from "./net/wire.js";

let passed = 0, failed = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log("  PASS  " + name); }
  else { failed++; failures.push(name); console.log("  FAIL  " + name + (detail ? "   [" + detail + "]" : "")); }
}
function eq(name, actual, expected) {
  check(name, JSON.stringify(actual) === JSON.stringify(expected),
        `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

const OUR_MAC = "0e:00:00:00:00:01";
const OUR_IP = "10.0.2.2";
const GUEST_MAC = "52:54:00:12:34:56";
const GUEST_IP = "10.0.2.15";

const enc = new TextEncoder();
const dec = new TextDecoder();
const text = (bytes) => dec.decode(bytes);

// ------------------------------------------------------------------ the wire

console.log("\nthe wire format");
{
  eq("a MAC round trips", macToString(macToBytes(GUEST_MAC)), GUEST_MAC);
  eq("an address round trips", ipToString(ipToBytes(GUEST_IP)), GUEST_IP);
  let rejected = 0;
  for (const bad of ["10.0.2", "10.0.2.256", "not.an.ip.at"]) {
    try { ipToBytes(bad); } catch { rejected++; }
  }
  eq("a malformed address is refused rather than truncated", rejected, 3);

  // The classic property: a header including its own checksum sums to zero.
  const packet = encodeIp({ src: OUR_IP, dst: GUEST_IP, protocol: PROTO.ICMP, payload: new Uint8Array(8) });
  eq("an IP header checksums to zero with its own checksum in place",
     checksum(packet.subarray(0, 20)), 0);

  const frame = encodeEthernet({ dst: GUEST_MAC, src: OUR_MAC, type: ETHERTYPE.ARP, payload: new Uint8Array(28) });
  eq("a short frame is padded to the ethernet minimum", frame.length, 60);
  const eth = decodeEthernet(frame);
  eq("and still decodes", [eth.dst, eth.src, eth.type], [GUEST_MAC, OUR_MAC, ETHERTYPE.ARP]);

  const arp = decodeArp(encodeArp({
    op: ARP_OP.REPLY, senderMac: GUEST_MAC, senderIp: GUEST_IP,
    targetMac: OUR_MAC, targetIp: OUR_IP
  }));
  eq("an ARP reply round trips",
     [arp.op, arp.senderMac, arp.senderIp, arp.targetIp],
     [ARP_OP.REPLY, GUEST_MAC, GUEST_IP, OUR_IP]);
  check("a request that is not ethernet-over-IPv4 is not decoded",
        decodeArp(Uint8Array.from([0, 9, 8, 0, 6, 4, 0, 1, ...new Array(20).fill(0)])) === null);
}
{
  // Ethernet padding on a small packet is the bug this guards: a 20-byte header
  // and 4 bytes of payload is 38 bytes, padded to 60, and a decoder that trusted
  // the frame would hand 26 bytes of zeros on as payload.
  const payload = enc.encode("four");
  const packet = encodeIp({ src: GUEST_IP, dst: OUR_IP, protocol: PROTO.TCP, payload });
  const frame = encodeEthernet({ dst: OUR_MAC, src: GUEST_MAC, type: ETHERTYPE.IPV4, payload: packet });
  eq("the frame really is padded", frame.length, 60);
  const ip = decodeIp(decodeEthernet(frame).payload);
  eq("but the packet's length wins over the frame's", text(ip.payload), "four");
  check("and it is not a fragment", ip.fragmented === false);

  const fragment = new Uint8Array(packet);
  fragment[6] = 0x20;                          // more fragments
  check("a fragment says so, rather than being parsed as whole",
        decodeIp(fragment).fragmented === true);
}
{
  const payload = enc.encode("hello");
  const segment = encodeTcp({
    src: OUR_IP, dst: GUEST_IP, srcPort: 50000, dstPort: 80,
    seq: 7, ack: 9, flags: FLAG.ACK | FLAG.PSH, payload
  });
  const tcp = decodeTcp(segment);
  eq("a segment round trips",
     [tcp.srcPort, tcp.dstPort, tcp.seq, tcp.ack, tcp.flags, text(tcp.payload)],
     [50000, 80, 7, 9, FLAG.ACK | FLAG.PSH, "hello"]);
  check("its checksum validates against the pseudo-header",
        tcpChecksumValid(OUR_IP, GUEST_IP, segment));
  const corrupt = new Uint8Array(segment);
  corrupt[corrupt.length - 1] ^= 0xff;
  check("and fails when a byte is flipped", !tcpChecksumValid(OUR_IP, GUEST_IP, corrupt));

  const syn = encodeTcp({
    src: OUR_IP, dst: GUEST_IP, srcPort: 50000, dstPort: 80, seq: 1, flags: FLAG.SYN, mss: MSS
  });
  eq("a SYN carries options, so its data offset is larger", (syn[12] >>> 4) * 4, 28);
  eq("and the option is the MSS", (syn[22] << 8) | syn[23], MSS);
  eq("which the decoder skips", decodeTcp(syn).payload.length, 0);
}
{
  // Sequence space wraps, and a comparison that used < would read the far side
  // of the wrap as the distant past.
  check("comparison follows the shorter way round the circle", seqLt(0xfffffff0, 0x00000010));
  check("and back again", seqGt(0x00000010, 0xfffffff0));
  eq("addition wraps", seqAdd(0xffffffff, 2), 1);
}

// ----------------------------------------------------------------- the guest
//
// The server half of TCP, written against the wire format rather than against
// the stack. It knows nothing about how the stack tracks its own state.

class Guest {
  constructor({ mac = GUEST_MAC, ip = GUEST_IP, iss = 100000 } = {}) {
    this.mac = mac; this.ip = ip;
    this.inbox = [];              // frames we would put on the wire
    this.received = [];           // payloads accepted on the connection
    this.conn = null;
    this.iss = iss;
    this.autoAck = true;
    this.arpSeen = 0;
    this.pings = 0;
  }

  /** A frame from the stack. */
  feed(frame) {
    const eth = decodeEthernet(frame);
    if (eth.type === ETHERTYPE.ARP) {
      const arp = decodeArp(eth.payload);
      if (arp.op === ARP_OP.REQUEST && arp.targetIp === this.ip) {
        this.arpSeen++;
        this.emit(ETHERTYPE.ARP, encodeArp({
          op: ARP_OP.REPLY, senderMac: this.mac, senderIp: this.ip,
          targetMac: arp.senderMac, targetIp: arp.senderIp
        }), eth.src);
      }
      return;
    }
    const ip = decodeIp(eth.payload);
    if (!ip || ip.dst !== this.ip) return;
    if (ip.protocol === PROTO.ICMP) {
      if (decodeIcmp(ip.payload).type === ICMP.ECHO_REPLY) this.pings++;
      return;
    }
    if (ip.protocol !== PROTO.TCP || this.deaf) return;

    const segment = decodeTcp(ip.payload);
    this.lastSegment = segment;
    if (!tcpChecksumValid(ip.src, ip.dst, ip.payload)) { this.badChecksum = true; return; }

    if ((segment.flags & FLAG.SYN) && (segment.flags & FLAG.ACK)) {
      // The answer to a SYN we sent: finish the handshake.
      this.conn.rcvNxt = seqAdd(segment.seq, 1);
      this.connected = true;
      this.send({ flags: FLAG.ACK });
      return;
    }
    if (segment.flags & FLAG.SYN) {
      this.conn = {
        localPort: segment.dstPort, remotePort: segment.srcPort,
        rcvNxt: seqAdd(segment.seq, 1), sndNxt: this.iss
      };
      this.send({ flags: FLAG.SYN | FLAG.ACK, seq: this.iss, consume: 1 });
      return;
    }
    if (!this.conn || segment.srcPort !== this.conn.remotePort) return;

    if (segment.payload.length && segment.seq === this.conn.rcvNxt) {
      this.received.push(segment.payload);
      this.conn.rcvNxt = seqAdd(this.conn.rcvNxt, segment.payload.length);
      if (this.autoAck) this.send({ flags: FLAG.ACK });
    }
    if (segment.flags & FLAG.FIN) {
      this.conn.rcvNxt = seqAdd(this.conn.rcvNxt, 1);
      this.finSeen = true;
      this.send({ flags: FLAG.ACK });
    }
  }

  /** Open a connection to the stack, the way a program in the guest would. */
  open(port, { from = 40000, iss = 200000 } = {}) {
    this.conn = { localPort: from, remotePort: port, rcvNxt: 0, sndNxt: iss };
    this.connected = false;
    this.send({ flags: FLAG.SYN, seq: iss, consume: 1 });
  }

  /** Application data from the guest's side. */
  write(bytes, { flags = FLAG.ACK | FLAG.PSH } = {}) {
    this.send({ flags, payload: bytes instanceof Uint8Array ? bytes : enc.encode(bytes) });
  }

  finish() { this.send({ flags: FLAG.ACK | FLAG.FIN, consume: 1 }); }

  reset() {
    this.send({ flags: FLAG.RST | FLAG.ACK });
  }

  send({ flags, payload = new Uint8Array(0), seq = null, consume = 0, window = 65535 }) {
    const at = seq === null ? this.conn.sndNxt : seq;
    this.emit(ETHERTYPE.IPV4, encodeIp({
      src: this.ip, dst: OUR_IP, protocol: PROTO.TCP,
      payload: encodeTcp({
        src: this.ip, dst: OUR_IP,
        srcPort: this.conn.localPort, dstPort: this.conn.remotePort,
        seq: at, ack: this.conn.rcvNxt, flags, payload, window
      })
    }));
    this.conn.sndNxt = seqAdd(at, payload.length + consume);
  }

  ping(payload = enc.encode("abcdefgh")) {
    const echo = new Uint8Array(8 + payload.length);
    echo[0] = ICMP.ECHO_REQUEST;
    echo.set(payload, 8);
    const sum = checksum(echo);
    echo[2] = (sum >>> 8) & 0xff; echo[3] = sum & 0xff;
    this.emit(ETHERTYPE.IPV4, encodeIp({ src: this.ip, dst: OUR_IP, protocol: PROTO.ICMP, payload: echo }));
  }

  arpFor(ip) {
    this.emit(ETHERTYPE.ARP, encodeArp({
      op: ARP_OP.REQUEST, senderMac: this.mac, senderIp: this.ip,
      targetMac: "00:00:00:00:00:00", targetIp: ip
    }), "ff:ff:ff:ff:ff:ff");
  }

  emit(type, payload, dst = OUR_MAC) {
    this.inbox.push(encodeEthernet({ dst, src: this.mac, type, payload }));
  }
}

/** A stack wired to a guest, with a clock the test moves by hand. */
function pair(options = {}) {
  const guest = new Guest(options);
  let clock = 0;
  const captured = [];
  const stack = new NetStack({
    mac: OUR_MAC, ip: OUR_IP, peerIp: guest.ip,
    now: () => clock,
    send: (frame) => { captured.push(frame); guest.feed(frame); }
  });
  const deliver = () => {
    // Frames the guest queued, handed over one at a time. Anything the stack
    // sends in response goes to the guest immediately, so one call settles.
    while (guest.inbox.length) stack.receive(guest.inbox.shift());
  };
  return {
    guest, stack, captured, deliver,
    advance(ms) { clock += ms; stack.tick(clock); deliver(); },
    at: () => clock,
    /** The last frame the stack sent, decoded down to TCP. */
    lastTcp() {
      for (let i = captured.length - 1; i >= 0; i--) {
        const eth = decodeEthernet(captured[i]);
        if (eth.type !== ETHERTYPE.IPV4) continue;
        const ip = decodeIp(eth.payload);
        if (ip.protocol === PROTO.TCP) return decodeTcp(ip.payload);
      }
      return null;
    },
    sentTcp() {
      return captured.map(decodeEthernet)
        .filter((e) => e.type === ETHERTYPE.IPV4)
        .map((e) => decodeIp(e.payload))
        .filter((ip) => ip.protocol === PROTO.TCP)
        .map((ip) => decodeTcp(ip.payload));
    }
  };
}

/** Open a connection, settling the handshake. */
async function connected(world, port = 80) {
  const opening = world.stack.connect(port);
  world.deliver();                    // ARP reply, then the SYN goes out
  world.deliver();                    // SYN-ACK
  return opening;
}

// --------------------------------------------------------- addressing and icmp

console.log("\nfinding each other on the segment");
{
  const world = pair();
  world.guest.arpFor(OUR_IP);
  world.deliver();
  const eth = decodeEthernet(world.captured[0]);
  const arp = decodeArp(eth.payload);
  eq("an ARP request for us is answered", arp.op, ARP_OP.REPLY);
  eq("with our MAC", arp.senderMac, OUR_MAC);
  eq("addressed back to the asker", eth.dst, GUEST_MAC);
  eq("and the guest's MAC is learned from it", world.stack.peerMac, GUEST_MAC);

  world.guest.arpFor("10.0.2.99");
  const before = world.captured.length;
  world.deliver();
  eq("an ARP for somebody else is left alone", world.captured.length, before);
}
{
  const world = pair();
  world.guest.ping();
  world.deliver();
  eq("a ping is answered", world.guest.pings, 1);

  const ip = decodeIp(decodeEthernet(world.captured.at(-1)).payload);
  const icmp = decodeIcmp(ip.payload);
  eq("as an echo reply", icmp.type, ICMP.ECHO_REPLY);
  eq("carrying the payload back", text(icmp.rest.subarray(4)), "abcdefgh");
  eq("and its checksum is right", checksum(ip.payload), 0);
}
{
  // Nothing has been heard from the guest, so its MAC is unknown and the first
  // packet cannot be addressed yet.
  const world = pair();
  world.stack.connect(80);
  const first = decodeEthernet(world.captured[0]);
  eq("the first frame of a cold connection is an ARP request", first.type, ETHERTYPE.ARP);
  eq("broadcast", first.dst, "ff:ff:ff:ff:ff:ff");
  eq("and the guest sees it", world.guest.arpSeen, 1);
  world.deliver();
  const tcp = world.sentTcp()[0];
  check("the held SYN goes out once the MAC is known", (tcp.flags & FLAG.SYN) !== 0);
}

// ------------------------------------------------------------------- handshake

console.log("\nopening a connection");
{
  const world = pair();
  const opening = world.stack.connect(8080);
  world.deliver();
  const syn = world.sentTcp()[0];
  eq("the SYN goes to the port asked for", syn.dstPort, 8080);
  eq("from an ephemeral port", syn.srcPort >= 49152, true);
  eq("it is a bare SYN", syn.flags, FLAG.SYN);
  eq("announcing an MSS that fits the link", (syn[0], MSS), MSS);

  world.deliver();
  const socket = await opening;
  eq("the connection opens", socket.state, STATE.ESTABLISHED);
  const ack = world.lastTcp();
  eq("and is acknowledged", ack.flags, FLAG.ACK);
  eq("acknowledging the guest's sequence plus one", ack.ack, seqAdd(world.guest.iss, 1));
}
{
  const world = pair();
  world.guest.arpFor(OUR_IP);
  world.deliver();                         // the MAC is known; the port is not open
  world.guest.deaf = true;
  const opening = world.stack.connect(80, { timeoutMs: 1000 });
  let error = null;
  opening.catch((err) => { error = err; });
  world.advance(1200);
  await Promise.resolve();
  check("a connection nobody answers fails rather than hanging", error !== null);
  check("and says what to look at", /listening/.test(error && error.message || ""), error && error.message);
}
{
  const world = pair();
  world.guest.arpFor(OUR_IP);
  world.deliver();
  // A SYN for a port with nothing behind it, from the guest's side.
  world.guest.conn = { localPort: 40000, remotePort: 55555, rcvNxt: 0, sndNxt: 5 };
  world.guest.send({ flags: FLAG.SYN, seq: 5, consume: 1 });
  world.deliver();
  const rst = world.lastTcp();
  check("a segment for a port we are not using is reset", (rst.flags & FLAG.RST) !== 0);
  eq("and the reset acknowledges the SYN", rst.ack, 6);
}

// ---------------------------------------------------------------------- data

console.log("\ncarrying bytes");
{
  const world = pair();
  const socket = await connected(world);
  socket.write(enc.encode("GET / HTTP/1.1\r\n\r\n"));
  world.deliver();
  eq("what is written arrives", text(world.guest.received[0]), "GET / HTTP/1.1\r\n\r\n");
  const sent = world.lastTcp();
  eq("pushed, and acknowledging the guest", sent.flags, FLAG.ACK | FLAG.PSH);

  const seen = [];
  socket.onData = (bytes) => seen.push(text(bytes));
  world.guest.write("HTTP/1.1 200 OK\r\n");
  world.deliver();
  eq("and what the guest writes comes back", seen, ["HTTP/1.1 200 OK\r\n"]);
  eq("acknowledged", world.lastTcp().flags, FLAG.ACK);
  eq("up to the sequence received", world.lastTcp().ack, seqAdd(world.guest.iss, 1 + 17));
}
{
  const world = pair();
  const socket = await connected(world);
  const big = new Uint8Array(MSS * 2 + 100).fill(65);
  socket.write(big);
  world.deliver();
  const payloads = world.sentTcp().filter((s) => s.payload.length).map((s) => s.payload.length);
  eq("a write larger than the MSS is split at the MSS", payloads, [MSS, MSS, 100]);
  eq("and all of it arrives", world.guest.received.reduce((n, b) => n + b.length, 0), big.length);
}
{
  const world = pair({ });
  const socket = await connected(world);
  // A guest that advertises a small window must not be written past it.
  world.guest.autoAck = false;
  world.guest.send({ flags: FLAG.ACK, window: 100 });
  world.deliver();
  socket.write(new Uint8Array(500).fill(66));
  world.deliver();
  const inFlight = world.guest.received.reduce((n, b) => n + b.length, 0);
  eq("the guest's window is respected", inFlight, 100);

  world.guest.send({ flags: FLAG.ACK, window: 65535 });
  world.deliver();
  eq("and the rest follows when it opens", world.guest.received.reduce((n, b) => n + b.length, 0), 500);
}
{
  const world = pair();
  const socket = await connected(world);
  const seen = [];
  socket.onData = (bytes) => seen.push(text(bytes));

  // Out of order: the second segment first. A stack that dropped it would stall
  // until the guest resent, which on this link would be a long wait.
  const base = world.guest.conn.sndNxt;
  world.guest.send({ flags: FLAG.ACK | FLAG.PSH, seq: seqAdd(base, 5), payload: enc.encode("world") });
  world.deliver();
  eq("a segment ahead of the gap is not delivered yet", seen, []);
  world.guest.send({ flags: FLAG.ACK | FLAG.PSH, seq: base, payload: enc.encode("hello") });
  world.deliver();
  eq("and both arrive in order once the gap is filled", seen.join(""), "helloworld");

  // The same segment again, as a retransmission whose ACK was lost.
  world.guest.send({ flags: FLAG.ACK | FLAG.PSH, seq: base, payload: enc.encode("hello") });
  world.deliver();
  eq("a duplicate is not delivered twice", seen.join(""), "helloworld");
  eq("but is acknowledged again", world.lastTcp().ack, seqAdd(base, 10));
}

// ------------------------------------------------------------- retransmission

console.log("\nwhen a segment goes unanswered");
{
  const world = pair();
  const socket = await connected(world);
  world.guest.autoAck = false;
  socket.write(enc.encode("please repeat"));
  world.deliver();
  eq("it is sent once", world.guest.received.length, 1);

  world.advance(50);
  eq("and not resent before the timeout", world.guest.received.length, 1);
  world.advance(300);
  eq("but is resent after it", world.guest.received.length, 1);   // the guest ignores duplicates of accepted data
  eq("which the stack counts", world.stack.stats.retransmits, 1);

  const resent = world.sentTcp().filter((s) => text(s.payload) === "please repeat");
  eq("the retransmission is the same bytes at the same sequence", resent.length, 2);
  eq("at the same sequence number", resent[0].seq, resent[1].seq);

  world.guest.autoAck = true;
  world.guest.send({ flags: FLAG.ACK });
  world.deliver();
  const before = world.stack.stats.retransmits;
  world.advance(5000);
  eq("and stops once acknowledged", world.stack.stats.retransmits, before);
}
{
  const world = pair();
  const socket = await connected(world);
  let closed = "not yet";
  socket.onClose = (err) => { closed = err ? err.message : null; };
  world.guest.autoAck = false;
  socket.write(enc.encode("into the void"));
  for (let i = 0; i < 12; i++) world.advance(5000);
  check("a peer that never acknowledges eventually fails the connection", typeof closed === "string" && closed !== "not yet");
  check("with a message that names the port", /port 80/.test(closed || ""), closed);
}

// -------------------------------------------------------------------- closing

console.log("\nclosing");
{
  const world = pair();
  const socket = await connected(world);
  let ended = false, closed = "not yet";
  socket.onEnd = () => { ended = true; };
  socket.onClose = (err) => { closed = err ? err.message : null; };

  world.guest.write("the whole body");
  world.guest.finish();
  world.deliver();
  check("the guest's FIN ends the readable side", ended);
  eq("and the connection is not closed yet, since we may still write", closed, "not yet");
  eq("it is in close-wait", socket.state, STATE.CLOSE_WAIT);

  socket.end();
  world.deliver();
  check("our FIN follows", world.guest.finSeen === true);
  eq("and then it is closed", closed, null);
  eq("cleanly", socket.state, STATE.CLOSED);
}
{
  const world = pair();
  const socket = await connected(world);
  let closed = "not yet";
  socket.onClose = (err) => { closed = err ? err.message : null; };
  world.guest.reset();
  world.deliver();
  check("a reset closes the connection with an error", typeof closed === "string" && closed !== "not yet");
  check("that says the guest reset it", /reset by the guest/.test(closed || ""), closed);
  eq("and it is counted", world.stack.stats.resets, 1);
}


// ------------------------------------------------------- the guest as a client

console.log("\ntaking connections from the guest");
{
  const world = pair();
  const taken = [];
  world.stack.listen(80, (socket) => taken.push(socket));

  world.guest.open(80);
  world.deliver();
  eq("a SYN for a listening port is answered", world.guest.connected, true);
  eq("and the connection is handed over once, on the ACK", taken.length, 1);
  eq("established", taken[0].state, STATE.ESTABLISHED);
  eq("on the port that was listening", taken[0].localPort, 80);

  const seen = [];
  taken[0].onData = (bytes) => seen.push(text(bytes));
  world.guest.write("GET /status HTTP/1.0\r\n\r\n");
  world.deliver();
  eq("what the guest sends arrives", seen.join(""), "GET /status HTTP/1.0\r\n\r\n");

  taken[0].write(enc.encode("HTTP/1.1 200 OK\r\n\r\nrunning"));
  taken[0].end();
  world.deliver();
  eq("and what we answer reaches the guest",
     world.guest.received.map(text).join(""), "HTTP/1.1 200 OK\r\n\r\nrunning");
  check("closed by a FIN", world.guest.finSeen === true);
}
{
  const world = pair();
  world.stack.listen(80, () => {});
  world.guest.open(81, { from: 40001 });
  world.deliver();
  const rst = world.lastTcp();
  check("a SYN for a port nobody listens on is refused", (rst.flags & FLAG.RST) !== 0);
  eq("and not left to time out", world.guest.connected, false);
}
{
  // Two programs in the guest, one listening port. A connection is identified by
  // both ends, not by ours alone.
  const world = pair();
  const taken = [];
  world.stack.listen(80, (socket) => taken.push(socket));

  world.guest.open(80, { from: 40010, iss: 300000 });
  world.deliver();
  const first = world.guest.conn;
  world.guest.open(80, { from: 40011, iss: 400000 });
  world.deliver();
  eq("both connections are accepted", taken.length, 2);
  check("and they are different sockets", taken[0] !== taken[1]);
  eq("distinguished by the remote port", [taken[0].remotePort, taken[1].remotePort], [40010, 40011]);

  const seen = [[], []];
  taken[0].onData = (b) => seen[0].push(text(b));
  taken[1].onData = (b) => seen[1].push(text(b));
  world.guest.write("second");                       // the current one
  world.deliver();
  world.guest.conn = first;
  world.guest.write("first");
  world.deliver();
  eq("each connection gets its own bytes", [seen[0].join(""), seen[1].join("")], ["first", "second"]);
}
{
  const world = pair();
  const listener = world.stack.listen(80, () => {});
  listener.close();
  world.guest.open(80, { from: 40020 });
  world.deliver();
  check("a closed listener refuses what it used to take",
        (world.lastTcp().flags & FLAG.RST) !== 0);
  let again = null;
  try { world.stack.listen(80, () => {}); } catch (err) { again = err.message; }
  check("and the port can be listened on again", again === null, again);
}

// ----------------------------------------------------------------------- http

console.log("\nthe HTTP request writer");
{
  const bytes = encodeRequest({ method: "get", path: "/index.html", host: GUEST_IP });
  const written = text(bytes);
  check("the method is upper-cased", written.startsWith("GET /index.html HTTP/1.1\r\n"));
  check("1.1 requires a Host, so one is always sent", written.includes(`Host: ${GUEST_IP}\r\n`));
  check("and the connection is closed after one request", written.includes("Connection: close\r\n"));
  check("the head ends with a blank line", written.endsWith("\r\n\r\n"));

  const posted = text(encodeRequest({ method: "POST", path: "/", host: GUEST_IP, body: "name=value" }));
  check("a body brings its length", posted.includes("Content-Length: 10\r\n"));
  check("and follows the head", posted.endsWith("\r\n\r\nname=value"));

  const custom = text(encodeRequest({
    method: "GET", path: "/", host: GUEST_IP, headers: { Host: "example.test", Accept: "text/html" }
  }));
  eq("a caller's Host wins over the default", (custom.match(/Host:/g) || []).length, 1);
  check("and it is theirs", custom.includes("Host: example.test"));
}

console.log("\nwhat a shell script writes");
{
  // What a CGI script actually writes. `echo` ends a line with one byte, so the
  // headers a shell prints are separated by line feeds and the blank line that
  // ends them is one byte too. Insisting on CRLF turns that into "the guest
  // closed the connection before sending a complete response", which is a
  // confusing way to be told a script printed a newline.
  const parser = new ResponseParser();
  parser.push(enc.encode("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>hi</h1>"));
  parser.end();
  eq("headers ending in bare line feeds parse", [parser.status, parser.headers["content-type"]],
     [200, "text/html"]);
  eq("and the body is the body", text(parser.body()), "<h1>hi</h1>");
  check("with no error", parser.error === null);

  const mixed = new ResponseParser();
  mixed.push(enc.encode("HTTP/1.1 200 OK\r\nContent-Type: text/plain\nContent-Length: 2\r\n\r\nok"));
  eq("so do headers that mix the two", [mixed.status, mixed.done, text(mixed.body())], [200, true, "ok"]);

  const chunked = new ResponseParser();
  chunked.push(enc.encode("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n5\nhello\n0\n\n"));
  eq("and a chunked body counted out with line feeds", text(chunked.body()), "hello");
  check("which is complete", chunked.done);

  const request = new RequestParser();
  request.push(enc.encode("GET /status HTTP/1.1\nHost: 10.0.2.2\n\n"));
  eq("a request written the same way parses too", [request.method, request.path, request.done],
     ["GET", "/status", true]);
}

console.log("\nthe response parser, against a real server");
{
  // node writes the responses; we read the raw bytes off a real socket. What is
  // being tested is agreement with a server nobody here wrote.
  const server = http.createServer((req, res) => {
    if (req.url === "/length") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("a body of a known length");
    } else if (req.url === "/chunked") {
      res.writeHead(200, { "Content-Type": "text/plain" });   // no length: node chunks it
      res.write("first ");
      res.write("second ");
      res.end("third");
    } else if (req.url === "/empty") {
      res.writeHead(204).end();
    } else if (req.url === "/headers") {
      res.writeHead(201, { "X-One": "1", "Set-Cookie": "a=1", "Content-Length": "2" });
      res.end("hi");
    } else {
      res.writeHead(404, { "Content-Length": "9" }).end("not found");
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  const raw = (path) => new Promise((resolve, reject) => {
    const chunks = [];
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`);
    });
    socket.on("data", (c) => chunks.push(new Uint8Array(c)));
    socket.on("error", reject);
    socket.on("close", () => resolve(chunks));
  });

  const parse = (chunks, { byByte = false } = {}) => {
    const parser = new ResponseParser();
    for (const chunk of chunks) {
      if (!byByte) { parser.push(chunk); continue; }
      for (let i = 0; i < chunk.length; i++) parser.push(chunk.subarray(i, i + 1));
    }
    parser.end();
    return parser;
  };

  {
    const parser = parse(await raw("/length"));
    eq("a length-delimited response parses", [parser.status, parser.done, text(parser.body())],
       [200, true, "a body of a known length"]);
    eq("with its headers lower-cased", parser.headers["content-type"], "text/plain");
    check("and no error", parser.error === null);
  }
  {
    const chunks = await raw("/chunked");
    const joined = text(chunks.reduce((a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }, new Uint8Array(0)));
    check("node really did chunk it", /transfer-encoding: chunked/i.test(joined));
    const parser = parse(chunks);
    eq("a chunked response is reassembled", text(parser.body()), "first second third");
    check("and is complete before the close", parser.done);
  }
  {
    const parser = parse(await raw("/chunked"), { byByte: true });
    eq("fed one byte at a time it says the same", text(parser.body()), "first second third");
    check("and is still complete", parser.done && parser.error === null);
  }
  {
    const parser = parse(await raw("/empty"));
    eq("a 204 is complete with no body at all", [parser.status, parser.done, parser.body().length], [204, true, 0]);
  }
  {
    const parser = parse(await raw("/headers"));
    eq("the status line's code and reason are kept", [parser.status, parser.statusText], [201, "Created"]);
    eq("and every header", [parser.headers["x-one"], parser.headers["set-cookie"]], ["1", "a=1"]);
  }
  {
    const parser = parse(await raw("/missing"));
    eq("an error status is a response like any other", [parser.status, text(parser.body())], [404, "not found"]);
  }
  server.close();

  // A body delimited by nothing but the close. HTTP/1.0 servers do this, and so
  // does anything hand-written by somebody in a hurry -- which, in a guest, is
  // the likely case.
  const bare = net.createServer((socket) => {
    socket.end("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the close");
  });
  await new Promise((r) => bare.listen(0, "127.0.0.1", r));
  const chunks = await new Promise((resolve) => {
    const seen = [];
    const socket = net.connect(bare.address().port, "127.0.0.1", () => socket.write("GET / HTTP/1.1\r\n\r\n"));
    socket.on("data", (c) => seen.push(new Uint8Array(c)));
    socket.on("close", () => resolve(seen));
  });
  const parser = parse(chunks);
  eq("a body framed only by the close is taken whole", text(parser.body()), "until the close");
  check("and the close completed it", parser.done);
  bare.close();

  const truncated = new ResponseParser();
  truncated.push(enc.encode("HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nonly this much"));
  truncated.end();
  check("a response cut short is an error, not a short body", truncated.error !== null);
  check("naming what is missing", /still to come/.test(truncated.error.message), truncated.error.message);
}


// ------------------------------------------------- answering the guest's HTTP

console.log("\nHTTP the other way round");
{
  const parser = new RequestParser();
  parser.push(enc.encode("GET /serve?dir=/disk/www&port=80 HTTP/1.1\r\nHost: 10.0.2.2\r\n\r\n"));
  eq("a request line parses", [parser.method, parser.path], ["GET", "/serve"]);
  eq("with its query kept apart", parser.query.get("dir"), "/disk/www");
  eq("and every parameter", parser.query.get("port"), "80");
  check("a request with no body is complete at the blank line", parser.done);

  const withBody = new RequestParser();
  withBody.push(enc.encode("POST /sync HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe"));
  check("a body still arriving is not complete", !withBody.done);
  withBody.push(enc.encode("llo"));
  check("and is once it has", withBody.done);
  eq("carrying the bytes", text(withBody.body()), "hello");

  const bad = new RequestParser();
  bad.push(enc.encode("nonsense\r\n\r\n"));
  check("something that is not a request is an error", bad.error !== null);
}
{
  const response = text(encodeResponse({ status: 200, body: "running\n" }));
  check("a response carries a status line", response.startsWith("HTTP/1.1 200 OK\r\n"));
  check("its length", response.includes("Content-Length: 8\r\n"));
  check("and closes the connection", response.includes("Connection: close\r\n"));
  check("the body follows the head", response.endsWith("\r\n\r\nrunning\n"));
  eq("a status with no body says so", encodeResponse({ status: 204 }).length > 0, true);
}
{
  // The whole loop: a program in the guest asks the tab a question.
  const world = pair();
  const asked = [];
  serve(world.stack, {
    port: 80,
    handler: (req) => {
      asked.push(`${req.method} ${req.path}`);
      if (req.path === "/status") return "serving /disk/www\n";
      if (req.path === "/sync") return { status: 200, body: `synced ${req.query.get("message")}\n` };
      return { status: 404, body: "no such command\n" };
    }
  });

  world.guest.open(80);
  world.deliver();
  world.guest.write("GET /status HTTP/1.1\r\nHost: 10.0.2.2\r\n\r\n");
  world.deliver();
  await Promise.resolve();
  world.deliver();
  eq("the handler saw the request", asked, ["GET /status"]);
  const answer = world.guest.received.map(text).join("");
  check("and answered it", answer.includes("200 OK"), answer.slice(0, 40));
  check("with the body", answer.endsWith("serving /disk/www\n"));

  const second = pair();
  serve(second.stack, { port: 80, handler: (req) => `ran ${req.path} ${req.query.get("message") || ""}` });
  second.guest.open(80);
  second.deliver();
  second.guest.write("GET /sync?message=hello%20there HTTP/1.1\r\n\r\n");
  second.deliver();
  await Promise.resolve();
  second.deliver();
  const body = second.guest.received.map(text).join("");
  check("a query parameter arrives decoded", body.endsWith("ran /sync hello there"), body.slice(-40));
}
{
  const world = pair();
  serve(world.stack, { port: 80, handler: () => { throw new Error("the disk is not mounted"); } });
  world.guest.open(80);
  world.deliver();
  world.guest.write("GET /serve HTTP/1.1\r\n\r\n");
  world.deliver();
  await Promise.resolve();
  world.deliver();
  const answer = world.guest.received.map(text).join("");
  check("a handler that throws is a 500, not a hang", answer.includes("500"));
  check("carrying the reason, which is what a shell shows", answer.endsWith("the disk is not mounted\n"));
}

// -------------------------------------------------------------- end to end

console.log("\na request into the guest, over frames");
{
  const world = pair();
  // A guest that serves one HTTP response, at the wire level, with no knowledge
  // of the stack that is talking to it.
  const guest = world.guest;
  const pending = request(world.stack, { port: 80, path: "/hello.html" });

  world.deliver();   // ARP
  world.deliver();   // SYN -> SYN-ACK
  await Promise.resolve();
  world.deliver();   // the request

  const asked = text(guest.received.map(text).join("") ? enc.encode(guest.received.map(text).join("")) : new Uint8Array(0));
  check("the guest received a request", asked.startsWith("GET /hello.html HTTP/1.1\r\n"), asked.slice(0, 40));
  check("with a Host header", /\r\nHost: 10\.0\.2\.15\r\n/.test(asked));

  const body = "<!doctype html><title>from the guest</title>";
  guest.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
  world.deliver();
  const response = await pending;

  eq("the response comes back", response.status, 200);
  eq("with its headers", response.headers["content-type"], "text/html");
  eq("and its body", text(response.body), body);

  guest.finish();
  world.deliver();
  eq("and the connection ends up closed", world.stack._connections.size, 0);
}
{
  // The same path, but the guest answers in fragments across several segments,
  // which is what a real server writing a file does.
  const world = pair();
  const guest = world.guest;
  const pending = request(world.stack, { port: 8080, path: "/split" });
  world.deliver(); world.deliver();
  await Promise.resolve();
  world.deliver();

  const body = "x".repeat(3000);
  const head = `HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n`;
  guest.write(head + body.slice(0, 500));
  world.deliver();
  guest.write(body.slice(500, 2000));
  world.deliver();
  guest.write(body.slice(2000));
  world.deliver();

  const response = await pending;
  eq("a body split across segments is reassembled", response.body.length, 3000);
  eq("in order", text(response.body).slice(0, 4), "xxxx");
  check("and it is the same bytes", text(response.body) === body);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
process.exit(0);
