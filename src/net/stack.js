// A TCP/IP stack that lives in the tab.
//
// The guest thinks it has a NIC on a quiet ethernet segment with one other host
// on it. That other host is this file. Nothing here reaches the network: a
// frame the guest transmits is handed to us as bytes, and a frame we transmit is
// handed back. So the guest gets real sockets whose far end is a function call,
// and the tab gets a way into a server running inside the guest without anybody
// hosting a relay.
//
// We are always the client. The guest listens; we connect. That removes the
// whole passive-open half of TCP -- no backlog, no accept queue, no SYN
// cookies -- and what is left is small enough to read in one sitting.
//
// Two things a real stack has are missing on purpose. There is no congestion
// control, because the path is a function call and there is nothing to congest;
// flow control by the peer's advertised window is kept, because the guest means
// it. And there is no reassembly of IP fragments, because we set DF and the link
// has a 1500-byte MTU on both sides, so a fragment here is a bug, not a packet.
//
// The clock is injected. Retransmission is the one behaviour that cannot be
// tested by inspecting a frame, and a stack that reads Date.now() directly can
// only be tested by waiting.

import {
  ARP_OP, BROADCAST_MAC, ETHERTYPE, FLAG, ICMP, MSS, PROTO,
  decodeArp, decodeEthernet, decodeIcmp, decodeIp, decodeTcp,
  encodeArp, encodeEthernet, encodeIp, encodeTcp,
  icmpEchoReply, seqAdd, seqGt, seqGte, seqLt, seqLte, tcpChecksumValid
} from "./wire.js";

export const STATE = {
  SYN_SENT: "syn-sent",
  SYN_RCVD: "syn-received",     // we answered a SYN and are waiting for its ACK
  ESTABLISHED: "established",
  CLOSE_WAIT: "close-wait",     // peer is done sending; we may still write
  FIN_WAIT: "fin-wait",         // we are done sending; peer may still write
  CLOSING: "closing",           // both sides have sent a FIN
  CLOSED: "closed"
};

const EPHEMERAL_FIRST = 49152;
const EPHEMERAL_LAST = 65535;
const RTO_INITIAL = 200;
const RTO_MAX = 4000;
const MAX_RETRIES = 8;
const RECEIVE_WINDOW = 65535;
// How long to keep a connection whose FIN was acknowledged but whose peer has
// not sent its own. A well-behaved server closes; this is for one that does not.
const LINGER = 10000;

export class NetStack {
  /**
   * @param {Object} options
   * @param {string} options.mac our MAC, the one the guest will ARP for
   * @param {string} options.ip our address on the segment
   * @param {string} options.peerIp the guest's address
   * @param {(frame: Uint8Array) => void} options.send hands a frame to the NIC
   * @param {() => number} [options.now] injected clock, in milliseconds
   * @param {(event: Object) => void} [options.onEvent]
   */
  constructor({ mac, ip, peerIp, send, now = () => Date.now(), onEvent }) {
    if (typeof send !== "function") throw new Error("a send function is required");
    this.mac = mac;
    this.ip = ip;
    this.peerIp = peerIp;
    this._send = send;
    this._now = now;
    this.onEvent = onEvent || (() => {});

    this.peerMac = null;
    this._pendingArp = [];              // frames waiting on the peer's MAC
    this._connections = new Map();      // "localPort:remotePort" -> connection
    this._listeners = new Map();        // local port -> handler, for connections we accept
    this._nextPort = EPHEMERAL_FIRST;
    this.stats = { rx: 0, tx: 0, retransmits: 0, resets: 0, connections: 0, accepted: 0 };
  }

  // --- inbound ---------------------------------------------------------------

  /** A frame the guest put on the wire. */
  receive(frame) {
    this.stats.rx++;
    const eth = decodeEthernet(frame);
    if (!eth) return;
    // Ours, or broadcast. A NIC in promiscuous mode would see more; we are not.
    if (eth.dst !== this.mac && eth.dst !== BROADCAST_MAC) return;

    if (eth.type === ETHERTYPE.ARP) return this._onArp(eth);
    if (eth.type !== ETHERTYPE.IPV4) return;

    const ip = decodeIp(eth.payload);
    if (!ip || ip.dst !== this.ip || ip.fragmented) return;
    this._learn(ip.src, eth.src);

    if (ip.protocol === PROTO.ICMP) return this._onIcmp(ip);
    if (ip.protocol === PROTO.TCP) return this._onTcp(ip);
  }

  _onArp(eth) {
    const arp = decodeArp(eth.payload);
    if (!arp) return;
    this._learn(arp.senderIp, arp.senderMac);
    if (arp.op !== ARP_OP.REQUEST || arp.targetIp !== this.ip) return;
    this._transmit(encodeEthernet({
      dst: arp.senderMac, src: this.mac, type: ETHERTYPE.ARP,
      payload: encodeArp({
        op: ARP_OP.REPLY,
        senderMac: this.mac, senderIp: this.ip,
        targetMac: arp.senderMac, targetIp: arp.senderIp
      })
    }));
  }

  _onIcmp(ip) {
    const icmp = decodeIcmp(ip.payload);
    // Echo is the whole of it. A ping that answers is the cheapest proof the
    // guest's NIC, its routing table and this stack all agree.
    if (!icmp || icmp.type !== ICMP.ECHO_REQUEST) return;
    this._sendIp(ip.src, PROTO.ICMP, icmpEchoReply(ip.payload));
  }

  _onTcp(ip) {
    const segment = decodeTcp(ip.payload);
    if (!segment) return;
    // A corrupt segment is indistinguishable from one meant for someone else.
    if (!tcpChecksumValid(ip.src, ip.dst, ip.payload)) return;

    const conn = this._connections.get(`${segment.dstPort}:${segment.srcPort}`);
    if (!conn || conn.state === STATE.CLOSED) {
      // A SYN for a port we are listening on opens a connection; anything else
      // for a port nobody holds is refused, rather than left to time out.
      if ((segment.flags & FLAG.SYN) && !(segment.flags & FLAG.ACK) &&
          this._listeners.has(segment.dstPort)) {
        return this._accept(segment);
      }
      if (!(segment.flags & FLAG.RST)) this._reset(ip.src, segment);
      return;
    }

    if (segment.flags & FLAG.RST) {
      this.stats.resets++;
      return this._teardown(conn, new Error(`connection reset by the guest on port ${conn.remotePort}`));
    }

    if (conn.state === STATE.SYN_SENT) return this._onSynAck(conn, segment);
    if (conn.state === STATE.SYN_RCVD) return this._onHandshakeAck(conn, segment);

    // Everything past the handshake: acknowledge what is ours, take what is new.
    if (segment.flags & FLAG.ACK) this._onAck(conn, segment);
    if (segment.payload.length) this._onData(conn, segment);
    if (segment.flags & FLAG.FIN) this._onFin(conn, segment);
    this._pump(conn);
  }

  _onSynAck(conn, segment) {
    if (!(segment.flags & FLAG.SYN) || !(segment.flags & FLAG.ACK)) return;
    if (segment.ack !== conn.sndNxt) return;   // not an answer to our SYN

    conn.sndUna = segment.ack;
    conn.unacked = [];
    conn.rcvNxt = seqAdd(segment.seq, 1);
    conn.peerWindow = segment.window;
    conn.state = STATE.ESTABLISHED;
    conn.rto = RTO_INITIAL;
    this._ack(conn);
    this.stats.connections++;
    conn.socket.opened = true;
    this.onEvent({ type: "connected", port: conn.remotePort });
    conn.resolve(conn.socket);
    this._pump(conn);
  }

  /**
   * Answer a SYN for a port we are listening on.
   *
   * The mirror image of connect(): the sequence numbers start here rather than
   * there, and the connection is not handed to the caller until the ACK that
   * completes the handshake arrives, so a caller never sees a half-open one.
   */
  _accept(segment) {
    const iss = (Math.random() * 0xffffffff) >>> 0;
    const conn = {
      localPort: segment.dstPort, remotePort: segment.srcPort,
      state: STATE.SYN_RCVD,
      iss, sndUna: iss, sndNxt: iss, rcvNxt: seqAdd(segment.seq, 1),
      peerWindow: segment.window || MSS,
      outbox: [], unacked: [], ooo: new Map(),
      finSeq: null, finAcked: false, peerFin: false, wantsFin: false, lingerUntil: null,
      rto: RTO_INITIAL,
      deadline: this._now() + 30000,
      resolve: null, reject: null, socket: null,
      accepted: true
    };
    conn.socket = new TcpSocket(this, conn);
    this._connections.set(`${conn.localPort}:${conn.remotePort}`, conn);
    this._emit(conn, { flags: FLAG.SYN | FLAG.ACK, mss: MSS });
  }

  /** The third segment of an inbound handshake. */
  _onHandshakeAck(conn, segment) {
    if (!(segment.flags & FLAG.ACK) || segment.ack !== conn.sndNxt) return;
    conn.sndUna = segment.ack;
    conn.unacked = [];
    conn.state = STATE.ESTABLISHED;
    conn.rto = RTO_INITIAL;
    conn.socket.opened = true;
    this.stats.accepted++;
    this.onEvent({ type: "accepted", port: conn.localPort });

    const handler = this._listeners.get(conn.localPort);
    if (handler) handler(conn.socket);

    // Data can ride the same segment that completes the handshake.
    if (segment.payload.length) this._onData(conn, segment);
    if (segment.flags & FLAG.FIN) this._onFin(conn, segment);
    this._pump(conn);
  }

  /**
   * Take connections on a port.
   *
   * This is what lets the guest talk to the tab rather than only the other way
   * round: the guest's own tooling can reach a control plane running here, the
   * way an instance in a cloud reaches a metadata service on a link-local
   * address it did not have to be told about.
   *
   * @param {number} port
   * @param {(socket: TcpSocket) => void} onConnection
   * @returns {{port: number, close: () => void}}
   */
  listen(port, onConnection) {
    if (typeof onConnection !== "function") throw new Error("a connection handler is required");
    if (this._listeners.has(port)) throw new Error(`already listening on port ${port}`);
    this._listeners.set(port, onConnection);
    this.onEvent({ type: "listening", port });
    return {
      port,
      close: () => {
        this._listeners.delete(port);
        for (const conn of [...this._connections.values()]) {
          if (conn.localPort === port && conn.accepted) this._destroy(conn);
        }
        this.onEvent({ type: "unlistened", port });
      }
    };
  }

  _onAck(conn, segment) {
    if (seqGt(segment.ack, conn.sndNxt)) return;      // acknowledging what we never sent
    if (seqGt(segment.ack, conn.sndUna)) {
      conn.sndUna = segment.ack;
      conn.unacked = conn.unacked.filter((s) => seqGt(seqAdd(s.seq, s.length), segment.ack));
      conn.rto = RTO_INITIAL;                         // progress resets the backoff
    }
    conn.peerWindow = segment.window;
    if (conn.finSeq !== null && seqGte(conn.sndUna, seqAdd(conn.finSeq, 1))) conn.finAcked = true;
    this._maybeClose(conn);
  }

  _onData(conn, segment) {
    const end = seqAdd(segment.seq, segment.payload.length);
    // Entirely in the past: a retransmission of something we already took. The
    // ACK that would have stopped it was lost, so send another.
    if (seqLte(end, conn.rcvNxt)) return this._ack(conn);

    if (segment.seq === conn.rcvNxt) {
      this._deliver(conn, segment.payload);
      conn.rcvNxt = end;
      this._drainOutOfOrder(conn);
    } else if (seqGt(segment.seq, conn.rcvNxt)) {
      // A gap. Hold the segment rather than dropping it: the guest would resend,
      // but holding turns one lost segment into one retransmission instead of a
      // stall for everything queued behind it.
      conn.ooo.set(segment.seq, segment.payload);
    } else {
      // Overlaps the boundary: keep only the part we have not seen.
      this._deliver(conn, segment.payload.subarray((conn.rcvNxt - segment.seq) >>> 0));
      conn.rcvNxt = end;
      this._drainOutOfOrder(conn);
    }
    this._ack(conn);
  }

  _drainOutOfOrder(conn) {
    for (;;) {
      const held = conn.ooo.get(conn.rcvNxt);
      if (!held) return;
      conn.ooo.delete(conn.rcvNxt);
      this._deliver(conn, held);
      conn.rcvNxt = seqAdd(conn.rcvNxt, held.length);
    }
  }

  _deliver(conn, bytes) {
    if (!bytes.length) return;
    conn.socket._data(new Uint8Array(bytes));
  }

  _onFin(conn, segment) {
    // Only the FIN that closes the sequence we have actually received. A FIN
    // arriving ahead of data still in flight is acknowledged by the gap, not by
    // ending the stream early.
    if (segment.seq !== conn.rcvNxt) return;
    conn.rcvNxt = seqAdd(conn.rcvNxt, 1);
    conn.peerFin = true;
    this._ack(conn);
    conn.state = conn.finSeq === null ? STATE.CLOSE_WAIT : STATE.CLOSING;
    conn.socket._end();
    this._maybeClose(conn);
  }

  // --- outbound --------------------------------------------------------------

  /**
   * Open a connection to a port in the guest.
   * @param {number} port
   * @param {Object} [options]
   * @param {number} [options.timeoutMs]
   * @returns {Promise<TcpSocket>}
   */
  connect(port, { timeoutMs = 10000 } = {}) {
    const localPort = this._allocatePort();
    const iss = (Math.random() * 0xffffffff) >>> 0;
    const conn = {
      localPort, remotePort: port,
      state: STATE.SYN_SENT,
      iss, sndUna: iss, sndNxt: iss, rcvNxt: 0,
      peerWindow: MSS,
      outbox: [],            // bytes the caller has written, not yet sent
      unacked: [],           // segments sent, not yet acknowledged
      ooo: new Map(),
      finSeq: null, finAcked: false, peerFin: false, wantsFin: false, lingerUntil: null,
      rto: RTO_INITIAL,
      deadline: this._now() + timeoutMs,
      resolve: null, reject: null,
      socket: null
    };
    conn.socket = new TcpSocket(this, conn);
    this._connections.set(`${localPort}:${port}`, conn);

    const opened = new Promise((resolve, reject) => {
      conn.resolve = resolve;
      conn.reject = reject;
    });
    this._emit(conn, { flags: FLAG.SYN, mss: MSS });
    return opened;
  }

  /** Queue bytes for a connection. Called by the socket. */
  _write(conn, bytes) {
    if (conn.state === STATE.CLOSED) throw new Error("the connection is closed");
    if (conn.finSeq !== null) throw new Error("the connection is already half-closed");
    if (bytes.length) conn.outbox.push(bytes);
    this._pump(conn);
  }

  /** Send everything the peer's window has room for, then a FIN if one is due. */
  _pump(conn) {
    if (conn.state !== STATE.ESTABLISHED && conn.state !== STATE.CLOSE_WAIT) return;

    while (conn.outbox.length) {
      const inFlight = (conn.sndNxt - conn.sndUna) >>> 0;
      const room = Math.min(conn.peerWindow - inFlight, MSS);
      if (room <= 0) return;                        // the guest's window is full

      const payload = this._take(conn, room);
      if (!payload.length) return;
      this._emit(conn, { flags: FLAG.ACK | FLAG.PSH, payload });
    }

    if (conn.wantsFin && conn.finSeq === null) {
      conn.finSeq = conn.sndNxt;
      this._emit(conn, { flags: FLAG.ACK | FLAG.FIN });
      conn.state = conn.peerFin ? STATE.CLOSING : STATE.FIN_WAIT;
    }
  }

  /** Pull up to `limit` bytes off the outbox, splitting a buffer if it straddles. */
  _take(conn, limit) {
    const out = new Uint8Array(Math.min(limit, conn.outbox.reduce((n, b) => n + b.length, 0)));
    let filled = 0;
    while (filled < out.length) {
      const head = conn.outbox[0];
      const take = Math.min(head.length, out.length - filled);
      out.set(head.subarray(0, take), filled);
      filled += take;
      if (take === head.length) conn.outbox.shift();
      else conn.outbox[0] = head.subarray(take);
    }
    return out;
  }

  /** Build a segment, remember it if it needs acknowledging, and put it on the wire. */
  _emit(conn, { flags, payload = new Uint8Array(0), mss = null }) {
    const seq = conn.sndNxt;
    const length = payload.length + ((flags & FLAG.SYN) || (flags & FLAG.FIN) ? 1 : 0);
    const segment = encodeTcp({
      src: this.ip, dst: this.peerIp,
      srcPort: conn.localPort, dstPort: conn.remotePort,
      seq, ack: conn.rcvNxt, flags, window: RECEIVE_WINDOW, payload, mss
    });
    conn.sndNxt = seqAdd(seq, length);
    if (length) {
      conn.unacked.push({ seq, length, flags, payload, mss, sentAt: this._now(), tries: 0 });
    }
    this._sendIp(this.peerIp, PROTO.TCP, segment);
  }

  /** A bare acknowledgement. It carries no sequence space, so it is never resent. */
  _ack(conn) {
    this._sendIp(this.peerIp, PROTO.TCP, encodeTcp({
      src: this.ip, dst: this.peerIp,
      srcPort: conn.localPort, dstPort: conn.remotePort,
      seq: conn.sndNxt, ack: conn.rcvNxt, flags: FLAG.ACK, window: RECEIVE_WINDOW
    }));
  }

  /** Refuse a segment nobody is listening for. */
  _reset(dstIp, segment) {
    const acked = (segment.flags & FLAG.ACK) !== 0;
    this._sendIp(dstIp, PROTO.TCP, encodeTcp({
      src: this.ip, dst: dstIp,
      srcPort: segment.dstPort, dstPort: segment.srcPort,
      seq: acked ? segment.ack : 0,
      ack: seqAdd(segment.seq, segment.payload.length + ((segment.flags & FLAG.SYN) ? 1 : 0)),
      flags: acked ? FLAG.RST : (FLAG.RST | FLAG.ACK),
      window: 0
    }));
  }

  _sendIp(dst, protocol, payload) {
    const packet = encodeIp({ src: this.ip, dst, protocol, payload, id: (this.stats.tx & 0xffff) });
    const frame = (mac) => encodeEthernet({ dst: mac, src: this.mac, type: ETHERTYPE.IPV4, payload: packet });
    if (this.peerMac) return this._transmit(frame(this.peerMac));

    // We have never heard from the guest. Ask who it is and hold the packet;
    // dropping it would work too, but the first connection would always cost a
    // retransmission and the first ping would silently vanish.
    this._pendingArp.push(frame);
    if (this._pendingArp.length === 1) this._arpFor(dst);
  }

  _arpFor(ip) {
    this._transmit(encodeEthernet({
      dst: BROADCAST_MAC, src: this.mac, type: ETHERTYPE.ARP,
      payload: encodeArp({
        op: ARP_OP.REQUEST,
        senderMac: this.mac, senderIp: this.ip,
        targetMac: "00:00:00:00:00:00", targetIp: ip
      })
    }));
  }

  _learn(ip, mac) {
    if (ip !== this.peerIp || this.peerMac === mac) return;
    this.peerMac = mac;
    this.onEvent({ type: "peer", ip, mac });
    const waiting = this._pendingArp;
    this._pendingArp = [];
    for (const frame of waiting) this._transmit(frame(mac));
  }

  _transmit(frame) {
    this.stats.tx++;
    this._send(frame);
  }

  // --- time ------------------------------------------------------------------

  /**
   * Retransmit what has gone unanswered, and fail what never will.
   *
   * Call it on a timer in the browser, or by hand in a test. Nothing else in
   * this file reads the clock, so a test can move time in one line.
   */
  tick(now = this._now()) {
    for (const conn of [...this._connections.values()]) {
      if (conn.lingerUntil !== null && now > conn.lingerUntil) {
        this._teardown(conn, null);
        continue;
      }
      if ((conn.state === STATE.SYN_SENT || conn.state === STATE.SYN_RCVD) && now > conn.deadline) {
        this._teardown(conn, new Error(
          `nothing answered on port ${conn.remotePort} in the guest. Is something ` +
          `listening, and is the guest's route to ${this.ip} up?`
        ));
        continue;
      }
      for (const segment of conn.unacked) {
        if (now - segment.sentAt < conn.rto) continue;
        if (segment.tries >= MAX_RETRIES) {
          // A SYN that ran out of tries is a different situation from data that
          // did, and the difference is the one a caller acts on: nothing is
          // listening, rather than a connection that stopped being answered.
          this._teardown(conn, new Error(conn.state === STATE.SYN_SENT
            ? `nothing answered on port ${conn.remotePort} in the guest. Is something ` +
              `listening, and is the guest's route to ${this.ip} up?`
            : `no acknowledgement after ${MAX_RETRIES} attempts on port ${conn.remotePort}`
          ));
          break;
        }
        segment.tries++;
        segment.sentAt = now;
        this.stats.retransmits++;
        this._sendIp(this.peerIp, PROTO.TCP, encodeTcp({
          src: this.ip, dst: this.peerIp,
          srcPort: conn.localPort, dstPort: conn.remotePort,
          seq: segment.seq, ack: conn.rcvNxt, flags: segment.flags,
          window: RECEIVE_WINDOW, payload: segment.payload, mss: segment.mss
        }));
        conn.rto = Math.min(conn.rto * 2, RTO_MAX);
        break;                      // one segment per tick; the ACK decides the rest
      }
    }
  }

  // --- closing ---------------------------------------------------------------

  _finish(conn) {
    conn.wantsFin = true;
    this._pump(conn);
    this._maybeClose(conn);
  }

  _maybeClose(conn) {
    if (conn.state === STATE.CLOSED) return;
    if (conn.peerFin && conn.finAcked) this._teardown(conn, null);
    else if (conn.finAcked && conn.lingerUntil === null) conn.lingerUntil = this._now() + LINGER;
  }

  _teardown(conn, error) {
    if (conn.state === STATE.CLOSED) return;
    conn.state = STATE.CLOSED;
    conn.unacked = [];
    this._connections.delete(`${conn.localPort}:${conn.remotePort}`);
    if (conn.reject && !conn.socket.opened) conn.reject(error || new Error("closed before opening"));
    conn.socket._close(error);
    this.onEvent({ type: "closed", port: conn.remotePort, error: error ? error.message : null });
  }

  /** Send a reset and forget the connection. */
  _destroy(conn) {
    if (conn.state === STATE.CLOSED) return;
    this._sendIp(this.peerIp, PROTO.TCP, encodeTcp({
      src: this.ip, dst: this.peerIp,
      srcPort: conn.localPort, dstPort: conn.remotePort,
      seq: conn.sndNxt, ack: conn.rcvNxt, flags: FLAG.RST | FLAG.ACK, window: 0
    }));
    this._teardown(conn, null);
  }

  /** Reset every open connection. For a tab that is going away. */
  close() {
    for (const conn of [...this._connections.values()]) this._destroy(conn);
  }

  _allocatePort() {
    const inUse = new Set([...this._connections.values()].map((c) => c.localPort));
    for (let i = 0; i <= EPHEMERAL_LAST - EPHEMERAL_FIRST; i++) {
      const port = this._nextPort;
      this._nextPort = this._nextPort >= EPHEMERAL_LAST ? EPHEMERAL_FIRST : this._nextPort + 1;
      if (!inUse.has(port) && !this._listeners.has(port)) return port;
    }
    throw new Error("no ephemeral port is free");
  }
}

/**
 * One connection, as the caller sees it.
 *
 * Deliberately close to the shape of a node socket, minus everything that turns
 * out not to be needed: a listener for data, one for the peer's half-close, one
 * for the end.
 */
export class TcpSocket {
  constructor(stack, conn) {
    this._stack = stack;
    this._conn = conn;
    this.opened = false;
    this._closed = false;
    this.onData = null;
    this.onEnd = null;
    this.onClose = null;
    this.bytesRead = 0;
    this.bytesWritten = 0;
  }

  get state() { return this._conn.state; }
  get localPort() { return this._conn.localPort; }
  get remotePort() { return this._conn.remotePort; }

  write(bytes) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.bytesWritten += view.length;
    this._stack._write(this._conn, view);
    return this;
  }

  /** Half-close: everything written is still delivered, then a FIN. */
  end() { this._stack._finish(this._conn); return this; }

  /** Abort: a reset, and anything still queued is discarded. */
  destroy() { this._stack._destroy(this._conn); return this; }

  _data(bytes) {
    this.bytesRead += bytes.length;
    if (this.onData) this.onData(bytes);
  }

  _end() { if (this.onEnd) this.onEnd(); }

  _close(error) {
    if (this._closed) return;
    this._closed = true;
    if (this.onClose) this.onClose(error || null);
  }
}
