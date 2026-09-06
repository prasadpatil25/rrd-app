// The stack, bound to a v86 NIC.
//
// v86 emulates an NE2000 and puts both directions of it on its bus: a frame the
// guest transmits arrives as "net0-send", and a frame handed back on
// "net0-receive" appears to the guest as one its card just received. That is the
// whole interface, and it is the reason nothing outside the tab is needed. The
// emulator has to be constructed with a NIC for either to exist:
//
//     new V86({ ..., net_device: { type: "ne2k" } })
//
// Note what is absent from that: relay_url. Every other project that turns this
// on points it at a WebSocket relay, which puts a server back in the picture and
// hands somebody else the guest's traffic. Leaving it out means v86 builds the
// card and connects it to nothing, and the nothing is where this file attaches.
//
// The addresses are the ones a v86 user expects, because they are the ones
// v86's own relay uses: the guest at 10.0.2.15, the other end of the segment at
// 10.0.2.2. A guest image configured for the usual setup needs no change.

import { NetStack } from "../net/stack.js";
import { request } from "../net/http.js";

/** Locally administered, so it cannot collide with a real card. */
export const HOST_MAC = "0e:00:00:00:00:01";
export const HOST_IP = "10.0.2.2";
export const GUEST_IP = "10.0.2.15";

export class V86Net {
  /**
   * @param {Object} options
   * @param {Object} options.emulator a V86 built with net_device
   * @param {string} [options.mac] our MAC on the segment
   * @param {string} [options.ip] our address
   * @param {string} [options.peerIp] the guest's address
   * @param {number} [options.tickMs] how often to service retransmissions
   * @param {(event: Object) => void} [options.onEvent]
   */
  constructor({
    emulator, mac = HOST_MAC, ip = HOST_IP, peerIp = GUEST_IP, tickMs = 100, onEvent
  } = {}) {
    if (!emulator) throw new Error("an emulator is required");
    this.emulator = emulator;
    this.tickMs = tickMs;
    this.onEvent = onEvent || (() => {});
    this.attached = false;
    this._timer = null;
    this._listener = null;

    this.stack = new NetStack({
      mac, ip, peerIp,
      send: (frame) => this._toGuest(frame),
      onEvent: this.onEvent
    });
  }

  get ip() { return this.stack.ip; }
  get peerIp() { return this.stack.peerIp; }
  get stats() { return this.stack.stats; }

  /** Wire both directions and start the retransmission timer. */
  attach() {
    if (this.attached) return this;
    if (typeof this.emulator.add_listener !== "function") {
      throw new Error("this does not look like a V86 instance: no add_listener");
    }
    this._bus();   // fail now, with a clear message, rather than on the first frame

    this._listener = (data) => {
      // v86 hands over a view onto a buffer it reuses. Copy before parsing:
      // anything held past this call -- an out-of-order segment, a queued
      // payload -- would otherwise change under us.
      this.stack.receive(new Uint8Array(data));
    };
    this.emulator.add_listener("net0-send", this._listener);
    this._timer = setInterval(() => this.stack.tick(), this.tickMs);
    this.attached = true;
    this.onEvent({ type: "net-attached", ip: this.stack.ip, peerIp: this.stack.peerIp });
    return this;
  }

  detach() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    if (this._listener && typeof this.emulator.remove_listener === "function") {
      this.emulator.remove_listener("net0-send", this._listener);
    }
    this._listener = null;
    this.stack.close();
    this.attached = false;
  }

  /** @returns {Promise<import("../net/stack.js").TcpSocket>} */
  connect(port, options) { return this.stack.connect(port, options); }

  /** One HTTP request to a port in the guest. */
  request(options) { return request(this.stack, options); }

  /**
   * Wait until something in the guest answers on a port.
   *
   * A server started from a shell is not listening the instant the command
   * returns, and a demo that raced it would fail intermittently, which is the
   * worst way for it to fail.
   */
  async waitForPort(port, { timeoutMs = 30000, intervalMs = 300 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const socket = await this.stack.connect(port, { timeoutMs: Math.min(2000, timeoutMs) });
        socket.destroy();
        return true;
      } catch {
        if (Date.now() > deadline) {
          throw new Error(
            `nothing is listening on port ${port} in the guest after ${timeoutMs}ms. ` +
            `Check the server started, and that the guest's eth0 is configured.`
          );
        }
        await sleep(intervalMs);
      }
    }
  }

  _bus() {
    const bus = this.emulator.bus || this.emulator.emulator_bus;
    if (!bus || typeof bus.send !== "function") {
      throw new Error(
        "the emulator exposes no bus to send frames on. Was it constructed with " +
        "net_device: { type: \"ne2k\" }?"
      );
    }
    return bus;
  }

  _toGuest(frame) {
    this._bus().send("net0-receive", frame);
  }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
