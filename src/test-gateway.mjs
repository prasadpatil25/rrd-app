// Tests for the way out.
//
// The gateway is a policy decision with a parser attached, so what is tested is
// the policy: what it lets through, what it refuses, and whether the refusal
// says enough for somebody to act on it. fetch is replaced, because what the
// browser does with a request is the browser's business and not this file's.
//
// Run with: node src/test-gateway.mjs

import { startGateway, PROXY_URL } from "./net/gateway.js";
import { NetStack } from "./net/stack.js";
import { encodeRequest, ResponseParser } from "./net/http.js";
import {
  ARP_OP, ETHERTYPE, FLAG, PROTO,
  decodeArp, decodeEthernet, decodeIp, decodeTcp,
  encodeArp, encodeEthernet, encodeIp, encodeTcp, seqAdd
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

const OUR_IP = "10.0.2.2", OUR_MAC = "0e:00:00:00:00:01";
const GUEST_IP = "10.0.2.15", GUEST_MAC = "52:54:00:12:34:56";
const enc = new TextEncoder(), dec = new TextDecoder();

/** A guest that speaks the client half of TCP over real frames. */
function world() {
  const inbox = [];
  const received = [];
  let conn = null;
  let nextPort = 40000;
  const stack = new NetStack({
    mac: OUR_MAC, ip: OUR_IP, peerIp: GUEST_IP,
    send: (frame) => feed(frame)
  });

  function emit(type, payload) {
    inbox.push(encodeEthernet({ dst: OUR_MAC, src: GUEST_MAC, type, payload }));
  }
  function send({ flags, payload = new Uint8Array(0), seq = null, consume = 0 }) {
    const at = seq === null ? conn.sndNxt : seq;
    emit(ETHERTYPE.IPV4, encodeIp({
      src: GUEST_IP, dst: OUR_IP, protocol: PROTO.TCP,
      payload: encodeTcp({
        src: GUEST_IP, dst: OUR_IP, srcPort: conn.local, dstPort: conn.remote,
        seq: at, ack: conn.rcvNxt, flags, payload, window: 65535
      })
    }));
    conn.sndNxt = seqAdd(at, payload.length + consume);
  }
  function feed(frame) {
    const eth = decodeEthernet(frame);
    if (eth.type === ETHERTYPE.ARP) {
      const arp = decodeArp(eth.payload);
      if (arp && arp.op === ARP_OP.REQUEST) {
        emit(ETHERTYPE.ARP, encodeArp({
          op: ARP_OP.REPLY, senderMac: GUEST_MAC, senderIp: GUEST_IP,
          targetMac: arp.senderMac, targetIp: arp.senderIp
        }));
      }
      return;
    }
    const ip = decodeIp(eth.payload);
    if (!ip || ip.protocol !== PROTO.TCP || !conn) return;
    const seg = decodeTcp(ip.payload);
    if ((seg.flags & FLAG.SYN) && (seg.flags & FLAG.ACK)) {
      conn.rcvNxt = seqAdd(seg.seq, 1);
      send({ flags: FLAG.ACK });
      return;
    }
    if (seg.payload.length && seg.seq === conn.rcvNxt) {
      conn.rcvNxt = seqAdd(conn.rcvNxt, seg.payload.length);
      received.push(seg.payload);
      send({ flags: FLAG.ACK });
    }
    if (seg.flags & FLAG.FIN) { conn.rcvNxt = seqAdd(conn.rcvNxt, 1); send({ flags: FLAG.ACK }); }
  }
  const deliver = () => { while (inbox.length) stack.receive(inbox.shift()); };

  return {
    stack, deliver, received,
    /** Ask the proxy for something, the way a client with http_proxy set would. */
    async request(target, { method = "GET", port = 8080, headers = {} } = {}) {
      // A port apiece. Reusing one while the last connection is still being torn
      // down is a different test from the one being written here.
      conn = { local: nextPort++, remote: port, rcvNxt: 0, sndNxt: 500000 };
      received.length = 0;
      send({ flags: FLAG.SYN, seq: conn.sndNxt, consume: 1 });
      deliver(); deliver();
      const line = `${method} ${target} HTTP/1.1\r\nHost: proxied\r\n` +
        Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("") + "\r\n";
      send({ flags: FLAG.ACK | FLAG.PSH, payload: enc.encode(line) });
      deliver();
      for (let i = 0; i < 40; i++) {
        await Promise.resolve();
        deliver();
      }
      const parser = new ResponseParser();
      for (const chunk of received) parser.push(chunk);
      parser.end();
      return { status: parser.status, headers: parser.headers, body: dec.decode(parser.body()) };
    }
  };
}

/** What fetch was asked for, and what it will answer. */
function fakeFetch(answers) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method, headers: options.headers });
    const answer = answers[new URL(url).hostname];
    if (!answer) throw new TypeError("Failed to fetch");
    return {
      status: answer.status || 200,
      statusText: "OK",
      headers: new Map(Object.entries(answer.headers || { "content-type": "text/plain" })),
      arrayBuffer: async () => enc.encode(answer.body || "").buffer
    };
  };
  return calls;
}

const realFetch = globalThis.fetch;

// ------------------------------------------------------------------- policy

console.log("\nwhat a machine may reach");
{
  let refused = null;
  try { startGateway({ net: world().stack, allow: [] }); } catch (err) { refused = err.message; }
  check("a gateway with nothing allowed refuses to start", refused !== null);
  check("because not starting one already does that",
        /not starting one already does/.test(refused || ""), refused);
}
{
  const w = world();
  const calls = fakeFetch({ "api.github.com": { body: '{"ok":true}' } });
  const gateway = startGateway({ net: w.stack, allow: ["api.github.com"] });

  const allowed = await w.request("https://api.github.com/repos/x/y");
  eq("an allowed host is fetched", allowed.status, 200);
  eq("and its answer comes back", allowed.body, '{"ok":true}');
  eq("the tab asked for exactly what the guest asked for", calls[0].url, "https://api.github.com/repos/x/y");

  const denied = await w.request("https://example.com/");
  eq("a host that is not on the list is refused", denied.status, 403);
  check("and told which are", /api\.github\.com/.test(denied.body), denied.body);
  eq("without the tab having asked anybody", calls.length, 1);
  gateway.close();
}
{
  const w = world();
  fakeFetch({ "api.github.com": { body: "x" } });
  const gateway = startGateway({ net: w.stack, allow: [".github.com"] });
  const sub = await w.request("https://api.github.com/x");
  eq("a leading dot admits a subdomain", sub.status, 200);
  const other = await w.request("https://notgithub.com/x");
  eq("but not a name that merely ends the same way", other.status, 403);
  gateway.close();
}

// ------------------------------------------------------------------ refusals

console.log("\nwhat it refuses, and how it explains itself");
{
  const w = world();
  fakeFetch({});
  const gateway = startGateway({ net: w.stack, allow: ["example.com"] });

  const connect = await w.request("example.com:443", { method: "CONNECT" });
  eq("CONNECT is refused", connect.status, 405);
  check("as a man in the middle rather than as unsupported",
        /man in the middle/.test(connect.body), connect.body);

  const relative = await w.request("/just/a/path");
  eq("a request that is not absolute is refused", relative.status, 400);
  check("with the setting that would fix it",
        relative.body.includes(PROXY_URL), relative.body);

  const unreachable = await w.request("https://example.com/x");
  eq("a host the browser will not read is a bad gateway", unreachable.status, 502);
  check("explained as the browser's rules rather than the host being down",
        /cross-origin/.test(unreachable.body), unreachable.body);
  gateway.close();
}
{
  const w = world();
  fakeFetch({ "big.example": { body: "x".repeat(5000) } });
  const gateway = startGateway({ net: w.stack, allow: ["big.example"], maxBytes: 1000 });
  const large = await w.request("https://big.example/file");
  eq("more than the gateway will carry is refused", large.status, 502);
  check("saying how much came back", /5000 bytes/.test(large.body), large.body);
  gateway.close();
}
{
  const w = world();
  const calls = fakeFetch({ "api.github.com": { body: "ok" } });
  const events = [];
  const gateway = startGateway({
    net: w.stack, allow: ["api.github.com"], onEvent: (e) => events.push(e)
  });
  await w.request("https://api.github.com/x", { headers: { "Connection": "close", "Accept": "text/plain" } });
  check("a hop-by-hop header is not forwarded", !("Connection" in calls[0].headers), JSON.stringify(calls[0].headers));
  // Lower-cased, because the request parser lower-cases what it reads: a header
  // name is case-insensitive and keeping two spellings of one is how a lookup
  // comes back undefined.
  check("an ordinary one is", calls[0].headers.accept === "text/plain",
        JSON.stringify(calls[0].headers));
  check("every byte that leaves is announced", events.some((e) => e.type === "fetched"));
  eq("with where it went", events.find((e) => e.type === "fetched").host, "api.github.com");
  gateway.close();
  check("and closing says so", events.some((e) => e.type === "closed"));
}

globalThis.fetch = realFetch;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
process.exit(0);
