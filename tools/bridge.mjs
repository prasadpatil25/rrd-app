// A door for everything that is not a browser tab.
//
// A machine is reachable from other tabs because a service worker can answer
// their requests. Nothing else can reach it: a tab cannot listen on a port, so
// curl has nothing to connect to and no amount of worker cleverness changes
// that.
//
// This is the smallest thing that fixes it. It listens on a port, and the tab
// holding a machine connects *out* to it and asks, repeatedly, whether anything
// has arrived. A request to this server is handed to the tab, run through the
// stack into the guest, and the answer comes back the same way.
//
//     curl localhost:9000/cgi-bin/process.cgi?text=hi
//       -> this server -> your tab -> TCP in JavaScript -> busybox httpd
//
// It is a development tool and says so. It is a server, which the rest of this
// project is at pains not to be, and it is on your own machine rather than in
// the deployment. Anything that can reach loopback can reach the machine while
// it runs, which is the same trust you extend to any dev server.
//
// --host widens that to a network, and a token stops being optional there; see
// the note above TOKEN. For a public URL, put a tunnel in front of loopback
// rather than opening a port on the router:
//
//     node tools/bridge.mjs 9000 --host 0.0.0.0     # a token is generated
//     cloudflared tunnel --url http://localhost:9000
//
// No dependencies, because the tab polls over ordinary HTTP rather than holding
// a WebSocket: node has no WebSocket server, and adding one to a project with no
// build step to install it would cost more than the polling does.
//
//   node tools/bridge.mjs [port] [--host addr] [--token secret]   port 9000

import http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";

const args = process.argv.slice(2);
const flag = (name) => {
  const at = args.indexOf(name);
  return at < 0 ? null : (args[at + 1] && !args[at + 1].startsWith("--") ? args[at + 1] : "");
};

const PORT = Number(args.find((a) => /^\d+$/.test(a))) || 9000;
const HOST = flag("--host");
const LOOPBACK = ["127.0.0.1", "::1", "localhost", null];

/**
 * A token, always, the moment this is reachable from anywhere but this computer.
 *
 * A machine has no authentication of its own -- it is a web server on a disk,
 * and everything that can reach it can run whatever it serves. On loopback that
 * is the same trust as any development server. Off loopback it is not, so there
 * is no way to ask for that without one: given no token, this makes one and
 * prints it rather than starting open.
 */
const asked = flag("--token");
const TOKEN = asked || (LOOPBACK.includes(HOST) ? null : randomBytes(16).toString("hex"));
const HOLD_MS = 25000;      // how long a poll waits before answering "nothing yet"
const ANSWER_MS = 60000;    // how long a caller waits for the machine to answer

/** Requests waiting for a tab to collect them, by machine. */
const waiting = new Map();
/** Requests a tab has collected and not yet answered, by id. */
const inFlight = new Map();
/** Polls parked with nothing to give them, by machine. */
const pollers = new Map();

let nextId = 1;

const queueFor = (machine) => {
  if (!waiting.has(machine)) waiting.set(machine, []);
  return waiting.get(machine);
};
const pollersFor = (machine) => {
  if (!pollers.has(machine)) pollers.set(machine, []);
  return pollers.get(machine);
};

/** Hand a request to a waiting poll if one is parked, otherwise queue it. */
function offer(machine, job) {
  const parked = pollersFor(machine);
  const poll = parked.shift();
  if (poll) {
    clearTimeout(poll.timer);
    deliver(poll.response, job);
    return;
  }
  queueFor(machine).push(job);
}

function deliver(response, job) {
  job.deliveredAt = Date.now();
  inFlight.set(job.id, job);
  send(response, 200, {
    id: job.id, method: job.method, path: job.path,
    headers: job.headers, body: job.body
  });
}

/**
 * Hold a poll open until there is something for it.
 *
 * The close listener is not tidiness. A tab that reloads or reconnects leaves
 * its polls parked here with nobody behind them, and handing the next request to
 * one of those is a request that will never be answered -- which is exactly what
 * happened: the first call after every reconnect waited the full minute and then
 * gave up.
 */
function park(machine, request, response) {
  const parked = pollersFor(machine);
  const poll = { response, timer: null };
  const drop = () => {
    const at = parked.indexOf(poll);
    if (at >= 0) parked.splice(at, 1);
  };
  poll.timer = setTimeout(() => { drop(); send(response, 204, {}); }, HOLD_MS);
  request.on("close", () => { clearTimeout(poll.timer); drop(); });
  parked.push(poll);
}

function send(response, status, body) {
  const text = JSON.stringify(body);
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(text),
    // The tab is on another origin -- a different port is a different origin --
    // and it is the only thing that talks to these two endpoints.
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "content-type"
  });
  response.end(text);
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/** Constant time, because a token compared with === leaks its prefix. */
function matches(given) {
  if (!given) return false;
  const a = Buffer.from(String(given));
  const b = Buffer.from(TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function authorised(request, url) {
  if (!TOKEN) return true;
  const header = request.headers.authorization || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : null;
  return matches(bearer) || matches(url.searchParams.get("token"));
}

async function handle(request, response) {
  const url = new URL(request.url, `http://localhost:${PORT}`);
  const machine = url.searchParams.get("machine") || "1";

  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "content-type",
      // So a preflight, if one happens at all, happens once rather than per
      // request.
      "Access-Control-Max-Age": "86400"
    });
    return response.end();
  }

  if (!authorised(request, url)) {
    response.writeHead(401, {
      "Content-Type": "text/plain; charset=utf-8",
      "WWW-Authenticate": 'Bearer realm="machine"',
      // Without this the tab cannot read its own rejection: the browser hides a
      // cross-origin response with no CORS header, and a refusal nobody can
      // read is indistinguishable from a bridge that is not running.
      "Access-Control-Allow-Origin": "*"
    });
    return response.end(
      "This bridge is reachable from somewhere other than the computer it runs on,\n" +
      "so it wants a token. Send it as a bearer token, or as ?token= on the URL.\n"
    );
  }

  // --- the tab, asking whether anything has arrived -------------------------
  if (url.pathname === "/_bridge/pending") {
    const queued = queueFor(machine).shift();
    if (queued) return deliver(response, queued);

    park(machine, request, response);
    return;
  }

  // --- the tab, answering ----------------------------------------------------
  if (url.pathname === "/_bridge/response" && request.method === "POST") {
    const answer = JSON.parse((await readBody(request)).toString("utf8"));
    const job = inFlight.get(answer.id);
    inFlight.delete(answer.id);
    if (job) job.settle(answer);

    // Hand back the next job on the same request rather than making the tab ask
    // again. A browser will only hold so many connections to one host, and with
    // several polls parked there is little room left for anything else: posting
    // an answer and collecting the next work separately meant each of them
    // queueing behind the others, which cost more than the machine did.
    const queued = queueFor(machine).shift();
    if (queued) return deliver(response, queued);
    park(machine, request, response);
    return;
  }

  if (url.pathname === "/_bridge/status") {
    return send(response, 200, {
      machines: [...new Set([...waiting.keys(), ...pollers.keys()])],
      waiting: [...waiting.entries()].map(([m, q]) => ({ machine: m, queued: q.length })),
      listening: [...pollers.entries()].map(([m, p]) => ({ machine: m, polls: p.length })),
      inFlight: inFlight.size
    });
  }

  // --- everything else is for the machine ------------------------------------
  const body = await readBody(request);
  const job = {
    id: nextId++,
    method: request.method,
    path: url.pathname + url.search,
    headers: Object.fromEntries(
      Object.entries(request.headers).filter(([name]) =>
        ["accept", "accept-language", "content-type", "range"].includes(name))
    ),
    body: body.length ? body.toString("base64") : null,
    settle: null
  };

  const answered = new Promise((resolve) => { job.settle = resolve; });
  const timer = setTimeout(() => {
    inFlight.delete(job.id);
    job.settle({ error: `no tab answered for machine ${machine} within ${ANSWER_MS}ms` });
  }, ANSWER_MS);

  const arrived = Date.now();
  offer(machine, job);
  const answer = await answered;
  clearTimeout(timer);

  // Where the time went, because "the bridge is slow" is not something to leave
  // as an impression when it can be three numbers.
  const collected = (job.deliveredAt || arrived) - arrived;
  const answering = Date.now() - (job.deliveredAt || arrived);
  console.log(`${request.method} ${job.path} -> machine ${machine}  ` +
              `[collected in ${collected}ms, answered in ${answering}ms]`);

  if (!answer || answer.error) {
    const message =
      `${answer && answer.error ? answer.error : "the machine did not answer"}\n\n` +
      `Open the app, start a machine, and connect it to this bridge:\n\n` +
      `    const b = await import("./bridge-client.js");\n` +
      `    await b.connect({ net: window.machine.net, bridge: "http://localhost:${PORT}" });\n`;
    response.writeHead(504, { "Content-Type": "text/plain; charset=utf-8" });
    return response.end(message);
  }

  const headers = { ...(answer.headers || {}) };
  delete headers["content-length"];
  delete headers["transfer-encoding"];
  const payload = answer.body ? Buffer.from(answer.body, "base64") : Buffer.alloc(0);
  headers["Content-Length"] = payload.length;
  response.writeHead(answer.status || 200, headers);
  response.end(payload);
}

// Both loopback addresses, which is not pedantry.
//
// "localhost" resolves to ::1 before 127.0.0.1 on a Windows client. A server
// bound only to IPv4 is therefore not there when the first attempt is made, and
// the client waits out that failure before trying the other one: measured, 210ms
// to connect to localhost against 0.8ms to 127.0.0.1, on the same server. Two
// hundred milliseconds of nothing at all, which looked exactly like a slow
// bridge and was not.
//
// Loopback only, both of them. This hands out whatever a machine is serving, and
// a machine is not a thing to put on a network by accident.
const bind = HOST ? [HOST] : ["127.0.0.1", "::1"];
const servers = bind.map(() => http.createServer(handle));
for (const server of servers) server.on("connection", (socket) => socket.setNoDelay(true));

let listening = 0;
bind.forEach((host, index) => {
  servers[index].on("error", (err) => {
    // A machine without IPv6 is a machine without IPv6, not a failure to start.
    if (host === "::1") return console.log(`  (no IPv6 loopback: ${err.code})`);
    throw err;
  });
  servers[index].listen(PORT, host, () => { if (++listening === 1) announce(); });
});

function announce() {
  const loopback = LOOPBACK.includes(HOST);
  console.log(`bridge on ${loopback ? `http://localhost:${PORT}` : `port ${PORT} on every interface`}`);
  if (TOKEN) {
    console.log(`  token: ${TOKEN}`);
    console.log(`  every request needs it: ?token=${TOKEN} or an Authorization: Bearer header`);
  }
  if (!loopback) {
    console.log(`\n  This is reachable beyond this computer. Everything that can reach this`);
    console.log(`  port and holds the token can run whatever the machine serves. Stop it when`);
    console.log(`  you are done.`);
    console.log(`\n  For a public URL, put a tunnel in front of loopback rather than opening a`);
    console.log(`  port on your router:  cloudflared tunnel --url http://localhost:${PORT}`);
  } else if (!TOKEN) {
    // A tunnel to loopback is as public as --host, and this cannot see one, so
    // it says so here rather than discovering it afterwards.
    console.log(`  no token: on loopback, that is the trust you give any dev server.`);
    console.log(`  Putting a tunnel in front of this makes it public -- restart with --token first.`);
  }
  console.log(`  waiting for a tab. In the app's console:\n`);
  console.log(`    const b = await import("./bridge-client.js");`);
  const arg = TOKEN ? `, token: "${TOKEN}"` : "";
  console.log(`    await b.connect({ net: window.machine.net, bridge: "http://localhost:${PORT}"${arg} });\n`);
  console.log(`  then: curl "localhost:${PORT}/${TOKEN ? `?token=${TOKEN}` : ""}"`);
}
