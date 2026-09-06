// The service worker that makes a machine reachable from other tabs.
//
// It owns no VM. It cannot: a service worker has no emulator, no disk and no
// stack. What it has is the ability to answer a fetch on this origin, and a way
// to ask another tab a question. So a request for /app/m/<machine>/... is handed
// to whichever tab is hosting that machine, that tab runs it through its TCP
// stack into the guest, and the answer comes back here to be turned into a
// Response. The tab holding the VM is the origin server; this is the receptionist.
//
// This file sits at the deployment root rather than in app/, and that is a
// deployment decision rather than a tidiness one. A worker may only claim a
// scope at or below its own directory unless the server sends a
// Service-Worker-Allowed header, and a static host worth deploying to -- GitHub
// Pages among them -- will not send headers at all. A worker at the root claims
// the root by default, everywhere, with nothing to configure.
//
// About the sandbox header, which is the most important line in the file.
//
// Guest content served from this origin is content the machine's owner did not
// write, running where this app's credentials live. Without the sandbox
// directive, a page served out of a VM could read the git token out of storage
// and push to the repository it came from. The directive drops the response into
// an opaque origin: scripts still run, so a real site works, but the app's
// storage, cookies and windows are not reachable from it. That makes same-origin
// hosting survivable. It does not make it right -- the fix is a separate origin,
// and this is what holds the line until there is one.

const PREFIX = "m";
// Long enough to cover the hosting tab putting a fallen-over guest back on its
// feet, which is slower than answering and is still the right thing to wait for.
const REQUEST_TIMEOUT = 60000;
const SANDBOX = "sandbox allow-scripts allow-forms allow-popups allow-modals";

// Which machine this origin belongs to, if it belongs to one.
//
// It comes from the worker's own script URL -- registered as net-sw.js?machine=1
// -- rather than from anything announced at run time, because a worker is
// stopped whenever it goes idle and started again for the next request, losing
// every variable it held. The script URL is part of the registration and
// survives that, so the worker knows what it is the moment it wakes up.
//
// Anywhere else, machines live under /m/<name>/ on the app's own origin and have
// to be sandboxed.
const OWN_MACHINE = new URL(self.location.href).searchParams.get("machine");

// The page that bridges this worker to the tab holding the VM. Matched by name
// rather than by path, because where it sits depends on where the project was
// deployed. It is served from the app, not from the guest; routing it to the
// guest would cut the branch this worker sits on.
const BRIDGE_NAME = "machine-origin.html";

/** The path prefix this worker was registered for; "/" unless deployed under one. */
function scopePath() {
  return new URL(self.registration ? self.registration.scope : "./", self.location.href).pathname;
}

/** machine id -> the id of the client hosting it. */
const hosts = new Map();
let nextId = 1;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
  const message = event.data || {};
  const client = event.source;
  if (message.type === "host" && client) {
    hosts.set(String(message.machine), client.id);
    reply(event, { ok: true, machine: String(message.machine), url: urlFor(message.machine) });
  } else if (message.type === "unhost") {
    if (hosts.get(String(message.machine)) === (client && client.id)) hosts.delete(String(message.machine));
    reply(event, { ok: true });
  } else if (message.type === "hosted") {
    reply(event, { ok: true, machines: [...hosts.keys()] });
  }
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  const route = parse(url.pathname);
  if (!route) return;                        // not ours; let the network have it
  event.respondWith(serve(event.request, route));
});

/** A request's machine and the path to ask it for, or null if it is not ours. */
function parse(pathname) {
  const base = scopePath();
  if (OWN_MACHINE) {
    if (!pathname.startsWith(base)) return null;
    // Everything under the scope is the guest's, addressed from the scope root,
    // so a machine deployed under a subpath still serves "/" as its own root.
    const path = "/" + pathname.slice(base.length);
    if (path.endsWith("/" + BRIDGE_NAME)) return null;
    return { machine: OWN_MACHINE, path };
  }
  if (!pathname.startsWith(base + PREFIX + "/")) return null;
  const rest = pathname.slice(base.length + PREFIX.length + 1);
  const slash = rest.indexOf("/");
  if (slash < 0) return { machine: rest, path: "/", bare: true };
  return { machine: rest.slice(0, slash), path: rest.slice(slash) || "/" };
}

function urlFor(machine) {
  if (OWN_MACHINE) return new URL(scopePath(), self.location.href).href;
  return new URL(`./${PREFIX}/${machine}/`, self.location.href).href;
}

async function serve(request, route) {
  // A bare /m/<machine> would make every relative link on the served page
  // resolve one directory too high, so send it to the directory form first.
  if (route.bare) {
    return Response.redirect(urlFor(route.machine), 302);
  }

  const client = await findHost(route.machine);
  if (!client) return offline(route.machine);

  const url = new URL(request.url);
  let body = null;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength) body = buffer;
  }

  let answer;
  try {
    answer = await ask(client, {
      type: "request",
      id: nextId++,
      machine: route.machine,
      method: request.method,
      path: route.path + url.search,
      headers: forwardable(request.headers),
      body
    }, body ? [body] : []);
  } catch (err) {
    // Not an error page so much as a "try that again": the tab holding the
    // machine is most likely busy restarting something.
    return problem(503, "The machine is busy", `${err.message} Reload to try again.`, route.machine);
  }

  if (!answer.ok) {
    return problem(502, "The machine could not serve that", answer.error, route.machine);
  }

  const headers = new Headers();
  for (const [name, value] of Object.entries(answer.headers || {})) {
    if (HOP_BY_HOP.has(name.toLowerCase())) continue;
    headers.set(name, value);
  }
  // Only when the guest is sharing the app's origin. On an origin of its own
  // there is nothing here to protect it from, and the sandbox would cost the
  // page its own assets: a document with an opaque origin is not controlled by
  // a service worker, so its stylesheets, scripts and images would bypass this
  // worker and 404 against the real server.
  if (!OWN_MACHINE) headers.set("Content-Security-Policy", SANDBOX);
  return new Response(answer.body || null, {
    status: answer.status,
    statusText: answer.statusText || "",
    headers
  });
}

/**
 * The client hosting a machine.
 *
 * The announcement is only a hint. A worker that has been stopped and started
 * again holds no announcements at all, and re-announcing would need the bridge
 * to notice a restart it is never told about. So fall back to looking: the
 * bridge page is identifiable by its URL, and it is a client of this worker
 * whether or not the worker has ever heard from it.
 */
async function findHost(machine) {
  const announced = hosts.get(machine);
  if (announced) {
    const client = await self.clients.get(announced);
    if (client) return client;
    hosts.delete(machine);
  }
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const bridge = windows.find((client) => {
    const url = new URL(client.url);
    return url.pathname.endsWith("/" + BRIDGE_NAME) &&
           (url.searchParams.get("machine") || "1") === machine;
  });
  if (bridge) {
    hosts.set(machine, bridge.id);
    return bridge;
  }
  return null;
}

/** Post to a client and wait for the reply on a private port. */
function ask(client, message, transfer = []) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      reject(new Error(`the tab hosting this machine did not answer within ${REQUEST_TIMEOUT}ms`));
    }, REQUEST_TIMEOUT);

    channel.port1.onmessage = (event) => {
      clearTimeout(timer);
      channel.port1.close();
      resolve(event.data);
    };
    client.postMessage(message, [channel.port2, ...transfer]);
  });
}

function reply(event, data) {
  const port = event.ports && event.ports[0];
  if (port) port.postMessage(data);
}

/**
 * Headers worth passing on. Everything the browser adds about this origin --
 * its cookies, its referer, the fetch metadata -- is about the app, not about
 * the guest, and the guest has no business seeing any of it.
 */
const FORWARD = new Set([
  "accept", "accept-language", "content-type", "range", "if-none-match", "if-modified-since"
]);
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "transfer-encoding", "upgrade", "content-length", "content-encoding"
]);

function forwardable(headers) {
  const out = {};
  for (const [name, value] of headers.entries()) {
    if (FORWARD.has(name.toLowerCase())) out[name] = value;
  }
  return out;
}

function offline(machine) {
  return problem(
    503, "This machine is not running",
    `No tab is hosting machine ${machine}. Open the app, start the machine and serve it again — ` +
    `its disk is safe in the repository either way.`,
    machine
  );
}

function problem(status, title, detail, machine) {
  const page = `<!doctype html><meta charset=utf-8><title>${title}</title>` +
    `<style>body{font:14px ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:48px 22px;` +
    `background:#EFF2F1;color:#131C1A}main{max-width:60ch;margin:0 auto}h1{font-size:19px;margin:0 0 10px}` +
    `p{color:#4A5754;line-height:1.6}code{background:#E8EDEB;padding:1px 5px;border-radius:3px}` +
    `@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}p{color:#A2B0AC}` +
    `code{background:#18231F}}</style>` +
    `<main><h1>${title}</h1><p>${escape(detail || "")}</p>` +
    `<p>Machine <code>${escape(machine)}</code>.</p></main>`;
  return new Response(page, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function escape(text) {
  return String(text).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}
