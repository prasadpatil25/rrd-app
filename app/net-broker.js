// The page side of the service worker.
//
// The worker can answer a fetch but has no machine; this tab has the machine but
// cannot answer a fetch. So the tab announces itself as the host of a machine,
// and from then on the worker forwards requests here, each on its own port. The
// tab runs them through the stack into the guest and replies.
//
// One tab hosts a machine at a time, which is the honest arrangement: the
// machine is a single VM in a single tab. The worker forgets a host as soon as
// its tab is gone, so a request for a machine nobody is running gets a page that
// says so rather than a hang.

const DEFAULT_MACHINE = "1";

/**
 * Where the worker is, relative to this module rather than to the page.
 *
 * It sits at the deployment root, not beside this file: a worker may only claim
 * a scope at or below its own directory unless the server sends a header, and
 * a static host will not send one. Resolving it from import.meta.url means a
 * deployment under a subpath finds it too.
 */
function workerScript() {
  return new URL("../net-sw.js", import.meta.url).href;
}

/**
 * Start serving a machine to the rest of the browser.
 *
 * @param {Object} options
 * @param {import("../src/device/net.js").V86Net} options.net an attached stack
 * @param {string} [options.machine] the name it is reachable under
 * @param {number} [options.port] the port to reach in the guest
 * @param {string} [options.scriptUrl] where the worker is served from
 * @param {(event: Object) => void} [options.onEvent]
 * @returns {Promise<{url: string, machine: string, stop: () => Promise<void>}>}
 */
export async function host({
  net, machine = DEFAULT_MACHINE, port = 80, scriptUrl = workerScript(), onEvent = () => {}
} = {}) {
  if (!net) throw new Error("a V86Net is required");
  if (!("serviceWorker" in navigator)) {
    throw new Error("this browser has no service worker, so other tabs cannot reach the machine");
  }
  if (!self.isSecureContext) {
    throw new Error(
      "service workers need a secure context. localhost counts; a plain-http address on " +
      "the network does not."
    );
  }

  const registration = await navigator.serviceWorker.register(scriptUrl);
  await navigator.serviceWorker.ready;

  const name = String(machine);
  const onMessage = async (event) => {
    const message = event.data || {};
    const port_ = event.ports && event.ports[0];

    // The worker forgets everything when it is stopped, which it is whenever it
    // is idle. Answering this is how it finds its way back to this tab.
    if (message.type === "who-hosts" && String(message.machine) === name) {
      if (port_) port_.postMessage({ hosting: true });
      return;
    }
    if (message.type !== "request" || String(message.machine) !== name) return;
    if (!port_) return;

    try {
      const response = await net.request({
        port,
        method: message.method,
        path: message.path,
        headers: message.headers,
        body: message.body ? new Uint8Array(message.body) : null
      });
      onEvent({ type: "served", path: message.path, status: response.status, bytes: response.body.length });
      // The body is transferred rather than copied; nothing here keeps it.
      port_.postMessage({
        ok: true,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        body: response.body.buffer
      }, [response.body.buffer]);
    } catch (err) {
      onEvent({ type: "failed", path: message.path, error: err.message });
      port_.postMessage({ ok: false, error: err.message });
    }
  };
  navigator.serviceWorker.addEventListener("message", onMessage);

  const announce = async () => {
    const worker = registration.active || navigator.serviceWorker.controller;
    if (!worker) throw new Error("the service worker registered but is not active yet");
    return tell(worker, { type: "host", machine: name });
  };

  // A worker that updates or takes control replaces the one we announced to, so
  // say it again rather than going quietly unreachable.
  const onControllerChange = () => { announce().catch(() => {}); };
  navigator.serviceWorker.addEventListener("controllerchange", onControllerChange);

  const announced = await announce();
  const url = announced.url || new URL(`./m/${name}/`, registration.scope).href;
  onEvent({ type: "hosting", machine: name, url });

  const stop = async () => {
    navigator.serviceWorker.removeEventListener("message", onMessage);
    navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
    const worker = registration.active || navigator.serviceWorker.controller;
    if (worker) await tell(worker, { type: "unhost", machine: name }).catch(() => {});
    onEvent({ type: "stopped", machine: name });
  };

  // A tab that goes away without saying so leaves the worker holding a client id
  // it will find dead on the next request. Saying so is tidier and costs nothing.
  addEventListener("pagehide", () => {
    const worker = registration.active;
    if (worker) worker.postMessage({ type: "unhost", machine: name });
  }, { once: true });

  return { url, machine: name, stop, registration };
}


// --- an origin of the machine's own -----------------------------------------
//
// Sharing the app's origin costs the guest its own assets. The worker has to
// sandbox guest content there, or a page out of a VM could read the token that
// pushes to the repository; and a sandboxed document has an opaque origin,
// which a service worker does not control, so its stylesheets and scripts
// bypass the worker entirely and 404. One document works. A site does not.
//
// Giving each machine its own origin removes the reason for the sandbox instead
// of working around it. `machine-1.localhost` resolves to the loopback address
// with no DNS entry and no certificate, and counts as a secure context, so a
// worker can be registered there and every path on it belongs to the guest.
//
// The catch is that a worker can only be registered by a page on its own
// origin, and this tab is not on that origin. So a hidden iframe on the machine
// origin does the registering and relays requests back here by postMessage.

/**
 * The origin a machine is served from.
 *
 * Two shapes, and which one applies is not a matter of taste. A browser
 * partitions storage -- service worker registrations included -- by the site of
 * the top-level page, so a registration made in an iframe is only the one a
 * top-level tab later finds if the two are the same site. Ports are not part of
 * a site and subdomains of a real domain are not either, but Chrome treats every
 * `*.localhost` as a site of its own, which is exactly the case a demo runs in.
 *
 * So locally a machine takes a port of its own, which is a different origin on
 * the same site; deployed it takes a subdomain, which is a different origin on
 * the same site as well. Either way the guest cannot read the app's storage, and
 * either way the worker registered through the bridge is the one that answers.
 */
export function machineOrigin(machine, {
  hostname = location.hostname, protocol = location.protocol, port = location.port,
  machinePort = null, declared = declaredMachineOrigin()
} = {}) {
  if (/^machine/i.test(hostname) && !declared) {
    throw new Error(`this page is already on a machine origin (${hostname})`);
  }

  // A deployment says where its machines live, because nothing here can work it
  // out. One origin serves whichever machine the hosting tab holds: the machine's
  // name travels in the worker's registration, not in the hostname, so this does
  // not need a name -- or a DNS record, or a certificate -- per machine.
  if (declared) return declared.replace(/\/$/, "");

  const local = hostname === "localhost" || hostname.endsWith(".localhost") ||
                hostname === "127.0.0.1" || hostname === "[::1]" ||
                /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (local) {
    if (!machinePort) {
      throw new Error(
        `on ${hostname} a machine needs a port of its own, because every ` +
        `*.localhost name is a separate site and a worker registered on one from ` +
        `here would not be the worker a top-level tab finds. Serve the project on ` +
        `a second port -- python serve.py 8001 -- and pass machinePort: 8001.`
      );
    }
    return `${protocol}//${hostname}:${machinePort}`;
  }

  // Deployed with nothing declared: a sibling name under the same registrable
  // domain, which is a different origin on the same site. Whoever deploys has to
  // point it somewhere, which is why the meta tag exists.
  return `${protocol}//machines.${hostname}${port ? ":" + port : ""}`;
}

/** Where a deployment says its machines are served from, if it says. */
function declaredMachineOrigin() {
  if (typeof document === "undefined") return null;
  const meta = document.querySelector('meta[name="machine-origin"]');
  const value = meta && meta.content && meta.content.trim();
  return value || null;
}

/**
 * Check that a machine's origin is being served, and say what to do if not.
 *
 * Worth calling before anything expensive. Booting a machine, formatting its
 * disk and syncing it takes the better part of a minute, and discovering only
 * at the end that the origin was never there wastes all of it.
 */
export async function assertServing(origin, { hostname = location.hostname } = {}) {
  try {
    await fetch(`${origin}/app/machine-origin.html`, { method: "HEAD", mode: "no-cors" });
  } catch {
    // The advice depends entirely on where this page is. Telling somebody whose
    // site is on a static host to start a second copy of a Python server is
    // advice about a machine they do not have.
    const local = hostname === "localhost" || hostname.endsWith(".localhost") ||
                  hostname === "127.0.0.1" || hostname === "[::1]" ||
                  /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    throw new Error(local
      ? `nothing is serving ${origin}, so a machine has nowhere to be served from. ` +
        `A machine takes a port of its own, so start a second copy of the static ` +
        `server there:\n\n    python serve.py ${new URL(origin).port || 80}\n`
      : `nothing is serving ${origin}, so a machine has nowhere to be served from. ` +
        `A machine needs an origin that is not this one, deployed with the same ` +
        `files, and this page has to be told where it is:\n\n` +
        `    <meta name="machine-origin" content="https://machines.example.com">\n\n` +
        `On a bare *.github.io there is no such origin to be had -- every ` +
        `repository is a path on one origin -- so that needs a domain of your own.`
    );
  }
  return origin;
}

/**
 * Serve a machine from an origin of its own.
 *
 * @param {Object} options
 * @param {{request: Function}} options.net an attached stack
 * @param {string} [options.machine]
 * @param {number} [options.port] the port to reach in the guest
 * @param {(event: Object) => void} [options.onEvent]
 * @returns {Promise<{url: string, origin: string, machine: string, stop: () => Promise<void>}>}
 */
export async function hostOnOrigin({
  net, machine = DEFAULT_MACHINE, port = 80, machinePort = null,
  timeoutMs = 20000, onEvent = () => {}
} = {}) {
  if (!net) throw new Error("a V86Net is required");
  const name = String(machine);
  const origin = machineOrigin(name, { machinePort });

  await assertServing(origin);

  const frame = document.createElement("iframe");
  frame.style.display = "none";
  frame.setAttribute("aria-hidden", "true");
  frame.title = `bridge to ${origin}`;
  frame.src = `${origin}/app/machine-origin.html` +
    `?machine=${encodeURIComponent(name)}&parent=${encodeURIComponent(location.origin)}`;

  let settle = null;
  const ready = new Promise((resolve, reject) => {
    settle = { resolve, reject };
    setTimeout(() => reject(new Error(
      `the bridge at ${origin} did not report ready within ${timeoutMs}ms. Does ` +
      `${new URL(origin).hostname} resolve, and does the server send ` +
      `Service-Worker-Allowed: / for net-sw.js?`
    )), timeoutMs);
  });

  const onMessage = async (event) => {
    // Only the bridge, and only from the origin it was put on.
    if (event.origin !== origin || event.source !== frame.contentWindow) return;
    const message = event.data || {};

    if (message.type === "machine-ready") return settle.resolve(message.url || `${origin}/`);
    if (message.type === "machine-failed") return settle.reject(new Error(message.error));
    if (message.type !== "machine-request" || String(message.machine) !== name) return;

    const answer = async () => {
      try {
        const response = await net.request({
          port,
          method: message.method,
          path: message.path,
          headers: message.headers,
          body: message.body ? new Uint8Array(message.body) : null
        });
        onEvent({ type: "served", path: message.path, status: response.status, bytes: response.body.length });
        return {
          ok: true, status: response.status, statusText: response.statusText,
          headers: response.headers, body: response.body.buffer
        };
      } catch (err) {
        onEvent({ type: "failed", path: message.path, error: err.message });
        return { ok: false, error: err.message };
      }
    };

    const result = await answer();
    frame.contentWindow.postMessage(
      { type: "machine-response", id: message.id, answer: result },
      origin,
      result.body ? [result.body] : []
    );
  };

  addEventListener("message", onMessage);
  document.body.appendChild(frame);

  let url;
  try {
    url = await ready;
  } catch (err) {
    removeEventListener("message", onMessage);
    frame.remove();
    throw err;
  }

  onEvent({ type: "hosting", machine: name, url });
  return {
    url, origin, machine: name,
    async stop() {
      removeEventListener("message", onMessage);
      frame.remove();
      onEvent({ type: "stopped", machine: name });
    }
  };
}

/** Which machines the worker currently believes are being hosted. */
export async function hosted({ scriptUrl = workerScript() } = {}) {
  const registration = await navigator.serviceWorker.register(scriptUrl);
  await navigator.serviceWorker.ready;
  const worker = registration.active || navigator.serviceWorker.controller;
  if (!worker) return [];
  const answer = await tell(worker, { type: "hosted" });
  return answer.machines || [];
}

/** Post a message and wait for its answer on a private port. */
function tell(worker, message, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      reject(new Error(`the service worker did not answer "${message.type}" within ${timeoutMs}ms`));
    }, timeoutMs);
    channel.port1.onmessage = (event) => {
      clearTimeout(timer);
      channel.port1.close();
      resolve(event.data || {});
    };
    worker.postMessage(message, [channel.port2]);
  });
}
