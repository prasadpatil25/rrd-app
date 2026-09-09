// The tab's half of the bridge.
//
// A tab cannot be connected to, so it connects out: it asks the bridge whether
// anything has arrived, runs whatever comes back through the stack into the
// guest, and posts the answer. Long polling rather than a socket, because that
// needs nothing on either side that is not already there.
//
// Several polls at once, because a page load asks for its stylesheet and its
// script at the same moment as its document, and one poll would make them queue
// behind each other for as long as the guest takes to answer -- which, for
// anything dynamic, is the part that costs.
//
//   const b = await import("./bridge-client.js");
//   const link = await b.connect({ net: window.machine.net });
//   ...
//   link.stop();

const DEFAULT_BRIDGE = "http://localhost:9000";

/**
 * @param {Object} options
 * @param {{request: Function}} options.net an attached stack
 * @param {string} [options.bridge] where the bridge is listening
 * @param {string} [options.machine]
 * @param {number} [options.port] the port to reach in the guest
 * @param {number} [options.concurrency] how many requests to carry at once
 * @param {(event: Object) => void} [options.onEvent]
 */
export async function connect({
  net, bridge = DEFAULT_BRIDGE, machine = "1", port = 80, token = null,
  concurrency = 4, onEvent = () => {}
} = {}) {
  if (!net) throw new Error("a network is required");

  // On the query string rather than in a header: a header the browser does not
  // already allow turns every request into two, and this one is sent on all of
  // them.
  const auth = token ? `&token=${encodeURIComponent(token)}` : "";

  // Fail here rather than in a poll loop nobody is watching.
  try {
    const probe = await fetch(`${bridge}/_bridge/status?machine=${encodeURIComponent(machine)}${auth}`);
    if (probe.status === 401) {
      throw Object.assign(new Error(
        `${bridge} wants a token. It prints one when it starts; pass it as token: "..."`
      ), { unauthorised: true });
    }
  } catch (err) {
    if (err.unauthorised) throw err;
    throw new Error(
      `nothing is listening at ${bridge}. Start it first:\n\n    node tools/bridge.mjs\n`
    );
  }

  let running = true;
  const decoder = new TextDecoder();

  async function answer(job) {
    const started = performance.now();
    try {
      const response = await net.request({
        port, method: job.method, path: job.path, headers: job.headers,
        body: job.body ? bytesFrom(job.body) : null
      });
      onEvent({ type: "served", path: job.path, status: response.status,
                bytes: response.body.length, ms: Math.round((performance.now() - started) * 10) / 10 });
      return {
        id: job.id, status: response.status, headers: response.headers,
        body: base64From(response.body)
      };
    } catch (err) {
      onEvent({ type: "failed", path: job.path, error: err.message });
      return {
        id: job.id, status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
        body: base64From(new TextEncoder().encode(`${err.message}\n`))
      };
    }
  }

  async function loop() {
    let job = null;
    while (running) {
      // Either ask for work, or hand back an answer and take the next job with
      // the same request. The second form is why this is not slow: a browser
      // holds only so many connections to one host, and posting an answer
      // separately from collecting the next one made them queue behind each
      // other.
      let response;
      try {
        response = job
          ? await fetch(`${bridge}/_bridge/response?machine=${encodeURIComponent(machine)}${auth}`, {
              method: "POST",
              // text/plain rather than application/json, deliberately: it is a
              // content type CORS lets through without asking first, and a
              // preflight on every answer is a round trip per request.
              headers: { "Content-Type": "text/plain" },
              body: JSON.stringify(await answer(job))
            })
          : await fetch(`${bridge}/_bridge/pending?machine=${encodeURIComponent(machine)}${auth}`);
      } catch (err) {
        if (!running) return;
        onEvent({ type: "disconnected", error: err.message });
        job = null;
        await new Promise((r) => setTimeout(r, 1000));  // the bridge went away; wait for it
        continue;
      }

      job = null;
      if (response.status === 204) continue;            // nothing arrived; ask again
      const next = await response.json().catch(() => null);
      if (next && next.id) job = next;
    }
  }

  const loops = Array.from({ length: concurrency }, () => loop());
  onEvent({ type: "connected", bridge, machine, concurrency });

  return {
    bridge, machine,
    stop() {
      running = false;
      onEvent({ type: "stopped", bridge, machine });
      return Promise.allSettled(loops);
    }
  };
}

function bytesFrom(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64From(bytes) {
  let binary = "";
  // In chunks: String.fromCharCode with a megabyte of arguments overflows the
  // stack, and a machine serving a file is exactly where that would happen.
  for (let at = 0; at < bytes.length; at += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(at, at + 8192));
  }
  return btoa(binary);
}
