// A way out, for a guest that has none.
//
// The machine's network reaches exactly one host: the tab. That is the whole
// design, and it is why nothing in a guest can phone home. It is also a wall:
// no package mirror, no API, no git over HTTPS.
//
// This is a door in that wall, and it is deliberately a narrow one. The guest
// speaks plain HTTP to a proxy on the tab's own address; the tab satisfies each
// request with fetch() and hands the answer back. Nothing else changes: the
// guest still has no route to anywhere, and every byte that leaves is a byte
// this file decided to let out.
//
// Three things it cannot do, and saying so is more useful than discovering them.
//
// It cannot tunnel TLS. A CONNECT would have to be answered by terminating the
// guest's TLS in the tab, which means holding a certificate the guest trusts and
// reading everything inside -- a man in the middle by construction. It refuses
// instead, and says why.
//
// It cannot reach a host that does not allow cross-origin reads. The tab's fetch
// obeys the browser, and the browser obeys CORS. Measured from a page on
// localhost: api.github.com, raw.githubusercontent.com, registry.npmjs.org and
// httpbin.org answer; dl-cdn.alpinelinux.org and example.com do not. A package
// mirror is therefore still out of reach, which is why this project vendors what
// a guest needs rather than fetching it.
//
// And it cannot be on by default. Until it is running, a machine cannot send
// anything anywhere, which is a property worth keeping unless somebody asks for
// it to go.

import { serve, encodeResponse } from "./http.js";

/** Where the guest looks for it. Its own address, on a port a server would not use. */
export const PORT = 8080;
export const PROXY_URL = `http://10.0.2.2:${PORT}`;

/** Headers that are about one hop and must not be forwarded to the next. */
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
]);

/**
 * Open the door.
 *
 * @param {Object} options
 * @param {Object} options.net a V86Net, or anything with a `.stack`
 * @param {string[]} options.allow hostnames the guest may reach. Exact, or a
 *        leading dot for a suffix: ".github.com" admits api.github.com.
 * @param {number} [options.port]
 * @param {number} [options.maxBytes] refuse a response larger than this
 * @param {(event: Object) => void} [options.onEvent]
 * @returns {{port: number, close: () => void, allowed: string[]}}
 */
export function startGateway({ net, allow = [], port = PORT, maxBytes = 32 * 1024 * 1024, onEvent = () => {} } = {}) {
  if (!net) throw new Error("a network is required");
  const stack = net.stack || net;
  const allowed = allow.map((host) => String(host).toLowerCase());

  if (!allowed.length) {
    throw new Error(
      "a gateway with an empty allowlist would refuse everything, which is what " +
      "not starting one already does. Name the hosts a machine may reach."
    );
  }

  const permitted = (hostname) => {
    const host = hostname.toLowerCase();
    return allowed.some((entry) => entry.startsWith(".")
      ? host === entry.slice(1) || host.endsWith(entry)
      : host === entry);
  };

  const listener = serve(stack, {
    port,
    handler: async (request) => {
      if (request.method === "CONNECT") {
        onEvent({ type: "refused", reason: "connect", target: request.target });
        return text(405,
          "This gateway cannot tunnel TLS. Answering CONNECT would mean terminating\n" +
          "the guest's TLS in the browser tab and reading everything inside it, which\n" +
          "is a man in the middle however well meant. Ask for a http:// or https://\n" +
          "URL through the proxy instead, and the tab will fetch it for you.\n");
      }

      let url;
      try {
        url = new URL(request.target);
      } catch {
        onEvent({ type: "refused", reason: "not-absolute", target: request.target });
        return text(400,
          `"${request.target}" is not an absolute URL. This is a proxy, so a request\n` +
          `to it carries the whole address: set http_proxy=${PROXY_URL} and use an\n` +
          `ordinary client.\n`);
      }

      if (!permitted(url.hostname)) {
        onEvent({ type: "denied", host: url.hostname, target: request.target });
        return text(403,
          `${url.hostname} is not on this machine's allowlist.\n\n` +
          `Allowed: ${allowed.join(", ")}\n\n` +
          `A machine can reach what it was told it may reach and nothing else. ` +
          `Widen the list\ndeliberately, in the page that started the gateway.\n`);
      }

      const headers = {};
      for (const [name, value] of Object.entries(request.headers)) {
        if (!HOP_BY_HOP.has(name.toLowerCase())) headers[name] = value;
      }

      const started = Date.now();
      let response;
      try {
        response = await fetch(url.href, {
          method: request.method,
          headers,
          body: request.body && request.body.length ? request.body : undefined,
          redirect: "follow"
        });
      } catch (err) {
        // Nearly always CORS, and nearly always confusing without being told so.
        onEvent({ type: "unreachable", host: url.hostname, error: err.message });
        return text(502,
          `${url.hostname} could not be read from this browser: ${err.message}.\n\n` +
          `The tab fetches on the machine's behalf, so the browser's rules apply: a\n` +
          `host that does not allow cross-origin reads cannot be reached this way, ` +
          `however\nreachable it is from a terminal.\n`);
      }

      const body = new Uint8Array(await response.arrayBuffer());
      if (body.length > maxBytes) {
        onEvent({ type: "too-large", host: url.hostname, bytes: body.length });
        return text(502, `${url.hostname} answered with ${body.length} bytes, more than this gateway will carry.\n`);
      }

      const out = {};
      for (const [name, value] of response.headers.entries()) {
        if (!HOP_BY_HOP.has(name.toLowerCase())) out[name] = value;
      }
      onEvent({
        type: "fetched", host: url.hostname, path: url.pathname,
        status: response.status, bytes: body.length, ms: Date.now() - started
      });
      return { status: response.status, statusText: response.statusText, headers: out, body };
    }
  });

  onEvent({ type: "open", port, allowed });
  return {
    port, allowed,
    close: () => { listener.close(); onEvent({ type: "closed", port }); }
  };
}

function text(status, body) {
  return { status, headers: { "Content-Type": "text/plain; charset=utf-8" }, body };
}

export { encodeResponse };
