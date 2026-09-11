// Signing in to GitHub from something that is not a browser.
//
// A page cannot do this. GitHub's token endpoints send no CORS headers -- which
// is how a browser is kept out of OAuth secrets -- and every route out of a
// machine ends at the tab's own `fetch`, so the wall is the same from inside a
// guest. The bridge is not a browser, and that is the whole of why this lives
// there rather than in the page.
//
// The device flow is the one OAuth grant designed for a client that cannot keep
// a secret: the client id is public, there is no client secret at all, and the
// user authorises out of band by typing a short code into github.com. So the
// bridge -- a Node process on the user's own machine, already there for curl --
// can complete it with nothing to deploy and nothing to keep.
//
// No timers. Polling is driven by whoever asks, and the interval GitHub asks for
// is enforced here rather than trusted to the caller: `poll` returns "pending"
// without touching the network when it is called too soon. A timer loop would
// have to be cancelled on every exit path, and a bridge that leaks one keeps the
// process alive after the tab has gone.
//
// Handles are random because the bridge is reachable by anything that can reach
// loopback. A guessable handle would let one local process collect a token the
// user authorised for another. A token is handed out exactly once and the entry
// is forgotten in the same breath.

import { randomBytes } from "node:crypto";

const DEFAULT_BASE = "https://github.com";
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";

export class DeviceLogin {
  /**
   * @param {Object} options
   * @param {string} options.clientId          public; a device flow has no secret
   * @param {string} [options.scope]           OAuth Apps use it; GitHub Apps ignore it
   * @param {string} [options.base]            override for Enterprise, or for a test
   * @param {typeof fetch} [options.fetch]
   * @param {() => number} [options.now]
   */
  constructor({ clientId, scope = "", base = DEFAULT_BASE, fetch: doFetch = globalThis.fetch, now = Date.now } = {}) {
    if (!clientId) throw new Error("a client id is required");
    this.clientId = clientId;
    this.scope = scope;
    this.base = String(base).replace(/\/$/, "");
    this.fetch = doFetch;
    this.now = now;
    this.pending = new Map();
  }

  async _post(path, fields) {
    const response = await this.fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams(fields).toString()
    });
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      // GitHub answers HTML when the app is not set up for this, and a parse
      // error would otherwise surface as a stack trace with nothing to act on.
      throw new Error(
        `${this.base}${path} did not answer JSON (${response.status}). ` +
        `Is the device flow enabled for this app, and is the client id right?`
      );
    }
  }

  /** Ask GitHub for a code the user can type. */
  async start() {
    const answer = await this._post("/login/device/code", {
      client_id: this.clientId, ...(this.scope ? { scope: this.scope } : {})
    });
    if (answer.error) {
      // GitHub answers an unknown client id with a bare "Not Found" and no
      // description at all, which is the first thing anyone setting this up
      // will hit and the least useful thing it could say. Name the two causes.
      const detail = answer.error_description ||
        (/not.?found|unauthorized_client/i.test(answer.error)
          ? "GitHub does not recognise this client id, or the app it names does " +
            "not have the device flow enabled"
          : "no description");
      throw new Error(`${answer.error}: ${detail}`);
    }
    if (!answer.device_code || !answer.user_code) {
      throw new Error("GitHub did not return a device code");
    }

    const handle = randomBytes(16).toString("hex");
    const interval = Number(answer.interval) || 5;
    this.pending.set(handle, {
      deviceCode: answer.device_code,
      interval,
      nextAt: this.now() + interval * 1000,
      expiresAt: this.now() + (Number(answer.expires_in) || 900) * 1000
    });

    return {
      handle,
      userCode: answer.user_code,
      verificationUri: answer.verification_uri || `${this.base}/login/device`,
      expiresIn: Number(answer.expires_in) || 900,
      interval
    };
  }

  /**
   * Ask once whether the user has finished, honouring GitHub's interval.
   *
   * The token comes back exactly once: a caller that reads it and drops it has
   * lost it, which is better than a bridge holding one until the process ends.
   */
  async poll(handle) {
    const entry = this.pending.get(handle);
    if (!entry) return { status: "unknown" };

    if (this.now() > entry.expiresAt) {
      this.pending.delete(handle);
      return { status: "expired" };
    }
    if (this.now() < entry.nextAt) return { status: "pending", waiting: true };

    const answer = await this._post("/login/oauth/access_token", {
      client_id: this.clientId, device_code: entry.deviceCode, grant_type: GRANT
    });
    entry.nextAt = this.now() + entry.interval * 1000;

    if (answer.access_token) {
      this.pending.delete(handle);
      return { status: "done", token: answer.access_token, scope: answer.scope || "" };
    }

    switch (answer.error) {
      case "authorization_pending":
        return { status: "pending" };
      case "slow_down":
        // GitHub says how much slower; the specification's fallback is five more.
        entry.interval = Number(answer.interval) || entry.interval + 5;
        entry.nextAt = this.now() + entry.interval * 1000;
        return { status: "pending", interval: entry.interval };
      case "expired_token":
        this.pending.delete(handle);
        return { status: "expired" };
      case "access_denied":
        this.pending.delete(handle);
        return { status: "denied" };
      default:
        this.pending.delete(handle);
        return { status: "error", error: answer.error || "unknown",
                 description: answer.error_description || "" };
    }
  }

  forget(handle) { return this.pending.delete(handle); }
  get size() { return this.pending.size; }
}
