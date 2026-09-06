// One writer at a time.
//
// Conflict retry in the sync engine handles two writes that meet: one lands, the
// other rebuilds on top of it. What it cannot handle is two tabs that both
// believe they own a machine. Each has its own device, its own dirty set, and
// its own idea of what the disk contains; whichever syncs second rebuilds a
// manifest from a device that never saw the first one's writes, and the first
// one's work is gone. Retrying is the wrong tool because nothing went wrong --
// both writes were valid, and both were meant.
//
// So a machine is held rather than shared. The holder is written to a branch of
// its own, and the thing that makes it a lock rather than a note is the host: a
// fast-forward-only reference update rejects a second writer who started from
// the same commit. That is a compare-and-swap, and it is what `casRef` in the
// host capabilities means.
//
// It is a lease and not a lock because a browser tab can close without warning,
// and a lock nobody can release is worse than no lock. A lease expires. Taking
// one that has expired is allowed, and is still arbitrated by the same
// compare-and-swap, so two tabs reclaiming an abandoned machine cannot both win.
//
// Where the host has no compare-and-swap -- GitLab and Forgejo, measured, not
// assumed -- this still records who holds a machine and still refuses the
// obvious collisions. It cannot promise exclusion, and says so rather than
// implying a guarantee the host does not offer.

import { blobId } from "./objectid.js";

/** Where the holder is recorded, inside the lease branch's tree. */
export const FILE = "lease.json";

/** Long enough to survive a slow sync, short enough that a dead tab frees up. */
export const TTL_MS = 10 * 60 * 1000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class LeaseError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "LeaseError";
    Object.assign(this, details);
  }
}

export class Lease {
  /**
   * @param {Object} options
   * @param {Object} options.host
   * @param {string} options.branch the machine's branch; the lease takes its own
   * @param {string} options.holder who is asking, stable for as long as they hold it
   * @param {number} [options.ttlMs]
   * @param {() => number} [options.now]
   * @param {(event: Object) => void} [options.onEvent]
   */
  constructor({ host, branch, holder, ttlMs = TTL_MS, now = () => Date.now(), onEvent } = {}) {
    if (!host) throw new Error("a host is required");
    if (!branch) throw new Error("the machine's branch is required");
    if (!holder) throw new Error("a holder is required: whoever takes a lease has to be nameable");
    this.host = host;
    this.branch = `${branch}-lease`;
    this.machineBranch = branch;
    this.holder = holder;
    this.ttlMs = ttlMs;
    this._now = now;
    this.onEvent = onEvent || (() => {});
    this.state = null;
  }

  /** Whether this host can actually enforce what a lease promises. */
  get enforced() {
    const capabilities = this.host.constructor && this.host.constructor.capabilities;
    return !!(capabilities && capabilities.casRef);
  }

  /** The lease as it stands, or null if nobody has ever taken one. */
  async read() {
    const head = await this.host.resolveRef(this.branch);
    if (!head) return null;
    const entries = await this.host.readTree(head.tree);
    const entry = entries.find((e) => e.path === FILE);
    if (!entry) return null;
    const bytes = await this.host.readObject(entry.id);
    return { ...JSON.parse(decoder.decode(bytes)), commit: head.commit };
  }

  /**
   * Take the machine, or say who has it.
   *
   * @returns {Promise<{held: boolean, holder: string, expiresAt: number, enforced: boolean}>}
   * @throws {LeaseError} when somebody else holds it and has not let it expire
   */
  async acquire({ steal = false } = {}) {
    const current = await this.read();
    const now = this._now();

    if (current && current.holder !== this.holder && current.state === "held") {
      const remaining = current.expiresAt - now;
      if (remaining > 0 && !steal) {
        throw new LeaseError(
          `${this.machineBranch} is held by ${current.holder} for another ` +
          `${Math.ceil(remaining / 1000)}s. Syncing from here would commit a disk ` +
          `that never saw their writes.`,
          { holder: current.holder, expiresAt: current.expiresAt, remainingMs: remaining }
        );
      }
      this.onEvent({
        type: remaining > 0 ? "stolen" : "expired",
        from: current.holder, byMs: -remaining
      });
    }

    return this._write("held", current);
  }

  /**
   * Push the expiry out. The holder has to still be the holder: a renewal that
   * finds somebody else in possession is not a renewal, it is a discovery.
   */
  async renew() {
    const current = await this.read();
    if (!current || current.holder !== this.holder || current.state !== "held") {
      throw new LeaseError(
        `${this.machineBranch} is no longer held by ${this.holder}` +
        (current ? `; ${current.state === "held" ? current.holder + " has it" : "it was released"}` : ""),
        { holder: current ? current.holder : null }
      );
    }
    return this._write("held", current);
  }

  /** Give it up. Cheaper for the next holder than waiting out the expiry. */
  async release() {
    const current = await this.read();
    if (!current || current.holder !== this.holder) return { released: false };
    await this._write("released", current);
    return { released: true };
  }

  /** Whether this holder may write to the machine right now. */
  async held() {
    const current = await this.read();
    if (!current) return false;
    return current.holder === this.holder &&
           current.state === "held" &&
           current.expiresAt > this._now();
  }

  /**
   * The check a writer makes before writing.
   *
   * Separate from held() because a caller about to commit wants the reason, not
   * a boolean: what it does next depends on whether the lease lapsed or somebody
   * else took it.
   */
  async assertHeld() {
    const current = await this.read();
    if (!current || current.state !== "held") {
      throw new LeaseError(
        `nothing holds ${this.machineBranch}. Take the lease before writing to it.`,
        { holder: null }
      );
    }
    if (current.holder !== this.holder) {
      throw new LeaseError(
        `${this.machineBranch} is held by ${current.holder}, not by ${this.holder}.`,
        { holder: current.holder, expiresAt: current.expiresAt }
      );
    }
    if (current.expiresAt <= this._now()) {
      throw new LeaseError(
        `the lease on ${this.machineBranch} expired ` +
        `${Math.ceil((this._now() - current.expiresAt) / 1000)}s ago. Renew it before writing: ` +
        `another tab may have taken the machine in the meantime.`,
        { holder: this.holder, expiresAt: current.expiresAt, expired: true }
      );
    }
    return true;
  }

  async _write(state, current) {
    const now = this._now();
    const record = {
      holder: this.holder,
      state,
      machine: this.machineBranch,
      acquiredAt: current && current.holder === this.holder && current.acquiredAt
        ? current.acquiredAt : now,
      renewedAt: now,
      expiresAt: state === "held" ? now + this.ttlMs : now,
      enforced: this.enforced
    };
    const bytes = encoder.encode(JSON.stringify(record, null, 2) + "\n");

    try {
      const result = await this.host.commit({
        branch: this.branch,
        message: `${state} by ${this.holder}`,
        files: [{ path: FILE, bytes, id: await blobId(bytes) }],
        parent: current ? current.commit : null,
        branchExists: !!current
      });
      this.state = { ...record, commit: result.commit };
      this.onEvent({ type: state, holder: this.holder, expiresAt: record.expiresAt });
      return { ...this.state, held: state === "held", enforced: this.enforced };
    } catch (err) {
      // A rejected fast-forward is the compare-and-swap doing its job: somebody
      // moved the lease between the read and the write, which is exactly the
      // race a lease exists to settle.
      if (err.status === 422 || /fast.?forward|not a fast/i.test(err.message || "")) {
        const now = await this.read();
        throw new LeaseError(
          `${this.machineBranch} was taken by ${now ? now.holder : "somebody else"} ` +
          `while this tab was asking for it.`,
          { holder: now ? now.holder : null, raced: true }
        );
      }
      throw err;
    }
  }
}

/**
 * A name for whoever is asking.
 *
 * Stable for as long as a tab lives and different between tabs, which is the
 * whole requirement: two tabs must not accidentally share one.
 */
export function holderName(prefix = "tab") {
  const random = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${random}`;
}
