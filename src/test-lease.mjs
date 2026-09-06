// Tests for the lease.
//
// The thing being tested is a race, so the host double has to lose the race the
// way a real one does: a commit whose parent is not the branch's current head is
// rejected. That single rule is what turns a note about who is holding a machine
// into a lock, and a double without it would let both writers win and report
// success twice.
//
// Time is injected. A lease is mostly a statement about expiry, and a test that
// waited for one would be a test nobody runs.
//
// Run with: node src/test-lease.mjs

import { Lease, LeaseError, holderName, FILE } from "./core/lease.js";

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
const dec = new TextDecoder();

/** A host that enforces fast-forward-only updates, as GitHub's refs do. */
class Host {
  static capabilities = { casRef: true, batchCommit: false, orphanCommit: true };
  constructor() {
    this.objects = new Map(); this.trees = new Map();
    this.commits = new Map(); this.branches = new Map();
    this.rejected = 0; this._n = 0;
  }
  async resolveRef(branch) {
    const head = this.branches.get(branch);
    return head ? { commit: head, tree: this.commits.get(head).tree } : null;
  }
  async readTree(tree) { return this.trees.get(tree) || []; }
  async readObject(id) { return this.objects.get(id); }
  async commit({ branch, message, files, parent = null }) {
    const current = this.branches.get(branch) || null;
    if (current !== parent) {
      this.rejected++;
      const err = new Error("Update is not a fast forward");
      err.status = 422;
      throw err;
    }
    for (const f of files) {
      if (!f.id) throw new Error(`${f.path} was handed over with no object id`);
      this.objects.set(f.id, f.bytes);
    }
    const tree = `t${++this._n}`;
    this.trees.set(tree, files.map((f) => ({ path: f.path, id: f.id, size: f.bytes.length })));
    const commit = `c${++this._n}`;
    this.commits.set(commit, { tree, parents: parent ? [parent] : [], message });
    this.branches.set(branch, commit);
    return { commit, requests: files.length + 3 };
  }
}

/** A host with no compare-and-swap, as GitLab and Forgejo were measured to be. */
class LooseHost extends Host {
  static capabilities = { casRef: false, batchCommit: true, orphanCommit: false };
  async commit(options) {
    // Accepts whatever it is given, whoever moved last.
    const current = this.branches.get(options.branch) || null;
    return super.commit({ ...options, parent: current });
  }
}

let clock = 1_000_000;
const now = () => clock;
const lease = (host, holder, options = {}) =>
  new Lease({ host, branch: "machine-1", holder, now, ...options });

// ---------------------------------------------------------------- taking one

console.log("\ntaking a machine");
{
  const host = new Host();
  const one = lease(host, "tab-a");
  const taken = await one.acquire();
  check("a machine with no lease can be taken", taken.held);
  eq("by whoever asked", taken.holder, "tab-a");
  eq("and it is enforced on a host with compare-and-swap", taken.enforced, true);
  check("the holder holds it", await one.held());

  const record = await one.read();
  eq("which is recorded on a branch of its own", record.machine, "machine-1");
  eq("in a file", record.state, "held");
  check("with an expiry", record.expiresAt > clock);
  eq("on the lease branch, not the machine's", one.branch, "machine-1-lease");
  check("and the machine's own branch is untouched",
        (await host.resolveRef("machine-1")) === null);
}
{
  const host = new Host();
  await lease(host, "tab-a").acquire();
  const two = lease(host, "tab-b");
  let refused = null;
  try { await two.acquire(); } catch (err) { refused = err; }
  check("a second tab is refused", refused instanceof LeaseError);
  eq("and told who has it", refused.holder, "tab-a");
  check("and for how long", refused.remainingMs > 0);
  check("the message says what would happen if it went ahead",
        /never saw their writes/.test(refused.message), refused.message);
  check("the second tab does not hold it", !(await two.held()));
}

// ------------------------------------------------------------------- expiry

console.log("\nwhen a tab goes away");
{
  const host = new Host();
  const one = lease(host, "tab-a", { ttlMs: 60000 });
  await one.acquire();
  const two = lease(host, "tab-b", { ttlMs: 60000 });

  clock += 59000;
  let refused = null;
  try { await two.acquire(); } catch (err) { refused = err; }
  check("a lease that has not expired still refuses", refused instanceof LeaseError);

  clock += 2000;
  const events = [];
  const three = new Lease({ host, branch: "machine-1", holder: "tab-b", ttlMs: 60000, now,
                            onEvent: (e) => events.push(e.type) });
  const taken = await three.acquire();
  check("an expired one can be taken", taken.held);
  eq("and the taking is noticed", events[0], "expired");
  check("the old holder no longer holds it", !(await one.held()));
}
{
  const host = new Host();
  const one = lease(host, "tab-a", { ttlMs: 60000 });
  const first = await one.acquire();
  clock += 30000;
  const renewed = await one.renew();
  check("a holder can push the expiry out", renewed.expiresAt > clock + 59000);
  eq("without pretending it was acquired later", renewed.acquiredAt, first.acquiredAt);
  check("though it records when it was renewed", renewed.renewedAt > first.renewedAt);

  clock += 59000;
  check("so it is still held where it would otherwise have lapsed", await one.held());
}
{
  const host = new Host();
  const one = lease(host, "tab-a", { ttlMs: 60000 });
  await one.acquire();
  const two = lease(host, "tab-b", { ttlMs: 60000 });
  clock += 61000;
  await two.acquire();

  let lost = null;
  try { await one.renew(); } catch (err) { lost = err; }
  check("renewing a lease somebody else took is refused", lost instanceof LeaseError);
  check("and says who has it now", /tab-b/.test(lost.message), lost.message);
}

// ------------------------------------------------------------------ writing

console.log("\nbefore writing");
{
  const host = new Host();
  const one = lease(host, "tab-a", { ttlMs: 60000 });
  await one.acquire();
  check("a holder may write", await one.assertHeld());

  clock += 61000;
  let expired = null;
  try { await one.assertHeld(); } catch (err) { expired = err; }
  check("a lapsed lease refuses the write", expired instanceof LeaseError);
  check("and says so as a lapse rather than as a theft", expired.expired === true);
  check("naming what may have happened meanwhile",
        /another tab may have taken/.test(expired.message), expired.message);
}
{
  const host = new Host();
  const one = lease(host, "tab-a");
  let none = null;
  try { await one.assertHeld(); } catch (err) { none = err; }
  check("writing with no lease at all is refused", none instanceof LeaseError);
  check("with the instruction, not just the fact",
        /Take the lease before writing/.test(none.message), none.message);
}

// ------------------------------------------------------------------ release

console.log("\ngiving it up");
{
  const host = new Host();
  const one = lease(host, "tab-a");
  await one.acquire();
  eq("a holder can release", (await one.release()).released, true);
  check("after which nobody holds it", !(await one.held()));

  const two = lease(host, "tab-b");
  const taken = await two.acquire();
  check("and the next tab takes it without waiting for an expiry", taken.held);

  eq("releasing something you do not hold does nothing",
     (await one.release()).released, false);
}

// --------------------------------------------------------------- the race

console.log("\nthe race the lease exists for");
{
  // Both tabs read the same state and both decide to take it. On a host with
  // fast-forward-only updates exactly one can win, and the loser is told.
  const host = new Host();
  const a = lease(host, "tab-a");
  const b = lease(host, "tab-b");

  const results = await Promise.allSettled([a.acquire(), b.acquire()]);
  const won = results.filter((r) => r.status === "fulfilled");
  const lost = results.filter((r) => r.status === "rejected");
  eq("exactly one wins", won.length, 1);
  eq("and exactly one loses", lost.length, 1);
  check("the loser is told it was a race", lost[0].reason.raced === true ||
        lost[0].reason instanceof LeaseError, String(lost[0].reason));
  check("the host rejected the second write", host.rejected >= 1);

  const holder = (await a.read()).holder;
  check("and the machine has exactly one holder", holder === "tab-a" || holder === "tab-b");
}
{
  // The same on a host that cannot arbitrate. It still records and still refuses
  // the obvious case, and it does not claim to be enforcing anything.
  const host = new LooseHost();
  const a = new Lease({ host, branch: "machine-1", holder: "tab-a", now });
  const taken = await a.acquire();
  eq("a host without compare-and-swap says so", taken.enforced, false);

  const b = new Lease({ host, branch: "machine-1", holder: "tab-b", now });
  let refused = null;
  try { await b.acquire(); } catch (err) { refused = err; }
  check("a lease that is plainly held is still refused there", refused instanceof LeaseError);
}
{
  const names = new Set(Array.from({ length: 200 }, () => holderName()));
  check("holder names do not collide in practice", names.size === 200);
  check("and say what they are", [...names][0].startsWith("tab-"));
}


// ------------------------------------------------- the engine refusing to write

console.log("\nwhat the engine does with one");
{
  const { Machine } = await import("./core/machine.js");
  const { MemoryDevice } = await import("./device/memory.js");
  const { Governor } = await import("./core/governor.js");

  const host = new Host();
  host.requestCount = 0;
  const holder = "tab-a";
  const held = lease(host, holder, { ttlMs: 60000 });
  await held.acquire();

  const machine = (leaseFor) => new Machine({
    host, branch: "machine-1", lease: leaseFor,
    device: new MemoryDevice({ diskSize: 1024 * 1024 }),
    governor: new Governor({ ratePerMin: 6e6, concurrency: 4 })
  });

  const mine = machine(held);
  await mine.load({ diskSize: 1024 * 1024, chunkSize: 256 * 1024, base: "blank", baseIsBlank: true });
  const ok = await mine.sync({ message: "the holder writes" });
  check("the holder syncs", !!ok.commit);

  // A second tab, with its own lease object, holding nothing.
  const other = lease(host, "tab-b", { ttlMs: 60000 });
  const theirs = machine(other);
  await theirs.load({ diskSize: 1024 * 1024, chunkSize: 256 * 1024, base: "blank", baseIsBlank: true });
  theirs.markHydrated();
  let refused = null;
  try { await theirs.sync({ message: "the other tab writes" }); } catch (err) { refused = err; }
  check("a tab that does not hold the machine cannot sync", refused instanceof LeaseError);
  check("and is told who does", /tab-a/.test(refused.message), refused && refused.message);

  clock += 61000;
  let lapsed = null;
  try { await mine.sync({ message: "after the lease lapsed" }); } catch (err) { lapsed = err; }
  check("and neither can the holder once it has lapsed", lapsed instanceof LeaseError);
  check("which is a different message from being outbid", lapsed.expired === true);

  await held.renew();
  const again = await mine.sync({ message: "renewed" });
  check("renewing lets it write again", !!again.commit);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
process.exit(0);
