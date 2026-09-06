// Tests for the publish lane.
//
// The lane exists so a machine can put a website somewhere a static host will
// serve it, which means the thing under test is a tree: what paths it holds,
// what bytes are under them, and what happens on the second publish. None of
// that needs a guest, so none of it is mocked either -- the host is the same
// in-memory host the engine's own tests use.
//
// Run with: node src/test-publish.mjs

import { publish, prepare, missingIndex } from "./core/publish.js";
import { blobId } from "./core/objectid.js";

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

const enc = new TextEncoder();
const dec = new TextDecoder();
const file = (path, text) => ({ path, bytes: enc.encode(text) });

/** The same shape the engine's own tests use: git objects in a Map. */
class Host {
  constructor() {
    this.objects = new Map();
    this.trees = new Map();
    this.commits = new Map();
    this.branches = new Map();
    this.calls = [];
    this._n = 0;
  }
  async resolveRef(branch) {
    const head = this.branches.get(branch);
    return head ? { commit: head, tree: this.commits.get(head).tree } : null;
  }
  async readTree(tree) { return this.trees.get(tree) || []; }
  async readObject(id) { return this.objects.get(id); }
  async commit({ branch, message, files, parent = null, orphan = false }) {
    this.calls.push({ branch, message, parent, orphan, paths: files.map((f) => f.path) });
    // Stored by the id the caller computed, exactly as the in-memory host the
    // engine's tests use does -- and as the batch-commit adapters do. A double
    // that invents its own ids would pass a caller that supplies none, and hide
    // the one bug that matters here: every file published as the same blob.
    const entries = files.map((f) => {
      if (!f.id) throw new Error(`${f.path} was handed over with no object id`);
      this.objects.set(f.id, f.bytes);
      return { path: f.path, id: f.id, size: f.bytes.length };
    });
    const tree = `t${++this._n}`;
    this.trees.set(tree, entries);
    const commit = `c${++this._n}`;
    this.commits.set(commit, { tree, parents: orphan || !parent ? [] : [parent] });
    this.branches.set(branch, commit);
    return { commit, requests: files.length + 3 };
  }
}

/** Read a published site back the way a host serving it would. */
async function siteAt(host, branch) {
  const head = await host.resolveRef(branch);
  if (!head) return null;
  const entries = await host.readTree(head.tree);
  const out = {};
  for (const entry of entries) out[entry.path] = dec.decode(await host.readObject(entry.id));
  return out;
}

// ------------------------------------------------------------------ preparing

console.log("\nputting a collected site in order");
{
  eq("a leading slash is not a difference worth failing over",
     prepare([file("/index.html", "x")]).map((f) => f.path), ["index.html"]);
  eq("nor is a dot segment",
     prepare([file("./css/site.css", "x")]).map((f) => f.path), ["css/site.css"]);
  eq("nor a doubled separator",
     prepare([file("css//site.css", "x")]).map((f) => f.path), ["css/site.css"]);
  eq("a windows separator is still a separator",
     prepare([file("css\\site.css", "x")]).map((f) => f.path), ["css/site.css"]);

  eq("what comes out is sorted, so the same site is the same tree",
     prepare([file("b.html", "x"), file("a.html", "x"), file("a/b.html", "x")]).map((f) => f.path),
     ["a.html", "a/b.html", "b.html"]);

  let refused = 0;
  for (const bad of [
    [file("../secrets", "x")],
    [file("a/../../b", "x")],
    [file("", "x")],
    [file("index.html", "x"), file("./index.html", "y")]
  ]) {
    try { prepare(bad); } catch { refused++; }
  }
  eq("climbing out, empty names and duplicates are all refused", refused, 4);

  const same = prepare([file("a", "x")])[0].bytes;
  check("bytes come through untouched", dec.decode(same) === "x");
}
{
  check("a site with an index at the root has nothing to say",
        missingIndex([file("index.html", "x"), file("a.css", "y")]) === null);
  check("one without says so",
        /no index\.html/.test(missingIndex([file("a.html", "x")])));
  check("and points at the one further down when there is one",
        /one directory further down/.test(missingIndex([file("www/index.html", "x")])),
        missingIndex([file("www/index.html", "x")]));
}

// ----------------------------------------------------------------- publishing

console.log("\npublishing");
{
  const host = new Host();
  const result = await publish({
    host, branch: "site", message: "first",
    files: [file("index.html", "<h1>hello</h1>"), file("style.css", "body{}")]
  });
  eq("it reports what it wrote", [result.files, result.branch], [2, "site"]);
  eq("and how much", result.bytes, "<h1>hello</h1>".length + "body{}".length);
  check("with a commit", !!result.commit);

  const site = await siteAt(host, "site");
  eq("the tree holds the site, by path", Object.keys(site).sort(), ["index.html", "style.css"]);
  eq("with the bytes under them", site["index.html"], "<h1>hello</h1>");
  eq("each path its own, not whichever was written last", site["style.css"], "body{}");

  eq("the first publish has no parent", host.calls[0].parent, null);
  eq("and carries the message", host.calls[0].message, "first");

  // The bug this guards: files handed over without ids, every one of them
  // stored under the same key, every path in the tree resolving to whichever
  // was written last.
  const entries = await host.readTree((await host.resolveRef("site")).tree);
  eq("every file has an object id", entries.filter((e) => !!e.id).length, 2);
  check("and they are not the same id", entries[0].id !== entries[1].id);
  eq("which is the git blob id of its own contents",
     entries.find((e) => e.path === "style.css").id, await blobId(enc.encode("body{}")));
}
{
  const host = new Host();
  await publish({ host, branch: "site", files: [file("index.html", "one")] });
  const first = (await host.resolveRef("site")).commit;
  const second = await publish({ host, branch: "site", files: [file("index.html", "two")] });
  eq("a second publish builds on the first", host.calls[1].parent, first);
  eq("so the history is a chain", host.commits.get(second.commit).parents, [first]);
  eq("and the site is the new one", (await siteAt(host, "site"))["index.html"], "two");

  const orphaned = await publish({
    host, branch: "site", files: [file("index.html", "three")], orphan: true
  });
  eq("publishing as an orphan drops what came before",
     host.commits.get(orphaned.commit).parents.length, 0);
  eq("and still serves", (await siteAt(host, "site"))["index.html"], "three");
}
{
  const host = new Host();
  await publish({ host, branch: "site", files: [file("index.html", "x"), file("old.html", "y")] });
  await publish({ host, branch: "site", files: [file("index.html", "x")] });
  const site = await siteAt(host, "site");
  eq("a file that is gone from the site is gone from the tree",
     Object.keys(site), ["index.html"]);
}
{
  // The lane's whole point: a machine's disk and its site never share a ref.
  const host = new Host();
  const chunk = enc.encode("not html");
  await host.commit({ branch: "machine-1", message: "chunks", files: [
    { path: "chunks/0000", bytes: chunk, id: await blobId(chunk) }
  ] });
  await publish({ host, branch: "machine-1-site", files: [file("index.html", "html")] });

  const disk = await siteAt(host, "machine-1");
  const site = await siteAt(host, "machine-1-site");
  eq("the disk lane is untouched", Object.keys(disk), ["chunks/0000"]);
  eq("and the site lane holds only the site", Object.keys(site), ["index.html"]);
  check("they are different commits",
        (await host.resolveRef("machine-1")).commit !== (await host.resolveRef("machine-1-site")).commit);
}
{
  const host = new Host();
  let refused = null;
  try { await publish({ host, branch: "site", files: [] }); } catch (err) { refused = err.message; }
  check("publishing nothing is refused rather than committed", refused !== null);
  check("with a reason a person can act on", /nothing to publish/.test(refused || ""), refused);

  let noBranch = null;
  try { await publish({ host, files: [file("a", "b")] }); } catch (err) { noBranch = err.message; }
  check("and so is publishing to no branch in particular", noBranch !== null);
}
{
  const host = new Host();
  const many = Array.from({ length: 40 }, (_, i) => file(`page-${i}.html`, `page ${i}`));
  const result = await publish({ host, branch: "site", files: many });
  eq("a site of forty files is one commit", host.calls.length, 1);
  eq("holding all of them", result.files, 40);
  const site = await siteAt(host, "site");
  eq("and they are all there", Object.keys(site).length, 40);
  eq("in order", Object.keys(site)[0], "page-0.html");
}
{
  const events = [];
  const host = new Host();
  await publish({
    host, branch: "site", files: [file("index.html", "x")],
    onEvent: (event) => events.push(event.type)
  });
  eq("it says what it is doing", events, ["publishing", "published"]);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
process.exit(0);
