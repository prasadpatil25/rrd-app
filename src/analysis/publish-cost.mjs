// What a publish costs, and how that cost scales.
//
// The disk lane's cost is already measured: restore is the live set plus three
// requests, constant in history. The site lane had no measurement at all, which
// is the wrong way round for this repository -- it is the lane somebody would
// actually run every time they change a page.
//
// Two things are worth knowing before pointing a static host at a ref. How many
// requests a publish takes, because that is what a rate limit counts; and how
// many bytes go up, because base64 inflates a site by a third and the
// batch-commit hosts have a body limit rather than a request limit.
//
// No credentials and no network: the host is counted in process, and the numbers
// it produces are the same ones the adapters would issue. What it cannot measure
// is latency, which belongs to somebody's connection rather than to this design.
//
//   node src/analysis/publish-cost.mjs
//   node src/analysis/publish-cost.mjs --latex

import { publish } from "../core/publish.js";
import { compareHosts, GitHubHost, GitLabHost, ForgejoHost } from "../host/index.js";
import { blobId } from "../core/objectid.js";

const encoder = new TextEncoder();

/** A host that counts what a real one would be asked to do. */
class CountingHost {
  static capabilities = { casRef: true, batchCommit: false, orphanCommit: true };
  constructor({ empty = false } = {}) {
    this.requests = 0;
    this.bytes = 0;
    this.branches = new Map();
    this.commits = new Map();
    this.trees = new Map();
    this.objects = new Map();
    this.empty = empty;
    this.seeded = 0;
    this._n = 0;
  }
  async resolveRef(branch) {
    this.requests++;
    const head = this.branches.get(branch);
    return head ? { commit: head, tree: this.commits.get(head).tree } : null;
  }
  async readTree(tree) { this.requests++; return this.trees.get(tree) || []; }
  async readObject(id) { this.requests++; return this.objects.get(id); }
  async commit({ branch, files, parent = null }) {
    if (this.empty) {
      // What GitHub does with a repository that has never had a commit: one file
      // goes in through the contents API, and the ordinary path takes over.
      this.empty = false;
      this.seeded++;
      this.requests++;
      this.bytes += wire(files[0].bytes.length);
    }
    for (const file of files) {
      this.requests++;                       // one blob apiece
      this.bytes += wire(file.bytes.length);
      this.objects.set(file.id, file.bytes);
    }
    this.requests += 2;                      // the tree, then the commit
    const tree = `t${++this._n}`;
    this.trees.set(tree, files.map((f) => ({ path: f.path, id: f.id, size: f.bytes.length })));
    const commit = `c${++this._n}`;
    this.commits.set(commit, { tree, parents: parent ? [parent] : [] });
    this.requests++;                         // and the reference
    this.branches.set(branch, commit);
    return { commit, requests: files.length + 3 };
  }
}

/** Base64 inflates by four thirds, and JSON adds a little around it. */
function wire(bytes) {
  return Math.ceil(bytes * 4 / 3) + 64;
}

const page = (n) =>
  `<!doctype html><meta charset=utf-8><title>Page ${n}</title>` +
  `<link rel=stylesheet href="style.css"><h1>Page ${n}</h1>` +
  `<p>${"Text on a page. ".repeat(40)}`;

async function site(count) {
  const files = [{ path: "style.css", bytes: encoder.encode("body{font:15px monospace}".repeat(20)) }];
  for (let i = 0; i < count - 1; i++) {
    files.push({ path: i === 0 ? "index.html" : `page-${i}.html`, bytes: encoder.encode(page(i)) });
  }
  return files;
}

const SIZES = [1, 2, 5, 10, 25, 50, 100, 250];
const rows = [];

for (const count of SIZES) {
  const files = await site(count);
  const bytes = files.reduce((n, f) => n + f.bytes.length, 0);

  // A repository that already has a history: the ordinary case.
  const existing = new CountingHost();
  await publish({ host: existing, branch: "site", files, message: "first" });
  const before = existing.requests;
  await publish({ host: existing, branch: "site", files, message: "again" });
  const second = existing.requests - before;

  // And one that has never had a commit, which is where every site starts.
  const fresh = new CountingHost({ empty: true });
  await publish({ host: fresh, branch: "site", files, message: "first" });

  rows.push({
    files: count,
    siteBytes: bytes,
    firstRequests: fresh.requests,
    steadyRequests: second,
    wireBytes: existing.bytes / 2,
    inflation: (existing.bytes / 2) / bytes,
    seeded: fresh.seeded
  });
}

if (process.argv.includes("--latex")) {
  console.log("% cost of one publish, by site size; counted in process, no network");
  console.log("\\begin{tabular}{@{}rrrrr@{}}");
  console.log("\\toprule");
  console.log("files & site KB & req (first) & req (steady) & wire KB \\\\");
  console.log("\\midrule");
  for (const r of rows) {
    console.log(`${r.files} & ${(r.siteBytes / 1024).toFixed(1)} & ${r.firstRequests} & ` +
                `${r.steadyRequests} & ${(r.wireBytes / 1024).toFixed(1)} \\\\`);
  }
  console.log("\\bottomrule");
  console.log("\\end{tabular}");
} else {
  console.log("\nOne publish, by site size. Counted in process; no network, no credentials.\n");
  console.log("  files   site KB   req first   req steady   wire KB   inflation");
  for (const r of rows) {
    console.log(
      `  ${String(r.files).padStart(5)}   ${(r.siteBytes / 1024).toFixed(1).padStart(7)}   ` +
      `${String(r.firstRequests).padStart(9)}   ${String(r.steadyRequests).padStart(10)}   ` +
      `${(r.wireBytes / 1024).toFixed(1).padStart(7)}   ${r.inflation.toFixed(2)}x`
    );
  }

  const first = rows[0], last = rows[rows.length - 1];
  const perFile = (last.steadyRequests - first.steadyRequests) / (last.files - first.files);
  console.log(`\n  Steady state is ${perFile.toFixed(2)} requests per file plus ` +
              `${(first.steadyRequests - perFile * first.files).toFixed(0)}: a blob each, then one ` +
              `tree, one commit, one reference, and the read that found the parent.`);
  console.log(`  A repository with no commits costs ${last.firstRequests - last.steadyRequests} ` +
              `more on the first publish, because it has to be seeded before the git data API ` +
              `will accept anything.`);

  console.log("\nThe same publish across hosts, from the adapters' own cost model:\n");
  console.log("  host      requests   largest body KB   over the limit");
  for (const row of compareHosts(50, 700)) {
    console.log(`  ${row.host.padEnd(8)}  ${String(row.requests).padStart(8)}   ` +
                `${(row.largestBodyBytes / 1024).toFixed(1).padStart(15)}   ` +
                `${row.exceedsBodyLimit ? "yes" : "no"}`);
  }
  console.log("\n  A batch-commit host puts a whole site in one request and meets a body limit");
  console.log("  instead of a request limit, which is the trade the disk lane already reports.");
}
