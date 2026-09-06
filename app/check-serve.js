// Is the machine actually serving, and if not, which layer is at fault?
//
// A page that does not appear has four places to have gone wrong, and they need
// different fixes: the server inside the guest, the network between the guest
// and this tab, the worker on the machine's origin, and the browser tab doing
// the asking. Each check here answers exactly one of them, in order, so the
// first failure names the layer.
//
// Everything below runs from the tab holding the VM, which can reach the guest
// directly. What it deliberately does not do is fetch the machine's origin from
// here: that is cross-origin by design, and a browser would refuse to let this
// tab read the answer. Whether the last hop works is a question for a second
// tab, and the report says so rather than guessing.
//
//   const c = await import("./check-serve.js");
//   await c.check(session);          // the value demo-serve.js returned

import { rc } from "../src/guest/fs.js";
import * as guestNet from "../src/guest/net.js";

/**
 * @param {Object} session what demo-serve.js main() returned
 * @param {Object} [options]
 * @param {string} [options.directory] the served directory in the guest
 * @param {number} [options.port]
 * @returns {Promise<{ok: boolean, rows: Array, stats: Object}>}
 */
export async function check(session, { directory = "/disk/www", port = 80 } = {}) {
  const { run, net, url } = session;
  const rows = [];
  const record = async (layer, name, fn) => {
    const started = performance.now();
    try {
      const detail = await fn();
      rows.push({ layer, check: name, ok: true, detail, ms: Math.round(performance.now() - started) });
      return detail;
    } catch (err) {
      rows.push({ layer, check: name, ok: false, detail: err.message, ms: Math.round(performance.now() - started) });
      return null;
    }
  };

  // --- the guest -------------------------------------------------------------
  const listing = await record("guest", `${directory} has files`, async () => {
    const result = await rc(run, `ls ${directory}`);
    if (!result.ok) throw new Error(`${directory} is not there. Is the disk mounted?`);
    const names = result.output.split(/\s+/).filter(Boolean);
    if (!names.length) throw new Error(`${directory} is empty, so there is nothing to serve`);
    return names.join(" ");
  });

  await record("guest", "a server process is running", async () => {
    const result = await rc(run, "ps | grep -c [h]ttpd");
    const count = Number((result.output.match(/\d+/) || [0])[0]);
    if (!count) throw new Error("no httpd in the process list; it exited or never started");
    return `${count} process${count === 1 ? "" : "es"}`;
  });

  // --- the network -----------------------------------------------------------
  await record("network", "the guest can reach this tab", async () => {
    if (!(await guestNet.reaches(run))) {
      throw new Error("ping went unanswered; check the guest's address and route");
    }
    return "ping answered";
  });

  await record("network", `something accepts on port ${port}`, async () => {
    await net.waitForPort(port, { timeoutMs: 5000 });
    return "connection accepted";
  });

  // --- the site, file by file ------------------------------------------------
  const names = listing ? listing.split(" ") : [];
  const paths = ["/", ...names.filter((n) => n !== "index.html").map((n) => `/${n}`)];
  for (const path of paths) {
    await record("site", `GET ${path}`, async () => {
      const response = await net.request({ port, path });
      if (response.status >= 400) throw new Error(`the guest answered ${response.status}`);
      return `${response.status} ${response.headers["content-type"] || "no type"} ${response.body.length}b`;
    });
  }

  // --- the last hop, which this tab cannot judge -----------------------------
  rows.push({
    layer: "browser", check: "the machine's origin", ok: null,
    detail: `open ${url} in another tab: this one is on a different origin on purpose ` +
            `and is not allowed to read the answer`,
    ms: 0
  });

  const ok = rows.every((row) => row.ok !== false);
  if (typeof console.table === "function") console.table(rows);
  console.log(`stack: ${JSON.stringify(net.stats)}`);
  console.log(ok
    ? `every layer this tab can see is healthy. Open ${url} in a second tab for the last one.`
    : `first failure: ${rows.find((r) => r.ok === false).layer} — ${rows.find((r) => r.ok === false).check}`);

  return { ok, rows, stats: { ...net.stats }, url };
}
