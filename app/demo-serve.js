// A site inside the machine, reachable from another tab. The whole path.
//
// Format a disk, put a web server and a site on it, start the server inside the
// guest, and reach it from the browser over a TCP stack that lives in this tab.
// Then sync, so the machine that serves the site is itself a commit.
//
// The one thing that had to be added to make this possible is the server. The
// images this project boots ship a busybox built without httpd, without nc and
// without any other applet that can accept a connection, so nothing in them can
// listen on a port at all. vendor/busybox/ is one static megabyte that can, and
// it goes in the way every other binary does: over the 9p share, from this
// page's own origin. No package manager, no mirror, no relay.
//
// A machine is served from an origin of its own, so `python serve.py` listens on
// 8000 for the app and 8001 for machines. Both serve the same files; only the
// origin differs, and that difference is what keeps a guest's pages away from the
// token.
//
//   const s = await import("./demo-serve.js"); const m = await s.main();
//
// Then open m.url in a second tab. To stop:  await m.stop();

import { Machine } from "../src/core/machine.js";
import { Lease, holderName } from "../src/core/lease.js";
import { V86Device, serialFlush } from "../src/device/v86.js";
import { Governor } from "../src/core/governor.js";
import { Terminal } from "../src/ui/terminal.js";
import { attachKeyboard } from "./terminal-input.js";
import { makeRunner } from "../src/guest/runner.js";
import { rc, atPrompt } from "../src/guest/fs.js";
import * as fs from "../src/guest/fs.js";
import { V86Net } from "../src/device/net.js";
import { MemoryHost } from "./demo-loop.js";
import { SITE, serveMachine, stageFiles } from "./serve-machine.js";
import * as dynamicSite from "./dynamic-site.js";
import { bootOptions } from "./guest-image.js";
import { assertServing, machineOrigin } from "./net-broker.js";

const V86_ROOT = "../spike-c";
const BASE = `${V86_ROOT}/images/blank-16mb.img`;
const DISK_SIZE = 16 * 1024 * 1024;
const CHUNK_SIZE = 256 * 1024;
const PROMPT = /[#$%>]\s*$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function main({
  machine = "1", branch = null, machinePort = null, onStep = console.log
} = {}) {
  const steps = [];
  const log = (message) => { steps.push(message); onStep(message); };

  const gitHost = new MemoryHost();
  const onBranch = branch || `served-${Date.now().toString(36)}`;

  // Worth knowing up front, but not worth refusing over: a machine with no
  // origin of its own still runs, still serves, and still publishes -- it just
  // serves one document rather than a site. serveMachine says so when it falls
  // back; this only saves a minute of booting before the news.
  const onPort = machinePort || (location.port ? Number(location.port) + 1 : null);
  try {
    await assertServing(machineOrigin(machine, { machinePort: onPort }));
  } catch (err) {
    log(`heads up: ${err.message.split("\n")[0]}`);
  }

  const terminal = new Terminal(document.getElementById("term"));
  const emulator = new V86({
    ...bootOptions({ screen: document.getElementById("screen") }),
    hda: { buffer: new ArrayBuffer(DISK_SIZE) }
  });
  emulator.add_listener("serial0-output-byte", (b) => terminal.writeByte(b));

  // The flush goes over the same console everything else does, and the guest
  // talks over it. One repeat is the difference between a sync that fails and a
  // sync that happened.
  const flushOnce = serialFlush(emulator, { prompt: PROMPT });
  const device = new V86Device({
    emulator, diskSize: DISK_SIZE,
    flush: async () => {
      try { await flushOnce(); } catch { await flushOnce(); }
    }
  });
  await device.waitForDevice(60000);

  // One writer. The demo has only one tab, so this never refuses anything here
  // -- which is the point of taking it anyway: the path a second tab would meet
  // is the path this one walks.
  const lease = new Lease({ host: gitHost, branch: onBranch, holder: holderName() });
  const engine = new Machine({
    host: gitHost, device, branch: onBranch, lease,
    governor: new Governor({ ratePerMin: 6e6, concurrency: 8 })
  });
  const taken = await lease.acquire();
  log(`lease on ${onBranch} held by ${taken.holder}` +
      (taken.enforced ? "" : ", advisory only: this host has no compare-and-swap"));
  const renewing = setInterval(() => lease.renew().catch(() => {}), 4 * 60 * 1000);
  const attached = await engine.load({
    diskSize: DISK_SIZE, chunkSize: CHUNK_SIZE, base: BASE, baseIsBlank: true
  });
  if (attached.existing) await engine.hydrate();
  device.start();

  const net = new V86Net({ emulator });
  net.attach();
  log(`stack attached: this tab is ${net.ip}, the machine is ${net.peerIp}`);

  const t0 = Date.now();
  for (;;) {
    if (atPrompt(terminal.tail)) break;
    if (Date.now() - t0 > 180000) throw new Error("no shell prompt in three minutes");
    await sleep(200);
  }
  const run = makeRunner({
    send: (text) => emulator.serial0_send(text),
    tail: () => terminal.tail,
    reset: () => terminal.resetTail()
  });
  log(`shell up after ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  // The terminal panel types into this machine now. Without it the panel shows
  // the guest's output but sends keystrokes to an emulator app.js never booted,
  // so typing appears to do nothing.
  const detachKeyboard = attachKeyboard(emulator);
  log("the terminal panel is live: click it and type");

  // --- a disk with a server and a site on it ---------------------------------

  const staged = await stageFiles(emulator, terminal);
  log(`handed to the guest over 9p: busybox (${staged.bytes} bytes) and rrd`);

  const opened = await fs.open(run, { allowFormat: !attached.existing });
  log(`disk ${opened.formatted ? "formatted and " : ""}mounted at ${fs.MOUNTPOINT}`);

  await dynamicSite.install(run, { directory: SITE });
  log(`wrote the site to ${SITE}: index.html, ${dynamicSite.CGI} and its assets`);

  const serving = await serveMachine({
    emulator, run, device, engine, branch: onBranch, machine, lease,
    machinePort: onPort, net, directory: SITE, onStep: log
  });

  // Straight through the stack, before any service worker is involved. All
  // three files, because a site is not one document.
  const fetched = {};
  for (const name of ["", ...Object.keys(dynamicSite.ASSETS), `${dynamicSite.CGI}?text=hello&calc=6*7`]) {
    const path = `/${name}`;
    // A probe that fails is worth reporting, not worth abandoning a working
    // machine over: everything up to here is already running.
    try {
      const response = await net.request({ port: 80, path });
      fetched[path] = `${response.status} ${response.headers["content-type"] || "?"} ${response.body.length}b`;
    } catch (err) {
      fetched[path] = `failed: ${err.message}`;
    }
    log(`direct ${path} -> ${fetched[path]}`);
  }

  // Worth doing, not worth losing a running machine over. Everything above is
  // already serving; a sync that could not flush can be repeated by hand, and
  // "rrd sync" inside the machine does exactly that.
  try {
    const synced = await engine.sync({ message: "a machine that serves a site" });
    log(`synced: ${synced.chunks} chunks dirty, ${synced.uploaded} uploaded, commit ${synced.commit}`);
  } catch (err) {
    log(`the first sync did not finish (${err.message.split(".")[0]}); the machine is ` +
        `serving regardless, and "rrd sync" will try again`);
  }
  log(`open this in a second tab: ${serving.url}`);

  return {
    emulator, device, net, engine, host: gitHost, branch: onBranch,
    run, steps, fetched, lease, control: serving.control, url: serving.url,
    sandboxed: serving.sandboxed,
    async stop() {
      detachKeyboard();
      clearInterval(renewing);
      await lease.release().catch(() => {});
      await serving.stop();
      net.detach();
      device.detach();
      await emulator.destroy();
    }
  };
}

/** Escape for a single-quoted shell string: end the quoting, emit a quote, resume. */
function shellQuote(text) {
  return String(text).replace(/'/g, "'\\''");
}
