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
import { V86Device, serialFlush } from "../src/device/v86.js";
import { Governor } from "../src/core/governor.js";
import { Terminal } from "../src/ui/terminal.js";
import { attachKeyboard } from "./terminal-input.js";
import { makeRunner } from "../src/guest/runner.js";
import { rc, atPrompt } from "../src/guest/fs.js";
import * as fs from "../src/guest/fs.js";
import { V86Net } from "../src/device/net.js";
import { MemoryHost } from "./demo-loop.js";
import { SITE, resilient, restoreRuntimeState, serveMachine, stageFiles } from "./serve-machine.js";
import { assertServing, machineOrigin } from "./net-broker.js";

const V86_ROOT = "../spike-c";
const BASE = `${V86_ROOT}/images/blank-16mb.img`;
const DISK_SIZE = 16 * 1024 * 1024;
const CHUNK_SIZE = 256 * 1024;
const PROMPT = /[#$%>]\s*$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The site itself. Three files, because one file would not prove assets work. */
const FILES = {
  "index.html":
    '<!doctype html><meta charset=utf-8><title>Machine 1</title>' +
    '<link rel=stylesheet href="style.css"><h1>Served from inside the VM</h1>' +
    '<p>This file is on the machine’s disk. A busybox httpd inside the guest read it ' +
    'off that disk and wrote it to a TCP connection whose far end is JavaScript in another tab.' +
    '<p id=probe>The stylesheet and the script have not loaded.' +
    '<script src="app.js"></script>',
  "style.css":
    'body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:60ch;' +
    'margin:8vh auto;padding:0 20px;background:#EFF2F1;color:#131C1A}' +
    'h1{font-size:20px}@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}}',
  "app.js":
    'document.getElementById("probe").textContent = ' +
    '"The stylesheet and the script both loaded, so this is a whole site and not one page.";'
};

export async function main({
  machine = "1", branch = null, machinePort = null, onStep = console.log
} = {}) {
  const steps = [];
  const log = (message) => { steps.push(message); onStep(message); };

  const gitHost = new MemoryHost();
  const onBranch = branch || `served-${Date.now().toString(36)}`;

  // Before anything expensive. A machine takes a minute to boot, format and
  // sync, and finding out afterwards that its origin was never being served
  // throws all of that away for a reason that was knowable up front.
  const onPort = machinePort || (location.port ? Number(location.port) + 1 : null);
  await assertServing(machineOrigin(machine, { machinePort: onPort }));

  const terminal = new Terminal(document.getElementById("term"));
  const emulator = new V86({
    wasm_path: `../vendor/v86/v86.wasm`,
    memory_size: 128 * 1024 * 1024,
    vga_memory_size: 2 * 1024 * 1024,
    screen_container: document.getElementById("screen"),
    bios: { url: `${V86_ROOT}/bios/seabios.bin` },
    vga_bios: { url: `${V86_ROOT}/bios/vgabios.bin` },
    cdrom: { url: `${V86_ROOT}/images/linux4.iso` },
    // Zeros made here rather than a blank image fetched. The blank images are
    // not in the repository -- 288 MB of nothing is not worth committing, and
    // .gitignore says so -- which means a deployed copy of this page has no
    // such file to fetch. The app's own boot path does the same.
    hda: { buffer: new ArrayBuffer(DISK_SIZE) },
    // The card, with nothing on the other end of it but this page.
    net_device: { type: "ne2k" },
    // And the share, which is how the server gets in.
    filesystem: {},
    autostart: true, disable_keyboard: true, disable_mouse: true
  });
  emulator.add_listener("serial0-output-byte", (b) => terminal.writeByte(b));

  const device = new V86Device({
    emulator, diskSize: DISK_SIZE, flush: serialFlush(emulator, { prompt: PROMPT })
  });
  await device.waitForDevice(60000);

  const engine = new Machine({
    host: gitHost, device, branch: onBranch,
    governor: new Governor({ ratePerMin: 6e6, concurrency: 8 })
  });
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
  const rawRun = makeRunner({
    send: (text) => emulator.serial0_send(text),
    tail: () => terminal.tail,
    reset: () => terminal.resetTail()
  });
  const run = resilient(rawRun, { afterRecovery: restoreRuntimeState });
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

  await rc(run, `mkdir -p ${SITE}`);
  for (const [name, body] of Object.entries(FILES)) {
    const written = await rc(run, `printf '%s' '${shellQuote(body)}' > ${SITE}/${name}`);
    if (!written.ok) throw new Error(`could not write ${name} onto the disk`);
  }
  log(`wrote ${Object.keys(FILES).join(", ")} to ${SITE}`);

  const serving = await serveMachine({
    emulator, run, device, engine, branch: onBranch, machine,
    machinePort: onPort, net, directory: SITE, onStep: log
  });

  // Straight through the stack, before any service worker is involved. All
  // three files, because a site is not one document.
  const fetched = {};
  for (const name of ["", ...Object.keys(FILES).slice(1)]) {
    const path = `/${name}`;
    const response = await net.request({ port: 80, path });
    fetched[path] = `${response.status} ${response.headers["content-type"] || "?"} ${response.body.length}b`;
    log(`direct ${path} -> ${fetched[path]}`);
  }

  const synced = await engine.sync({ message: "a machine that serves a site" });
  log(`synced: ${synced.chunks} chunks dirty, ${synced.uploaded} uploaded, commit ${synced.commit}`);
  log(`open this in a second tab: ${serving.url}`);

  return {
    emulator, device, net, engine, host: gitHost, branch: onBranch,
    run, steps, fetched, control: serving.control, url: serving.url,
    async stop() {
      detachKeyboard();
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
