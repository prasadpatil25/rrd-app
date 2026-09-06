// Everything it takes to make a booted machine serve a site.
//
// Extracted from the demo because the app needs the same sequence: a machine
// booted from the UI and one booted from the console are the same machine, and
// the difference between them should not be which of the two can be reached from
// another tab.
//
// What it does, in order: put a web server on the disk, give the guest an
// address, start the server, hand the machine an origin of its own, and leave a
// control plane running so the machine can drive the rest itself.

import * as fs from "../src/guest/fs.js";
import * as guestNet from "../src/guest/net.js";
import * as guestControl from "../src/guest/control.js";
import { V86Net } from "../src/device/net.js";
import { publish, missingIndex } from "../src/core/publish.js";
import { rc } from "../src/guest/fs.js";
import { startControl } from "./control.js";
import { assertServing, host, hostOnOrigin, machineOrigin } from "./net-broker.js";

export const BUSYBOX = "../vendor/busybox/busybox-1.35.0-i686";
export const SITE = `${fs.MOUNTPOINT}/www`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Wait for the guest to stop printing.
 *
 * Not a fixed sleep: what is being waited for is the end of output nobody asked
 * for, and how long that takes depends on the machine.
 */
async function settle(terminal, { quietMs = 1200, timeoutMs = 20000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = terminal.tail;
  let since = Date.now();
  for (;;) {
    await sleep(200);
    const now = terminal.tail;
    if (now !== last) { last = now; since = Date.now(); }
    else if (Date.now() - since >= quietMs) return;
    if (Date.now() > deadline) return;
  }
}


/**
 * Stage the files a machine needs, before any command is sent.
 *
 * Both at once, and early: handing v86 a file makes the guest retry its 9p mount
 * and announce the result on the console whenever it gets round to it, and one
 * interruption is easier to live with than several.
 */
export async function stageFiles(emulator, terminal, { busybox = BUSYBOX } = {}) {
  const binary = new Uint8Array(await (await fetch(busybox)).arrayBuffer());
  await emulator.create_file("busybox", binary);
  await guestControl.stage(emulator);
  await settle(terminal);
  return { bytes: binary.length };
}

/**
 * Make a machine serve, and let it drive itself from then on.
 *
 * @param {Object} options
 * @param {Object} options.emulator
 * @param {(command: string, options?: Object) => Promise<string>} options.run a resilient runner
 * @param {Object} options.device the V86Device, for reporting what is unsaved
 * @param {Object} options.engine the Machine, for sync
 * @param {string} options.branch
 * @param {string} [options.directory] what to serve
 * @param {(message: string) => void} [options.onStep]
 */
export async function serveMachine({
  emulator, run, device, engine, branch, lease = null,
  machine = "1", directory = SITE, machinePort = null,
  publishHost = null, publishBranch = null,
  net = null, onStep = () => {}
} = {}) {
  const onPort = machinePort || (location.port ? Number(location.port) + 1 : null);

  const stack = net || new V86Net({ emulator });
  if (!stack.attached) stack.attach();
  onStep(`stack attached: this tab is ${stack.ip}, the machine is ${stack.peerIp}`);

  const installed = await fs.install(run, { name: "busybox" });
  onStep(`web server installed at ${installed.path}`);

  const configured = await guestNet.configure(run);
  onStep(`guest addressed with ${configured.tool}: ${configured.address} via ${configured.gateway}`);

  const running = { directory: null, port: 80, served: null };

  /**
   * The stack, plus one attempt at putting the server back.
   *
   * The guest knocks its own server over whenever it retries its 9p mount, and
   * the first anyone hears of it is a request from another tab failing. Checking
   * once at startup is not enough for something that can happen at any moment,
   * so a failed request is treated as a reason to look rather than as an answer.
   */
  // Set while the guest is blocked waiting for an answer from us. Nothing may
  // touch its console then: the command would sit in a shell that cannot read it
  // until the answer it is waiting for arrives.
  let guestWaiting = 0;

  let repairing = null;
  const healing = {
    request: async (options) => {
      try {
        return await stack.request(options);
      } catch (err) {
        if (!running.directory) throw err;
        if (guestWaiting) throw err;      // repairing needs the shell; it is not ours
        // One repair, however many requests noticed. A page asks for its
        // stylesheet and its script at the same moment as its document, and
        // three machines being restarted at once is three ways to fail.
        if (!repairing) {
          onStep(`the guest stopped answering; putting the server back`);
          repairing = startServing(running.directory).finally(() => { repairing = null; });
        }
        await repairing;
        return await stack.request(options);
      }
    }
  };

  async function startServing(where = directory) {
    await guestNet.stop(run, { name: "busybox" }).catch(() => {});
    await guestNet.serve(run, { directory: where, port: running.port, command: `${installed.path} httpd` });
    await stack.waitForPort(running.port);
    running.directory = where;
    if (!running.served) running.served = await attachHost();
    return { url: running.served.url, directory: where };
  }

  await startServing(directory);
  onStep(`serving ${directory} from inside the guest`);

  /** The list a machine leaves for the tab to read, so no shell is needed. */
  const MANIFEST = ".rrd-manifest";

  // A declaration, not a const: startServing is called before this point in the
  // file is reached, and a const would still be in its dead zone when it ran.
  function forward(e) {
    onStep(e.type === "served"
      ? `worker served ${e.path} -> ${e.status}, ${e.bytes} bytes`
      : `worker ${e.type} ${e.url || e.path || ""}`);
  }

  /**
   * Put the machine somewhere a browser can reach it.
   *
   * An origin of its own if there is one, because that is the only arrangement
   * in which a whole site works. If there is not -- nothing deployed at the
   * machine origin, or a host like *.github.io where a second origin cannot be
   * had at all -- then the app's own origin behind a sandbox, which protects the
   * token and costs the site its assets. Falling back is worth doing and worth
   * saying out loud: the difference between the two is visible to anyone who
   * opens the result, and they should hear it here rather than discover it there.
   */
  async function attachHost() {
    try {
      const origin = machineOrigin(machine, { machinePort: onPort });
      await assertServing(origin);
      return await hostOnOrigin({ net: healing, machine, machinePort: onPort, onEvent: forward });
    } catch (err) {
      onStep(`no origin of its own: ${err.message.split("\n")[0]}`);
      onStep(`falling back to this origin, sandboxed: the machine will serve one ` +
             `self-contained document, and its stylesheets, scripts and images will not load`);
      const served = await host({ net: healing, machine, onEvent: forward });
      return { ...served, sandboxed: true };
    }
  }

  /**
   * Read the site out of the machine, over the machine's own web server.
   *
   * Not over the 9p share, which is how binaries get in: handing v86 a file
   * makes the guest reattach the share and knock its own state over.
   *
   * And not by asking the shell what the files are called, when the request came
   * from the machine itself. `rrd publish` blocks its shell waiting for this
   * answer, so a command sent to that shell now would sit in its input buffer
   * until the answer it is waiting for arrives: each side waiting for the other,
   * which is a deadlock however politely it is written. So the guest lists its
   * own files before it asks, and leaves the list where the web server will hand
   * it over like any other file.
   */
  async function collectSite({ viaShell = false } = {}) {
    if (!running.directory) throw new Error("nothing is being served, so there is nothing to publish");

    let paths;
    if (viaShell) {
      const listing = await rc(run, `find ${running.directory} -type f`, 30000);
      if (!listing.ok) throw new Error(`could not list ${running.directory}`);
      paths = listing.output.split(/\r?\n/).map((line) => line.trim())
        .filter((line) => line.startsWith(`${running.directory}/`))
        .map((line) => line.slice(running.directory.length + 1));
    } else {
      // One retry: the machine may have just restarted its own server, which it
      // does before asking, and a connection refused a moment ago is not an
      // answer about whether the site is there.
      let manifest;
      try {
        manifest = await healing.request({ port: running.port, path: `/${MANIFEST}` });
      } catch (err) {
        await new Promise((r) => setTimeout(r, 1200));
        manifest = await healing.request({ port: running.port, path: `/${MANIFEST}` });
      }
      if (manifest.status !== 200) {
        throw new Error(
          `the machine did not leave a list of its files at ${MANIFEST}. ` +
          `Publishing from inside the machine writes one first; from here, ` +
          `pass viaShell.`
        );
      }
      paths = new TextDecoder().decode(manifest.body).split(/\r?\n/).map((l) => l.trim());
    }

    const files = [];
    for (const path of paths.filter((p) => p && p !== MANIFEST)) {
      const response = await healing.request({ port: running.port, path: `/${path}` });
      if (response.status !== 200) {
        throw new Error(`the machine answered ${response.status} for ${path}, which it is serving`);
      }
      files.push({ path, bytes: response.body });
    }
    return files;
  }

  /**
   * Run an action on behalf of the guest.
   *
   * Two kinds, and the difference is not cosmetic. Some actions need nothing but
   * the network -- publishing reads the site over the machine's own web server --
   * and can answer while the guest waits. Others need the guest's console, and
   * the guest is holding it: `rrd sync` blocks its shell until this returns, so a
   * command sent to that shell now would never run. Those are started after the
   * answer has gone back, when the shell is free again, and reported by status.
   */
  const lastRun = {};
  function deferred(name, action) {
    return async (...args) => {
      const started = () => {
        lastRun[name] = { state: "running", at: new Date().toISOString() };
        Promise.resolve()
          .then(() => action(...args))
          .then((result) => { lastRun[name] = { state: "done", ...flatten(result) }; })
          .catch((err) => { lastRun[name] = { state: "failed", error: err.message }; });
      };
      // Long enough for rrd to have printed the answer and exited.
      setTimeout(started, 400);
      return { deferred: true, name };
    };
  }

  const control = startControl({
    net: stack,
    onEvent: (e) => onStep(`control: ${e.type}${e.directory ? " " + e.directory : ""}${e.commit ? " " + e.commit : ""}`),
    actions: {
      status: async () => ({
        last: lastRun,
        lease: lease ? await lease.read().catch(() => null) : null,
        serving: !!running.directory,
        directory: running.directory,
        port: running.port,
        url: running.served ? running.served.url : null,
        disk: `${fs.MOUNTPOINT}`,
        dirty: device ? device.pending().length : undefined,
        branch
      }),
      serve: (where) => startServing(where),
      unserve: async () => {
        await guestNet.stop(run, { name: "busybox" }).catch(() => {});
        running.directory = null;
      },
      sync: deferred("sync", async (message) => {
        if (!engine) throw new Error("this machine has no repository attached");
        return { ...(await engine.sync({ message })), branch };
      }),
      publish: async (message, { viaShell = false } = {}) => {
        guestWaiting++;
        try {
        const host = publishHost || (engine && engine.host);
        if (!host) throw new Error("there is no repository to publish to");
        const to = publishBranch || `${branch}-site`;
        const files = await collectSite({ viaShell });
        const warning = missingIndex(files);
        const result = await publish({
          host, branch: to, files,
          message: message || `publish ${files.length} files from ${running.directory}`
        });
          return { ...result, warning, directory: running.directory };
        } finally { guestWaiting--; }
      }
    }
  });

  const profile = `${fs.MOUNTPOINT}/.profile`;
  const installedControl = await guestControl.install({ run, fs, profile });
  await fs.activateProfile(run, { profile }).catch(() => {});
  onStep(`installed ${installedControl.path}: type "rrd help" in the terminal`);

  // One check, not three. The image mounts its share once and then leaves the
  // machine alone, so the disk, the address and the server stay where they were
  // put -- measured over a full run: no recoveries, no resets, no restarts.
  if (!(await guestNet.reaches(run))) {
    onStep(`the guest cannot reach this tab, which it should be able to from boot`);
  }

  return {
    net: stack, control, url: running.served.url, directory: running.directory,
    sandboxed: !!running.served.sandboxed,
    async stop() {
      control.close();
      if (running.served) await running.served.stop();
      await guestNet.stop(run, { name: "busybox" }).catch(() => {});
    }
  };
}

/** Only the parts of a result worth reporting back through a shell. */
function flatten(result) {
  if (!result || typeof result !== "object") return { result: String(result) };
  const out = {};
  for (const [key, value] of Object.entries(result)) {
    if (value === null || ["string", "number", "boolean"].includes(typeof value)) out[key] = value;
  }
  return out;
}

export { settle };
