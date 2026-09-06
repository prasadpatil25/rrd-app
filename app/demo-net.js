// A site in the guest, reachable from another tab, with no server anywhere.
//
// What this demonstrates, in order: v86 builds an NE2000 with no relay behind
// it; the stack in the tab answers the guest's ARP and its ping; a server
// running inside the VM accepts a TCP connection whose far end is a function
// call in this page; and a service worker turns that into a URL any other tab
// on this browser can open.
//
// Nothing is fetched from the network and nothing is uploaded. The only reason
// a server is running at all is that the page had to come from somewhere.
//
//   const m = await import("./demo-net.js"); const s = await m.main();
//
// Then open the URL it prints in a second tab. To stop:  await s.stop();

import { V86Net } from "../src/device/net.js";
import { Terminal } from "../src/ui/terminal.js";
import { attachKeyboard } from "./terminal-input.js";
import { makeRunner } from "../src/guest/runner.js";
import { atPrompt } from "../src/guest/fs.js";
import * as guestNet from "../src/guest/net.js";
import { host } from "./net-broker.js";

const V86_ROOT = "../spike-c";
const SITE = "/tmp/www";        // a plain directory: this demo is about the network,
                                // and pointing httpd at /disk/www is the same call
const PROMPT = /[#$%>]\s*$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function main({ machine = "1", onStep = console.log } = {}) {
  const steps = [];
  const log = (message) => { steps.push(message); onStep(message); };

  const terminal = new Terminal(document.getElementById("term"));
  const emulator = new V86({
    wasm_path: "../vendor/v86/v86.wasm",
    memory_size: 128 * 1024 * 1024, vga_memory_size: 2 * 1024 * 1024,
    screen_container: document.getElementById("screen"),
    bios: { url: `${V86_ROOT}/bios/seabios.bin` },
    vga_bios: { url: `${V86_ROOT}/bios/vgabios.bin` },
    cdrom: { url: `${V86_ROOT}/images/linux4.iso` },
    // The line the whole demo rests on. No relay_url: the card is built, and
    // the only thing on the other end of it is this tab.
    net_device: { type: "ne2k" },
    // The way bytes get into the guest, unchanged by any of this: a server to
    // run, or a site to serve, arrives over the 9p share rather than over the
    // network. Without it the guest's boot-time mount of /mnt fails.
    filesystem: {},
    autostart: true, disable_keyboard: true, disable_mouse: true
  });
  emulator.add_listener("serial0-output-byte", (b) => terminal.writeByte(b));

  const net = new V86Net({ emulator, onEvent: (e) => log(`net ${e.type}${e.port ? ` :${e.port}` : ""}`) });
  net.attach();
  log(`stack attached: we are ${net.ip}, the guest is ${net.peerIp}`);

  const run = makeRunner({
    send: (text) => emulator.serial0_send(text),
    tail: () => terminal.tail,
    reset: () => terminal.resetTail()
  });

  const started = Date.now();
  while (!atPrompt(terminal.tail)) {
    if (Date.now() - started > 180000) throw new Error("no shell prompt in three minutes");
    await sleep(200);
  }
  log(`shell up after ${((Date.now() - started) / 1000).toFixed(1)}s`);
  const detachKeyboard = attachKeyboard(emulator);

  const configured = await guestNet.configure(run);
  log(`guest configured with ${configured.tool}: ${configured.address}, gateway ${configured.gateway}`);

  const reachable = await guestNet.reaches(run);
  log(`ping from the guest to the tab: ${reachable ? "answered" : "no answer"}`);

  await guestNet.placeholder(run, { directory: SITE, title: `Machine ${machine}` });
  await guestNet.serve(run, { directory: SITE, port: 80 });
  await net.waitForPort(80);
  log(`httpd is listening on port 80 inside the guest, serving ${SITE}`);

  // Straight through the stack, with no service worker involved. If this works
  // and the tab does not, the fault is in the worker, not in the network.
  const direct = await net.request({ port: 80, path: "/" });
  log(`direct request: ${direct.status}, ${direct.body.length} bytes, ` +
      `content-type ${direct.headers["content-type"] || "unset"}`);

  const served = await host({ net, machine, onEvent: (e) => log(`sw ${e.type}: ${e.path || e.url || ""}`) });
  log(`open this in another tab: ${served.url}`);

  return {
    emulator, net, run, steps, url: served.url,
    async stop() {
      detachKeyboard();
      await served.stop();
      await guestNet.stop(run).catch(() => {});
      net.detach();
      await emulator.destroy();
    }
  };
}
