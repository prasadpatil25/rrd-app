// Bringing the guest's interface up, and serving a directory from it.
//
// Same shape as the mount helpers next door: every function takes a
// `run(command) => Promise<string>` and reports through exit codes rather than
// by reading output, because the serial console echoes commands back and a
// wrapped line turns a failure into a false success.
//
// Addressing is static. There is no DHCP server in the tab, and there does not
// need to be: the segment has exactly two hosts on it and both addresses are
// known before the guest boots.

import { rc, TRANSFER } from "./fs.js";

export const DEVICE = "eth0";
export const ADDRESS = "10.0.2.15";
export const PREFIX = 24;
export const GATEWAY = "10.0.2.2";     // the tab

/** Where a machine's site lives on the disk, relative to the mountpoint. */
export const SITE = "www";

/**
 * Give the guest its address and a route to the tab.
 *
 * Busybox ip and busybox ifconfig are both possible depending on the image, so
 * this tries the modern spelling and falls back. Re-running it is safe: an
 * address that is already there is not an error worth failing on.
 */
export async function configure(run, {
  device = DEVICE, address = ADDRESS, prefix = PREFIX, gateway = GATEWAY, timeoutMs = 15000
} = {}) {
  // Loopback too. Nothing configures it in these images, and a machine that
  // cannot reach 127.0.0.1 cannot check its own web server -- which looks like
  // a hang rather than a failure, because a connection to an address with no
  // route waits instead of being refused.
  await rc(run, "ip link set lo up", timeoutMs).catch(() => {});

  const up = await rc(run, `ip link set ${device} up`, timeoutMs);
  if (up.code !== 0) {
    const legacy = await rc(run, `ifconfig ${device} ${address} netmask ${maskFor(prefix)} up`, timeoutMs);
    if (legacy.code !== 0) {
      throw new Error(
        `could not bring ${device} up. Was the emulator started with ` +
        `net_device: { type: "ne2k" }? Without it the guest has no card to configure.`
      );
    }
    await rc(run, `route add default gw ${gateway}`, timeoutMs);
    return { device, address, gateway, tool: "ifconfig" };
  }

  // "File exists" on a second run is success as far as the caller is concerned.
  const added = await rc(run, `ip addr add ${address}/${prefix} dev ${device}`, timeoutMs);
  if (added.code !== 0 && !/exists/i.test(added.output)) {
    throw new Error(`could not give ${device} the address ${address}/${prefix}: ${added.output.trim()}`);
  }
  await rc(run, `ip route add default via ${gateway}`, timeoutMs);
  return { device, address, gateway, tool: "ip" };
}

/** Whether the guest can see the tab. The cheapest end-to-end check there is. */
export async function reaches(run, { gateway = GATEWAY, timeoutMs = 15000 } = {}) {
  const result = await rc(run, `ping -c 1 -W 2 ${gateway}`, timeoutMs);
  return result.code === 0;
}

/**
 * Serve a directory over HTTP from inside the guest.
 *
 * Busybox httpd needs no configuration and daemonises on its own, which is the
 * whole reason to prefer it: a server that stayed in the foreground would hold
 * the one console the sync engine needs to talk to the guest through.
 *
 * `command` is how a server that is not on PATH gets used -- the images this
 * project boots have no httpd of their own, so the usual caller passes the path
 * of a busybox it put on the disk itself.
 */
export async function serve(run, { directory, port = 80, command = "httpd", timeoutMs = 15000 } = {}) {
  if (!directory) throw new Error("a directory to serve is required");
  const exists = await rc(run, `test -d ${directory}`, timeoutMs);
  if (exists.code !== 0) {
    throw new Error(`${directory} is not a directory in the guest. Is the disk mounted?`);
  }
  const started = await rc(run, `${command} -p ${port} -h ${directory}`, timeoutMs);
  if (started.code !== 0) {
    // Worth naming precisely, because it is a property of the image rather than
    // a mistake by the caller: the vendored buildroot busybox is built without
    // httpd, and without nc, telnetd or inetd either, so nothing in it can open
    // a listening socket at all. The stack in the tab is fine; there is simply
    // nothing on the other side of it to connect to.
    if (/not found/i.test(started.output)) {
      throw new Error(
        `this guest has no httpd, and its busybox has no other listener either. ` +
        `Put a server on the disk before serving from it -- bytes get into a guest ` +
        `through the 9p share at ${TRANSFER}, the same way every other binary does.`
      );
    }
    throw new Error(`httpd would not start on port ${port}: ${started.output.trim()}`);
  }
  return { directory, port };
}

/** Stop the server. Leaves the files alone. */
export async function stop(run, { name = "httpd", timeoutMs = 15000 } = {}) {
  await rc(run, `killall ${name}`, timeoutMs);
}

/** A placeholder site, so there is something to fetch before there is a site. */
export async function placeholder(run, { directory, title = "Served from the guest", timeoutMs = 15000 } = {}) {
  await rc(run, `mkdir -p ${directory}`, timeoutMs);
  const html = `<!doctype html><meta charset=utf-8><title>${title}</title>` +
    `<h1>${title}</h1><p>This page is a file on the machine's disk, ` +
    `served by a process inside the VM, fetched over a TCP stack in the tab.`;
  // Not a heredoc. rc() appends `; echo rc=$?` to whatever it is given, which
  // would land on the terminator line and leave the heredoc unterminated.
  const written = await rc(run, `printf '%s' '${quote(html)}' > ${directory}/index.html`, timeoutMs);
  if (written.code !== 0) throw new Error(`could not write ${directory}/index.html`);
  return `${directory}/index.html`;
}

/** Escape for a single-quoted shell string: end the quoting, emit a quote, resume. */
function quote(text) {
  return String(text).replace(/'/g, "'\\''");
}

function maskFor(prefix) {
  const bits = (0xffffffff << (32 - prefix)) >>> 0;
  return [24, 16, 8, 0].map((shift) => (bits >>> shift) & 0xff).join(".");
}
