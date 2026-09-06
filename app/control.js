// The control plane the guest talks to.
//
// Plain HTTP on the tab's own address, answering in plain text, because the
// client is a shell script using busybox wget and the reader is a person looking
// at a terminal. No JSON, no status codes carrying meaning a shell would have to
// parse: a line saying what happened.
//
// Everything it can do is something the page could already do. What is new is
// who gets to ask.

import { serve } from "../src/net/http.js";
import { HOST } from "../src/guest/control.js";

const HELP = `rrd -- this machine, from inside it

  rrd status              what is running, and what is unsaved
  rrd url                 where the site is being served
  rrd serve [directory]   serve a directory to the browser  (default /disk/www)
  rrd unserve             stop serving
  rrd sync [message]      commit the disk, so the machine survives this tab
  rrd publish [message]   commit the site to a ref of its own, for a static host
  rrd help                this
`;

/**
 * @param {Object} options
 * @param {import("../src/device/net.js").V86Net} options.net
 * @param {Object} options.actions what the commands actually do
 * @param {number} [options.port]
 * @param {(event: Object) => void} [options.onEvent]
 * @returns {{port: number, close: () => void}}
 */
export function startControl({ net, actions, port = 80, onEvent = () => {} }) {
  if (!net) throw new Error("a V86Net is required");
  if (!actions) throw new Error("the actions a command performs are required");

  const routes = {
    "/": async () => HELP,
    "/help": async () => HELP,

    "/status": async () => {
      const status = await actions.status();
      const last = Object.entries(status.last || {})
        .map(([name, run]) => [name, run.state === "failed" ? `failed: ${run.error}`
          : run.state === "done" ? `done${run.commit ? " " + run.commit : ""}${run.files !== undefined ? `, ${run.files} files` : ""}`
          : run.state]);
      return lines([
        ["serving", status.serving ? `${status.directory} on port ${status.port}` : "no"],
        ["url", status.url || "-"],
        ["disk", status.disk || "-"],
        ["unsaved", status.dirty === undefined ? "-" : `${status.dirty} chunks`],
        ["branch", status.branch || "-"],
        ...last
      ]);
    },

    "/where": async () => {
      const status = await actions.status();
      if (!status.directory) throw new Error("nothing is being served");
      return `${status.directory}\n`;
    },

    "/url": async () => {
      const status = await actions.status();
      if (!status.url) return "not serving. Try: rrd serve\n";
      return `${status.url}\n`;
    },

    "/serve": async (query) => {
      const directory = query.get("dir") || "/disk/www";
      const result = await actions.serve(directory);
      onEvent({ type: "served", directory });
      if (result && result.deferred) return started("serving " + directory);
      return `serving ${directory}\n${result.url}\n\nOpen that in another tab.\n`;
    },

    "/unserve": async () => {
      const result = await actions.unserve();
      onEvent({ type: "unserved" });
      if (result && result.deferred) return started("stopping the server");
      return "stopped serving. The disk is untouched.\n";
    },

    "/publish": async (query) => {
      const result = await actions.publish(query.get("message") || "");
      onEvent({ type: "published", commit: result.commit });
      return `published ${result.files} files (${result.bytes} bytes) from ${result.directory}\n` +
             `to ${result.branch} as ${result.commit}\n` +
             (result.warning ? `\nnote: ${result.warning}\n` : "") +
             `\nA static host pointed at that ref serves this site with nothing running.\n`;
    },

    "/sync": async (query) => {
      const message = query.get("message") || "from inside the machine";
      const result = await actions.sync(message);
      onEvent({ type: "synced", commit: result.commit });
      if (result && result.deferred) return started("syncing the disk");
      return `synced ${result.uploaded} of ${result.chunks} chunks as ${result.commit}\n` +
             `this machine can now be restored from ${result.branch || "its branch"}\n`;
    }
  };

  return serve(net.stack, {
    port,
    handler: async ({ method, path, query }) => {
      if (method !== "GET") {
        // The client is a shell script with wget and no verbs to spare.
        return { status: 405, headers: { "Content-Type": "text/plain" }, body: "rrd speaks GET only\n" };
      }
      const route = routes[path];
      if (!route) {
        return { status: 404, headers: { "Content-Type": "text/plain" },
                 body: `no such command: ${path}\ntry: rrd help\n` };
      }
      try {
        return { status: 200, headers: { "Content-Type": "text/plain" }, body: await route(query) };
      } catch (err) {
        // A command that failed still answers 200, with the reason as its output.
        // The client is a person reading a terminal, and busybox wget prints the
        // body of a 200 and swallows the body of anything else -- so a status
        // code here is a way of hiding the one thing worth saying.
        onEvent({ type: "failed", path, error: err.message });
        return { status: 200, headers: { "Content-Type": "text/plain" },
                 body: `rrd: ${err.message}\n` };
      }
    }
  });
}

export { HOST };

/**
 * What to say about work that has not started yet.
 *
 * The command that asked is holding the console the work needs, so it can only
 * begin once that command has finished. Saying so is better than pretending it
 * is done, and much better than waiting for a shell that is waiting for us.
 */
function started(what) {
  return `${what}. It needs the console this command is using, so it starts as ` +
         `soon as this returns.\n\nCheck with: rrd status\n`;
}

function lines(pairs) {
  const width = Math.max(...pairs.map(([name]) => name.length));
  return pairs.map(([name, value]) => `${name.padEnd(width)}  ${value}`).join("\n") + "\n";
}
