// The fake GitHub from `app/idp.js`, served over HTTP.
//
// `app/idp.js` holds the endpoints as a shell script because their real home is
// busybox httpd inside a guest. That makes them exactly as testable as a guest
// is, which is not very: booting one needs a browser, and the automated suite
// has none -- `src/test-idp.mjs` says so in its first paragraph and checks the
// shell by reading it rather than running it.
//
// So this runs the same script, byte for byte, in front of a Node server. What
// it buys is the thing `src/test-device-flow.mjs` cannot reach: those tests
// inject a `fetch`, which proves the state machine and nothing about the wire --
// not the form bodies, not the Accept header, not GitHub's habit of answering a
// refusal with a 200. Here the client is the real `DeviceLogin`, the transport
// is real HTTP, and the server is the script that will run in the machine.
//
// Two seams make that possible, and both were already idioms in the CGI beside
// it: `RRD_IDP` moves the state directory, and `RRD_BUSYBOX` names the busybox
// to call. Neither is a test hook bolted on -- `$TAB` in the token endpoint is
// the same shape, for the same reason.
//
// Run it by hand and point a real bridge at it:
//
//   node tools/fake-github.mjs --port 9100
//   node tools/bridge.mjs --github-client-id Iv1.test-client-do-not-trust \
//                         --github-base http://127.0.0.1:9100
//
// Then press the button in the Repository panel. Nothing reaches github.com.

import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { GITHUB, GITHUB_CLIENTS, githubClientFile } from "../app/idp.js";

/**
 * Enough of busybox for the script to run on a host that has none.
 *
 * `httpd -d` and `httpd -e` are the only two applets it uses that an ordinary
 * system has no equivalent of. Everything else is handed to the real binary.
 *
 * Written against awk rather than printf because the portable way to turn %41
 * into an "A" is the one that does arithmetic on the hex digits: POSIX printf
 * interprets \ooo and not \xHH, and the shells disagree about the rest.
 */
const BUSYBOX_SHIM = `#!/bin/sh
case "$1 $2" in
  "httpd -d")
    awk -v s="$3" 'BEGIN{
      hex = "0123456789abcdef"; out = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "%" && i + 2 <= n) {
          a = index(hex, tolower(substr(s, i + 1, 1))) - 1
          b = index(hex, tolower(substr(s, i + 2, 1))) - 1
          if (a >= 0 && b >= 0) { out = out sprintf("%c", a * 16 + b); i += 2; continue }
        }
        out = out c
      }
      printf "%s", out
    }'
    ;;
  "httpd -e")
    awk -v s="$3" 'BEGIN{
      gsub(/&/, "\\\\&amp;", s); gsub(/</, "\\\\&lt;", s)
      gsub(/>/, "\\\\&gt;", s); gsub(/"/, "\\\\&quot;", s)
      printf "%s", s
    }'
    ;;
  *) exec "$@" ;;
esac
`;

/** The shells worth trying, in the order a POSIX one is most likely to be. */
const SHELLS = ["sh", "bash", "dash"];

/**
 * A shell that runs, or null.
 *
 * Windows node reaches WSL's bash but has no `sh` on its PATH, and a Linux node
 * has both -- so this is asked rather than assumed, and the caller is told
 * which one answered so a skipped test can say why.
 */
export function findShell() {
  for (const shell of [process.env.RRD_SH, ...SHELLS].filter(Boolean)) {
    const probe = spawnSync(shell, ["-c", "command -v awk >/dev/null && echo ok"],
                            { encoding: "utf8" });
    if (!probe.error && probe.stdout.trim() === "ok") return shell;
  }
  return null;
}

/**
 * Quote for a single-quoted shell string: end the quoting, emit a quote, resume.
 *
 * The same trick `app/idp.js` uses to get a line onto a disk, and needed here
 * for the same reason -- a query string arrives holding whatever a client sent,
 * and one unescaped quote in it would end the command and start another.
 */
function quote(text) {
  return `'${String(text).replace(/'/g, "'\\''")}'`;
}

/** Split a CGI answer into its headers and its body. */
function parseCgi(text) {
  const split = text.search(/\r?\n\r?\n/);
  const head = split < 0 ? text : text.slice(0, split);
  const body = split < 0 ? "" : text.slice(split).replace(/^\r?\n\r?\n/, "");

  let status = 200;
  const headers = {};
  for (const line of head.split(/\r?\n/)) {
    const at = line.indexOf(":");
    if (at < 0) continue;
    const name = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    // CGI says a script announces its status in a header rather than a status
    // line, which is why busybox needs `Status:` and not `HTTP/1.1`.
    if (name.toLowerCase() === "status") status = parseInt(value, 10) || 200;
    else headers[name] = value;
  }
  return { status, headers, body };
}

/**
 * Serve the fake GitHub.
 *
 * `root` is deliberately a path relative to the working directory rather than
 * an absolute one. Windows node hands a child its own idea of the current
 * directory and WSL's bash resolves the same place under a different name, so
 * an absolute path would have to be translated between them and a relative one
 * does not have to be.
 *
 * @param {Object} [options]
 * @param {number} [options.port]   0 for whatever is free, which is what a test wants
 * @param {string} [options.root]   where the fixtures and the pending codes live
 * @param {string} [options.shell]
 * @param {(event: Object) => void} [options.onEvent]
 */
export async function serveFakeGitHub({
  port = 0, root = ".fake-github", shell = null, onEvent = () => {}
} = {}) {
  const sh = shell || findShell();
  if (!sh) throw new Error("no POSIX shell with awk: set RRD_SH to one");

  const state = `${root}/state`;
  const script = `${root}/github`;
  const busybox = `${root}/busybox`;

  rmSync(root, { recursive: true, force: true });
  for (const dir of [`${state}/gh-clients`, `${state}/device`, `${state}/gh-codes`]) {
    mkdirSync(dir, { recursive: true });
  }
  // The same substitution `install()` performs on the way onto a disk, so that
  // a script run by hand out of this directory behaves like the installed one
  // even with nothing in the environment.
  writeFileSync(script, GITHUB.replace(/__ROOT__/g, state));
  writeFileSync(busybox, BUSYBOX_SHIM);
  for (const [id, client] of Object.entries(GITHUB_CLIENTS)) {
    writeFileSync(`${state}/gh-clients/${id}`, githubClientFile(client));
  }

  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks);
      const at = request.url.indexOf("?");
      const path = at < 0 ? request.url : request.url.slice(0, at);
      const query = at < 0 ? "" : request.url.slice(at + 1);

      // Assignments in front of the command rather than an inherited
      // environment, for the reason `serve.py` gives about passing the client
      // id as an argument: WSL forwards only what WSLENV names, so a Windows
      // node's environment reaches a Linux shell empty and the CGI sees no
      // request at all. An argument crosses every boundary there is.
      const assignments = {
        // Unquoted everywhere in the script, so a shell word here is a
        // command: it saves the shim needing an executable bit, which a
        // Windows filesystem mounted under WSL does not reliably carry.
        RRD_BUSYBOX: `sh ${busybox}`,
        RRD_IDP: state,
        PATH_INFO: path,
        REQUEST_URI: request.url,
        REQUEST_METHOD: request.method,
        QUERY_STRING: query,
        CONTENT_LENGTH: String(body.length),
        CONTENT_TYPE: request.headers["content-type"] || "",
        HTTP_ACCEPT: request.headers.accept || "",
        // The script names itself in `verification_uri`, so it has to know what
        // it was reached as. Empty SCRIPT_NAME because it sits at the root here
        // and under /cgi-bin/github when a guest serves it.
        HTTP_HOST: request.headers.host || "",
        SCRIPT_NAME: ""
      };
      const command = Object.entries(assignments)
        .map(([name, value]) => `${name}=${quote(value)}`)
        .join(" ") + ` sh ${quote(script)}`;
      const child = spawn(sh, ["-c", command]);

      let out = "", err = "";
      child.stdout.on("data", (chunk) => { out += chunk; });
      child.stderr.on("data", (chunk) => { err += chunk; });
      child.on("close", () => {
        const answer = parseCgi(out);
        onEvent({ path, status: answer.status, stderr: err.trim() });
        response.writeHead(answer.status, {
          ...answer.headers,
          "Content-Length": Buffer.byteLength(answer.body)
        });
        response.end(answer.body);
      });
      child.stdin.end(body);
    });
  });

  await new Promise((ready) => server.listen(port, "127.0.0.1", ready));
  const actual = server.address().port;

  return {
    url: `http://127.0.0.1:${actual}`,
    port: actual,
    root,
    state,
    shell: sh,
    /**
     * Move the clock the script reads.
     *
     * A device code lives fifteen minutes and a client must wait five seconds
     * between polls, and a test that sat through either is a test nobody runs.
     * The file is the same seam the tab's injected `now` is.
     */
    setNow(seconds) { writeFileSync(`${state}/now`, `${Math.floor(seconds)}\n`); },
    async close() {
      await new Promise((done) => server.close(done));
      rmSync(root, { recursive: true, force: true });
    }
  };
}

// --- run it by hand ---------------------------------------------------------

// Compared as resolved paths, not by name. `src/test-fake-github.mjs` ends with
// this file's own name, so a suffix test is true when the test suite imports
// this -- which started a second server on a fixed port and left the event loop
// holding it open long after the tests had finished.
const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const flag = (name) => {
    const at = process.argv.indexOf(name);
    return at > 0 && at + 1 < process.argv.length ? process.argv[at + 1] : null;
  };
  const port = Number(flag("--port")) || 9100;
  const fake = await serveFakeGitHub({
    port,
    root: flag("--root") || ".fake-github",
    onEvent: ({ path, status, stderr }) => {
      console.log(`  ${status}  ${path}${stderr ? `\n  stderr: ${stderr}` : ""}`);
    }
  });

  const client = Object.keys(GITHUB_CLIENTS)[0];
  console.log(`a fake GitHub on ${fake.url}, run by ${fake.shell}`);
  console.log(`  nothing here is a secret, and no token it issues means anything.\n`);
  console.log(`  node tools/bridge.mjs --github-client-id ${client} \\`);
  console.log(`                        --github-base ${fake.url}\n`);
  console.log(`  authorise without typing a code:`);
  console.log(`  curl "${fake.url}/login/device?user_code=CODE&outcome=approve"`);
  console.log(`  ... and outcome=deny or outcome=expire for the other two answers.\n`);
  const stop = async () => { await fake.close(); process.exit(0); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
