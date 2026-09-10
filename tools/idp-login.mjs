// Log in with the identity provider running inside the machine.
//
// The whole loop in one command: a PKCE pair, a browser sent to the machine's
// authorize endpoint, a callback caught here, the code exchanged, and the token
// verified against the JWKS the static host serves. It prints who logged in.
//
// This is the client, not the server. It exists because "point a real app at it"
// is the only claim in `docs/oauth-test-idp.md` that a person cannot check by
// reading -- and because the shortest honest demonstration of an identity
// provider is somebody logging in.
//
//     node tools/idp-login.mjs                # opens a browser, pick a user
//     node tools/idp-login.mjs --user alice   # no browser, for a script or CI
//
// It needs three things already running, and says which one is missing:
//
//     python serve.py                 the static host, for the JWKS
//     node tools/bridge.mjs           a door for things that are not a tab
//     a tab with a machine, connected to the bridge and holding the IdP
//
// THE SIGNING KEY IS PUBLIC. Anyone can forge the token this prints. It is a
// fixture for testing a login flow and nothing else.
//
//   --bridge URL   where the machine is reachable   (http://localhost:9000)
//   --jwks URL     where to verify against          (http://localhost:8000/idp-test/jwks.json)
//   --client ID    the registered client            (test-client)
//   --port N       the callback port                (8080)
//   --user NAME    skip the browser and sign in as NAME
//   --no-open      print the URL instead of opening a browser

import http from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";

const args = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const at = args.indexOf(name);
  return at < 0 || !args[at + 1] || args[at + 1].startsWith("--") ? fallback : args[at + 1];
};

const BRIDGE = flag("--bridge", "http://localhost:9000").replace(/\/$/, "");
const JWKS = flag("--jwks", "http://localhost:8000/idp-test/jwks.json");
const CLIENT = flag("--client", "test-client");
const PORT = Number(flag("--port", "8080"));
const USER = flag("--user");
const NO_OPEN = args.includes("--no-open");
const REDIRECT = `http://localhost:${PORT}/callback`;

const base64url = (buffer) => Buffer.from(buffer).toString("base64url");
const sha256 = (text) => createHash("sha256").update(text).digest();

// PKCE, and a state and nonce that are actually checked further down. A demo
// that generates them and never looks at them teaches the wrong lesson.
const verifier = base64url(randomBytes(32));
const challenge = base64url(sha256(verifier));
const state = base64url(randomBytes(12));
const nonce = base64url(randomBytes(12));

const authorizeUrl = (extra = {}) => `${BRIDGE}/cgi-bin/authorize?` + new URLSearchParams({
  response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
  scope: "openid profile email", state, nonce,
  code_challenge: challenge, code_challenge_method: "S256", ...extra
});

function die(message, hint = "") {
  console.error(`\n  ${message}`);
  if (hint) console.error(`\n${hint}`);
  process.exit(1);
}

async function reachable() {
  try { await fetch(`${BRIDGE}/`, { signal: AbortSignal.timeout(4000) }); return true; }
  catch { return false; }
}

/** Open a browser, on whichever of the three platforms this is. */
function openBrowser(url) {
  const [command, commandArgs] = process.platform === "win32"
    ? ["cmd", ["/c", "start", "", url]]
    : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  try { spawn(command, commandArgs, { detached: true, stdio: "ignore" }).unref(); return true; }
  catch { return false; }
}

/** Wait for the browser to come back to us with a code. */
function waitForCallback() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, `http://localhost:${PORT}`);
      if (url.pathname !== "/callback") { response.writeHead(404).end("not the callback\n"); return; }

      const page = (title, body) =>
        `<!doctype html><meta charset=utf-8><title>${title}</title>` +
        "<style>body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:60ch;" +
        "margin:8vh auto;padding:0 20px;background:#EFF2F1;color:#131C1A}" +
        "@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}}</style>" + body;

      const error = url.searchParams.get("error");
      if (error) {
        response.writeHead(400, { "Content-Type": "text/html; charset=utf-8" })
          .end(page("Refused", `<h1>Refused</h1><p>${error}</p>`));
        server.close();
        reject(new Error(`the machine refused: ${error}`));
        return;
      }

      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(page("Signed in",
        "<h1>Signed in</h1><p>You can close this tab; the terminal has the token.</p>" +
        "<p><strong>The signing key is public.</strong> This token proves nothing.</p>"));
      server.close();
      resolve({ code: url.searchParams.get("code"), state: url.searchParams.get("state") });
    });

    server.on("error", (err) => reject(err.code === "EADDRINUSE"
      ? new Error(`something is already listening on ${PORT}; free it or pass --port`)
      : err));
    server.listen(PORT, "127.0.0.1");
    setTimeout(() => { server.close(); reject(new Error("nobody signed in within five minutes")); }, 300000);
  });
}

/** Verify a JWT the way a client would: against the key the static host serves. */
async function verify(jwt, keys) {
  const [head, payload, signature] = jwt.split(".");
  const header = JSON.parse(Buffer.from(head, "base64url").toString());
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`the JWKS has no key with kid ${header.kid}`);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key,
    Buffer.from(signature, "base64url"), Buffer.from(`${head}.${payload}`)
  );
  if (!ok) throw new Error("the signature does not verify: the JWKS and the signer disagree");
  return JSON.parse(Buffer.from(payload, "base64url").toString());
}

// --- the flow ----------------------------------------------------------------

if (!(await reachable())) {
  die(`nothing is listening at ${BRIDGE}.`,
      "  A machine lives in a browser tab and cannot be connected to, so a bridge\n" +
      "  is what gives it a socket. Start one:\n\n" +
      "      node tools/bridge.mjs\n\n" +
      "  then, in the app's console, with a machine running:\n\n" +
      "      const b = await import(\"./bridge-client.js\");\n" +
      "      await b.connect({ net: window.machine.net });\n");
}

let code;
if (USER) {
  // Non-interactive: ask for the code directly and read the redirect rather than
  // being sent through it. Same endpoint, same checks, no browser.
  const response = await fetch(authorizeUrl({ username: USER }), { redirect: "manual" });
  const location = response.headers.get("location") || await response.text();
  const found = location.match(/[?&]code=([A-Za-z0-9_-]+)/);
  if (!found) die(`no code came back for ${USER}: ${location.trim().slice(0, 200)}`);
  const returned = location.match(/[?&]state=([^&\s]+)/);
  if (!returned || decodeURIComponent(returned[1]) !== state) die("the state did not come back unchanged");
  code = found[1];
  console.log(`  signed in as ${USER} without a browser`);
} else {
  const url = authorizeUrl();
  console.log(`\n  Sign in here:\n\n    ${url}\n`);
  if (!NO_OPEN) openBrowser(url);
  const back = await waitForCallback().catch((err) => die(err.message));
  if (back.state !== state) die("the state that came back is not the one that went out");
  code = back.code;
}

const tokenResponse = await fetch(`${BRIDGE}/cgi-bin/token`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code", code, client_id: CLIENT,
    redirect_uri: REDIRECT, code_verifier: verifier
  })
});
const tokens = await tokenResponse.json();
if (tokens.error) die(`the token endpoint refused: ${tokens.error} -- ${tokens.error_description || ""}`);

let keys;
try {
  keys = (await (await fetch(JWKS)).json()).keys;
} catch {
  die(`could not read the JWKS at ${JWKS}.`,
      "  It is a static file. Is `python serve.py` running, or pass --jwks.");
}

const claims = await verify(tokens.id_token, keys).catch((err) => die(err.message));

if (claims.nonce !== nonce) die("the nonce did not survive the round trip: this token is not the answer to this request");
if (claims.aud !== CLIENT) die(`this token was issued for ${claims.aud}, not ${CLIENT}`);
if (claims.exp * 1000 < Date.now()) die("this token is already expired");

console.log(`
  signed in

    subject     ${claims.sub}
    name        ${claims.name || "-"}
    email       ${claims.email || "-"}
    issuer      ${claims.iss}
    audience    ${claims.aud}
    expires     ${new Date(claims.exp * 1000).toISOString()}

  the id_token verified against ${JWKS}
  and that key is public, so this proves nothing at all.
`);
