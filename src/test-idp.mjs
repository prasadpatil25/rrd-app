// Tests for the test identity provider.
//
// The point of these is that they need no VM. Everything the tab is responsible
// for -- the key, the signature, PKCE, the claims, the clock -- is ordinary code
// and can be checked here; what is left for a booted guest is the shell, which
// is checked by running it.
//
// Two of these are drift tests rather than logic tests. The JWKS and the
// discovery document are static files on a static host, and nothing at runtime
// would ever notice them disagreeing with the key that actually signs. A
// published JWKS that does not match the signer is the exact failure this
// design is most likely to ship, because it would work on the machine that
// wrote both.
//
// Time is injected: a token is mostly a statement about expiry, and a test that
// waited for one would be a test nobody runs.
//
// Run with: node src/test-idp.mjs

import { readFileSync } from "node:fs";
import {
  ALG, AUTHORIZE, CLIENTS, ISSUER, JWKS, KID, PRIVATE_JWK, PUBLIC_JWK, SIGNER_PORT,
  TOKEN, USERS, base64url, callbackUrl, install, issue, pkcePair, signJwt, startSigner,
  verifyChallenge, verifyWithJwks
} from "../app/idp.js";

let passed = 0, failed = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log("  PASS  " + name); }
  else { failed++; failures.push(name); console.log("  FAIL  " + name + (detail ? "   [" + detail + "]" : "")); }
}
function eq(name, actual, expected) {
  check(name, JSON.stringify(actual) === JSON.stringify(expected),
        `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

const check_ = (name, ok, detail = "") => check(name, ok, detail);

/**
 * A real P-256 public key that is not the one that signs.
 *
 * Bending a coordinate of the real key instead gives a point that is not on the
 * curve, and WebCrypto refuses it as malformed key material -- which is a
 * different failure from "this signature was made by another key", and the
 * second is the one a client actually meets.
 */
const STRANGER = {
  kty: "EC", crv: "P-256", kid: "test-key-do-not-trust", alg: "ES256", use: "sig",
  x: "dSKFplQK9b_Iyx9s1ttimqlQ5EM5c_eOKjq6HTnlr1g",
  y: "vXLPfheVmvyNYmXWxgSEIeUgzI8FpFFevNt8RfvzZt0"
};
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
const headerOf = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[0], "base64url").toString("utf8"));

/** Verify a JWT the way a client would: with the published key, and nothing else. */
async function verify(jwt, jwk = PUBLIC_JWK) {
  const key = await crypto.subtle.importKey(
    "jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
  const [header, payload, signature] = jwt.split(".");
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key,
    Buffer.from(signature, "base64url"), encoder.encode(`${header}.${payload}`)
  );
}

// ------------------------------------------------- the published key material

console.log("\nthe key that is published and the key that signs");
{
  const published = JSON.parse(readFileSync(new URL("../idp-test/jwks.json", import.meta.url), "utf8"));
  eq("the JWKS on disk is the one the module exports", published, JWKS);
  eq("and it is the public half of the signing key",
     [published.keys[0].x, published.keys[0].y], [PRIVATE_JWK.x, PRIVATE_JWK.y]);
  check("the private half is not in the published file", !("d" in published.keys[0]));
  eq("the key id says what it is", published.keys[0].kid, "test-key-do-not-trust");
}
{
  const discovery = JSON.parse(readFileSync(
    new URL("../idp-test/.well-known/openid-configuration", import.meta.url), "utf8"));
  eq("discovery names the issuer the signer uses", discovery.issuer, ISSUER);
  eq("and points at the JWKS beside it", discovery.jwks_uri, `${ISSUER}/jwks.json`);
  eq("and advertises the algorithm that is actually used",
     discovery.id_token_signing_alg_values_supported, [ALG]);
  check("and offers PKCE with S256",
        (discovery.code_challenge_methods_supported || []).includes("S256"));
  // The endpoints are the bridge, not the issuer, and that is the whole trick.
  check("the endpoints are not on the issuer's host",
        !discovery.token_endpoint.startsWith(ISSUER), discovery.token_endpoint);
}

// ------------------------------------------------------------------- signing

console.log("\nsigning");
{
  const jwt = await signJwt({ sub: "alice", iss: ISSUER });
  eq("three parts", jwt.split(".").length, 3);
  eq("the header names the key a client will look up", headerOf(jwt).kid, KID);
  eq("and the algorithm", headerOf(jwt).alg, "ES256");
  check("the signature verifies against the published key", await verify(jwt));
  eq("ES256 is a raw r||s pair, so the signature is 64 bytes",
     Buffer.from(jwt.split(".")[2], "base64url").length, 64);
}
{
  const jwt = await signJwt({ sub: "alice" });
  const tampered = jwt.split(".");
  tampered[1] = base64url(encoder.encode(JSON.stringify({ sub: "root" })));
  check("a payload swapped for another does not verify", !(await verify(tampered.join("."))));
}
{
  // base64url and not base64: a JWT that carries + or / is one a client splits wrongly.
  const encoded = base64url(new Uint8Array([251, 255, 190, 255]));
  check("base64url uses the URL alphabet", !/[+/=]/.test(encoded), encoded);
}

// ---------------------------------------------------------------------- PKCE

console.log("\nPKCE");
{
  // The example pair from RFC 7636 appendix B, so this checks the encoding
  // against the specification rather than against itself.
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  check("the specification's own example verifies", await verifyChallenge(verifier, challenge));
  check("a different verifier does not", !(await verifyChallenge(verifier + "x", challenge)));
  check("an empty verifier does not", !(await verifyChallenge("", challenge)));
  check("an empty challenge does not", !(await verifyChallenge(verifier, "")));
}

// -------------------------------------------------------------------- claims

console.log("\nthe claims, and whose clock stamps them");
{
  const at = 1_757_000_000_000;                 // a fixed instant, in milliseconds
  const tokens = await issue({
    sub: "alice", aud: "test-client", scope: "openid profile",
    nonce: "n-0S6", name: "Alice Example", email: "alice@example.test",
    now: () => at
  });

  const id = claimsOf(tokens.id_token);
  eq("iat is the tab's clock, not the guest's", id.iat, Math.floor(at / 1000));
  eq("exp is an hour later by default", id.exp - id.iat, 3600);
  eq("the issuer is the static one", id.iss, ISSUER);
  eq("the audience is the client", id.aud, "test-client");
  eq("the nonce is echoed, which is the replay defence", id.nonce, "n-0S6");
  eq("the profile claims come from the fixture", [id.name, id.email],
     ["Alice Example", "alice@example.test"]);

  const access = claimsOf(tokens.access_token);
  eq("the access token carries the scope", access.scope, "openid profile");
  check("and a jti, so two are distinguishable", typeof access.jti === "string" && access.jti.length > 0);
  check("both verify", (await verify(tokens.id_token)) && (await verify(tokens.access_token)));
  eq("the response is shaped the way a client expects", tokens.token_type, "Bearer");
  eq("and says how long it has", tokens.expires_in, 3600);
}
{
  const one = await issue({ sub: "a", aud: "c" });
  const two = await issue({ sub: "a", aud: "c" });
  check("two tokens for the same subject are not the same token",
        claimsOf(one.access_token).jti !== claimsOf(two.access_token).jti);
}
{
  let threw = "";
  try { await issue({ aud: "c" }); } catch (err) { threw = err.message; }
  check("a token with no subject is refused", /subject/.test(threw), threw);
  threw = "";
  try { await issue({ sub: "a" }); } catch (err) { threw = err.message; }
  check("a token with no audience is refused", /audience/.test(threw), threw);
}

// ------------------------------------------------------- the signer, as served

console.log("\nthe signer the guest actually talks to");

/** A stack that is only enough to drive one request through `serve`. */
function fakeStack() {
  const listeners = new Map();
  return {
    listen(port, onConnection) {
      listeners.set(port, onConnection);
      // The shape the real stack returns. A double that answers a narrower
      // contract than the thing it stands in for is a test that passes on code
      // the real stack would break.
      return { port, close: () => listeners.delete(port) };
    },
    /** Push a request in, get the parsed response back. */
    async call(port, target) {
      const chunks = [];
      const socket = {
        write: (bytes) => chunks.push(bytes),
        end: () => {}
      };
      listeners.get(port)(socket);
      socket.onData(encoder.encode(`GET ${target} HTTP/1.1\r\nHost: 10.0.2.2\r\n\r\n`));
      // The handler is async; let it settle before reading what it wrote.
      for (let spin = 0; spin < 50 && !chunks.length; spin++) await new Promise((r) => setImmediate(r));
      const text = decoder.decode(Buffer.concat(chunks.map(Buffer.from)));
      const [head, ...rest] = text.split("\r\n\r\n");
      return { status: Number(head.split(" ")[1]), body: rest.join("\r\n\r\n") };
    }
  };
}

{
  const stack = fakeStack();
  const events = [];
  const server = startSigner({ net: { stack }, now: () => 1_757_000_000_000,
                               onEvent: (e) => events.push(e) });
  eq("it listens where the CGI looks for it", server.port, SIGNER_PORT);

  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  const good = await stack.call(SIGNER_PORT,
    `/sign?sub=alice&aud=test-client&scope=openid&challenge=${challenge}&verifier=${verifier}`);
  const issued = JSON.parse(good.body);
  eq("a good exchange answers 200", good.status, 200);
  check("with a token that verifies", await verify(issued.id_token));
  eq("and says so", events.at(-1).type, "issued");

  const bad = await stack.call(SIGNER_PORT,
    `/sign?sub=alice&aud=test-client&challenge=${challenge}&verifier=wrong`);
  const refusal = JSON.parse(bad.body);
  eq("a bad verifier is refused", refusal.error, "invalid_grant");
  eq("and refused as an event too", events.at(-1).reason, "pkce");
  // The reason this is 200: busybox wget prints the body of a 200 and swallows
  // the body of anything else, so the CGI could not read its own refusal.
  eq("but still answered 200, so the guest can read why", bad.status, 200);

  const missing = await stack.call(SIGNER_PORT, "/nowhere");
  eq("an unknown endpoint says which one", JSON.parse(missing.body).error, "invalid_request");
}

// --------------------------------------------------------------- the fixtures

console.log("\nthe fixtures and the shell they are read by");
{
  check("there is a client to test with", Object.keys(CLIENTS).length > 0);
  check("and a user", Object.keys(USERS).length > 0);
  for (const [id, redirects] of Object.entries(CLIENTS)) {
    check(`${id} has at least one redirect URI`, redirects.length > 0);
    check(`${id}'s redirect URIs are one per line, so grep -qxF matches whole`,
          redirects.every((uri) => !uri.includes("\n")));
  }
}
{
  // The placeholder is substituted at install time. One that survives would put
  // the fixtures in a directory called __ROOT__ and fail at the first lookup.
  for (const [name, script] of [["authorize", AUTHORIZE], ["token", TOKEN]]) {
    check(`${name} substitutes its root`,
          !script.replace(/__ROOT__/g, "/disk/idp").includes("__ROOT__"));
    check(`${name} starts with a shebang`, script.startsWith("#!/bin/sh"));
    check(`${name} filters anything that becomes a path`, script.includes("tr -cd 'A-Za-z0-9._-'"));
  }
  check("the token endpoint spends the code before it can fail again",
        /saved=\$\(cat "\$record"\)\s*\nrm -f "\$record"/.test(TOKEN));
  check("the token endpoint asks the tab on the port the signer uses",
        TOKEN.includes(`:${SIGNER_PORT}`));
  check("authorize refuses anything but S256",
        AUTHORIZE.includes('[ "$method" = "S256" ]'));
}

// ------------------------------------------------------- the checker itself
//
// `check-idp.js` is what the UI button reports from, so it is worth knowing it
// would notice a broken IdP rather than only agreeing with a working one. The
// machine below is a stand-in: `run` answers the shell probes and `net.request`
// answers the flow, and each case bends one thing and asks which row fails.
//
// The JWKS is fetched rather than imported by the real checker -- the failure
// worth catching is the published file disagreeing with the signer -- so `fetch`
// is stubbed here to serve whichever key the case wants.

console.log("\nthe checker the button reports from");

// Imported under another name: `check` here is the assertion helper.
const { check: runCheck } = await import("../app/check-idp.js");

function fakeMachine({ status302 = true, allowReplay = false, signWith = null } = {}) {
  const codes = new Map();
  const spent = new Set();
  const answer = (status, body, headers = {}) => ({
    status, headers, body: encoder.encode(body)
  });

  return {
    async run(sent) {
      // Enough of a console for `rc()`: the output, then the marker it waits for.
      const out =
        /ls .*clients/.test(sent) ? "test-client\nalice" :
        /test -x/.test(sent) ? "" :
        /cat .*codes/.test(sent) ? [...codes.entries()].map(([c, r]) =>
            `client_id=test-client\nredirect_uri=urn:ietf:wg:oauth:2.0:oob\n` +
            `challenge=${r.challenge}\nsub=alice\nscope=openid profile\nnonce=n-check`).join("") :
        "";
      return `${out}\nrc=0`;
    },
    net: {
      ip: "10.0.2.2",
      async request({ method = "GET", path, body }) {
        const [route, query] = path.split("?");
        const params = new URLSearchParams(query || "");

        if (route === "/cgi-bin/authorize") {
          if (!/^(urn:ietf:wg:oauth:2\.0:oob|http:\/\/localhost:8080\/callback)$/
                .test(params.get("redirect_uri") || "")) {
            return answer(400, "redirect_uri is not registered for test-client");
          }
          const code = "code" + (codes.size + 1);
          codes.set(code, { challenge: params.get("code_challenge"),
                            nonce: params.get("nonce") || "" });
          const location = `${params.get("redirect_uri")}?code=${code}`;
          return status302
            ? answer(302, location, { location })
            : answer(200, location);          // busybox did not honour Status:
        }

        if (route === "/cgi-bin/token" && method === "POST") {
          const fields = new URLSearchParams(decoder.decode(body));
          const code = fields.get("code");
          const record = codes.get(code);
          const err = (e, d) => answer(400, JSON.stringify({ error: e, error_description: d }));
          if (!record) return err("invalid_grant", "no such code, or it has already been used");
          if (spent.has(code) && !allowReplay) {
            return err("invalid_grant", "no such code, or it has already been used");
          }
          spent.add(code);
          if (!(await verifyChallenge(fields.get("code_verifier"), record.challenge))) {
            return err("invalid_grant", "the code_verifier does not match the code_challenge");
          }
          const tokens = await issue({
            sub: "alice", aud: "test-client", scope: "openid profile",
            nonce: record.nonce, name: "Alice Example", email: "alice@example.test"
          });
          return answer(200, JSON.stringify(tokens));
        }
        return answer(404, "not found");
      }
    }
  };
}

/** Serve a chosen JWKS to the checker, the way the static host would. */
function withJwks(keys, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ keys }) });
  return fn().finally(() => { globalThis.fetch = real; });
}

const rowOf = (report, name) => report.rows.find((r) => r.check.includes(name));

{
  const report = await withJwks(JWKS.keys, () => runCheck(fakeMachine()));
  check_("a working IdP passes every row", report.ok,
         JSON.stringify(report.rows.filter((r) => !r.ok).map((r) => r.check + ": " + r.detail)));
  check_("and it did verify a real signature, not skip the check",
         rowOf(report, "verifies against the published JWKS").ok);
  check_("and it checked the refusals too",
         report.rows.filter((r) => r.layer === "refusals").length === 3);
}
{
  // The open question, seen from the checker: the flow still works, so this must
  // not fail -- but it must say so, or the finding is invisible.
  const report = await withJwks(JWKS.keys, () => runCheck(fakeMachine({ status302: false })));
  check_("a busybox that ignores Status: does not fail the run", report.ok);
  check_("but the row says a redirect-following client would not see the code",
         /not 302/.test(rowOf(report, "authorize issues a code").detail),
         rowOf(report, "authorize issues a code").detail);
}
{
  // The failure this design is most likely to ship: a published JWKS that is not
  // the key that signs. Everything else about the IdP works.
  const report = await withJwks([STRANGER], () => runCheck(fakeMachine()));
  check_("a JWKS that disagrees with the signer fails", !report.ok);
  check_("and it is the token row that names it",
         rowOf(report, "verifies against the published JWKS").ok === false);
}
{
  // An IdP that hands out a second token for a spent code. Every other row is
  // green, which is exactly why a checker that stopped at the happy path lies.
  const report = await withJwks(JWKS.keys, () => runCheck(fakeMachine({ allowReplay: true })));
  check_("an IdP that allows replay fails", !report.ok);
  check_("and it is the replay row that names it",
         rowOf(report, "spent code cannot be spent again").ok === false);
}

// ------------------------------------------------- signing in from the app

console.log("\nthe pieces the Sign in button is built from");
{
  const { verifier, challenge } = await pkcePair();
  check_("a generated pair satisfies its own challenge", await verifyChallenge(verifier, challenge));
  const other = await pkcePair();
  check_("two pairs are not the same pair", verifier !== other.verifier);
  check_("the challenge is not the verifier", verifier !== challenge);
  check_("neither carries a character that would need escaping in a query string",
         !/[+/=&?#]/.test(verifier + challenge));
}
{
  const jwt = await signJwt({ sub: "alice", iss: ISSUER });
  const { header, claims } = await verifyWithJwks(jwt, JWKS.keys);
  eq("a good token verifies and gives back its claims", claims.sub, "alice");
  eq("and its header", header.kid, KID);
}
{
  // The check a client actually depends on, from the other side: a token this
  // module could verify against its own key must still fail against a JWKS that
  // is not the signer's.
  const jwt = await signJwt({ sub: "alice" });
  const wrong = [STRANGER];
  let message = "";
  try { await verifyWithJwks(jwt, wrong); } catch (err) { message = err.message; }
  check_("a JWKS that is not the signer's is refused", /do not verify|does not verify/.test(message), message);

  message = "";
  try { await verifyWithJwks(jwt, [{ ...PUBLIC_JWK, kid: "someone-else" }]); }
  catch (err) { message = err.message; }
  check_("and a JWKS with no matching kid says so", /kid/.test(message), message);

  message = "";
  try { await verifyWithJwks("not-a-jwt", JWKS.keys); } catch (err) { message = err.message; }
  check_("and something that is not a JWT at all", /not a JWT/.test(message), message);
}
{
  const url = callbackUrl();
  check_("the callback is a real absolute URL", /^[a-z]+:\/\//.test(url), url);
  check_("on the app's own origin, beside idp.js", url.endsWith("/app/callback.html"), url);
}

// ------------------------------------------- what install writes, without a VM
//
// `install` only talks to the guest through `rc`, so a recorder in its place is
// enough to see what would land on the disk. Two things are worth knowing
// without booting: that the callback URL -- the one part of the fixture that is
// computed rather than written down -- actually reaches the client file, and
// that a directory already holding somebody's site keeps its own index.

console.log("\nwhat install writes");

function recorder({ indexExists }) {
  const commands = [];
  const rc = async (_run, command) => {
    commands.push(command);
    if (/^test -f .*index\.html$/.test(command)) return { ok: indexExists, code: indexExists ? 0 : 1, output: "" };
    return { ok: true, code: 0, output: "" };
  };
  return { fs: { rc }, commands,
           writtenTo: (path) => commands.filter((c) => c.endsWith(` ${path}`) || c.endsWith(`> ${path}`) ||
                                                       c.includes(`> ${path}`)).join("\n") };
}

{
  const rec = recorder({ indexExists: false });
  const where = await install(null, { fs: rec.fs });
  eq("it reports where the fixtures went", where.root, "/disk/idp");
  const client = rec.writtenTo("/disk/idp/clients/test-client");
  check_("the client fixture carries the computed callback URL",
         client.includes(callbackUrl()), client.slice(0, 200));
  for (const fixed of CLIENTS["test-client"]) {
    check_(`and still carries the written-down ${fixed}`, client.includes(fixed));
  }
  check_("the users are written", !!rec.writtenTo("/disk/idp/users/alice"));
  check_("an empty directory gets a landing page",
         rec.commands.some((c) => c.includes("> /disk/idp/www/index.html")));
  check_("and the CGI is made executable",
         rec.commands.includes("chmod +x /disk/idp/www/cgi-bin/authorize"));

  // The fake GitHub travels with the IdP: same disk, same install, same commit.
  // Its apps are written down rather than computed, because a bridge is reached
  // at a port and not at an address only the runtime knows.
  eq("it reports where the GitHub endpoints went", where.github,
     "/disk/idp/www/cgi-bin/github");
  check_("and installs them",
         rec.commands.includes("chmod +x /disk/idp/www/cgi-bin/github"));
  const app = rec.writtenTo("/disk/idp/gh-clients/Iv1.test-client-do-not-trust");
  check_("an app with the device flow enabled is on the disk",
         app.includes("device=on"), app);
  check_("carrying the secret that protects nothing", app.includes("secret="), app);
  const unticked = rec.writtenTo("/disk/idp/gh-clients/Iv1.no-device-flow");
  check_("and one with it unticked, which is the wall people hit",
         unticked.includes("device=off"), unticked);
}
{
  // The rule the Serve button follows, and the reason the button can install
  // into /disk/www without eating the demo site.
  const rec = recorder({ indexExists: true });
  await install(null, { fs: rec.fs, directory: "/disk/www" });
  check_("a directory that already has an index keeps it",
         !rec.commands.some((c) => c.includes("> /disk/www/index.html")));
  check_("but the endpoints still go in",
         rec.commands.includes("chmod +x /disk/www/cgi-bin/token"));
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
