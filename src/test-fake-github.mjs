// Signing in to GitHub, tested against a GitHub.
//
// `src/test-device-flow.mjs` injects a `fetch` and proves the state machine:
// the interval, the one-shot token, every way GitHub can say no. What it cannot
// see is the wire. A fake `fetch` returns whatever object the test wrote, so it
// would keep passing if `device-flow.js` stopped sending a form body, dropped
// the `Accept` header, or started trusting the status code -- and every one of
// those is a real way to break against the real GitHub while the suite stays
// green.
//
// So these run the same `DeviceLogin`, unmodified, over HTTP, against the shell
// script from `app/idp.js` that will run inside a guest. Nothing here reaches
// github.com and nothing here is a secret.
//
// The three things this reaches that a fake `fetch` cannot:
//
//   the encodings   GitHub answers form-encoded unless asked for JSON, and a
//                   client that forgets the header gets a body JSON.parse
//                   cannot read
//   the statuses    a refusal arrives as 200 with an error body, so a client
//                   that switched on the status code would read it as success
//   the clock       the interval is enforced at both ends, and only one of
//                   them is the code under test
//
// Run with: node src/test-fake-github.mjs

import { GITHUB_CLIENTS, pkcePair, verifyChallenge } from "../app/idp.js";
import { DeviceLogin } from "./host/device-flow.js";
import { findShell, serveFakeGitHub } from "../tools/fake-github.mjs";

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

// The script is /bin/sh and awk. A host without either cannot run these, and
// saying so is better than failing in a way that looks like a bug in the code
// under test.
const shell = findShell();
if (!shell) {
  console.log("\nSKIPPED: no POSIX shell with awk on this host.");
  console.log("Everything else in the suite is unaffected; set RRD_SH to one to run these.");
  process.exit(0);
}

const CLIENT = "Iv1.test-client-do-not-trust";
const SECRET = GITHUB_CLIENTS[CLIENT].secret;
const CALLBACK = GITHUB_CLIENTS[CLIENT].callbacks[0];
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";

const fake = await serveFakeGitHub({ root: ".fake-github-test", shell });

// One clock, read by both ends. The script reads a file and `DeviceLogin` takes
// an injected `now`, so the only way they can disagree is if a test forgets to
// move both -- which is what this function is for.
let clock = 1_000_000;
const advance = (seconds = 0) => { clock += seconds; fake.setNow(clock); };
advance(0);

const login = (extra = {}) =>
  new DeviceLogin({ clientId: CLIENT, base: fake.url, now: () => clock * 1000, ...extra });

/** POST a form the way a client does, for the paths no client here has yet. */
const post = async (path, fields, accept = "application/json") => {
  const response = await fetch(`${fake.url}${path}`, {
    method: "POST",
    headers: { Accept: accept, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString()
  });
  const text = await response.text();
  try { return { status: response.status, body: JSON.parse(text) }; }
  catch { return { status: response.status, body: text.trim() }; }
};

/** Type the code at the fake github.com, or refuse it, or let it go stale. */
const authorize = (userCode, outcome = "approve") =>
  post("/login/device", { user_code: userCode, outcome });

try {

// ----------------------------------------------------------- the whole flow

console.log("\nsigning in, end to end");
{
  const flow = login();
  const started = await flow.start();
  eq("a code arrives in GitHub's shape", /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(started.userCode), true);
  eq("with GitHub's interval", started.interval, 5);
  // It names itself rather than github.com, which is the only answer that can
  // finish the flow -- and the difference between a tester who can click the
  // link and one sent to a site that never heard of their code.
  eq("and somewhere to type it that can actually take it",
     started.verificationUri, `${fake.url}/login/device`);

  const early = await flow.poll(started.handle);
  eq("polling before the interval answers without asking", early.status, "pending");
  check("and really did not ask", early.waiting === true);

  advance(5);
  const pending = await flow.poll(started.handle);
  eq("once it may ask, the server says the user has not finished", pending.status, "pending");
  check("which it learned over HTTP, not from a fixture", pending.waiting === undefined);

  await authorize(started.userCode);
  advance(5);
  const done = await flow.poll(started.handle);
  eq("after the code is entered, a token", done.status, "done");
  check("of the shape a GitHub App issues", /^ghu_[0-9a-f]{40}$/.test(done.token || ""), done.token);
  eq("carrying what it can reach", done.scope, "");

  const again = await flow.poll(started.handle);
  eq("and it is handed out exactly once", again.status, "unknown");
  eq("with nothing left holding it", flow.size, 0);
}
{
  const flow = login({ scope: "repo" });
  const started = await flow.start();
  await authorize(started.userCode);
  advance(5);
  const done = await flow.poll(started.handle);
  eq("a scope asked for is a scope returned", done.scope, "repo");
}

// ------------------------------------------------------- every way to say no

console.log("\nevery way it can go wrong, over the wire");
{
  const flow = login();
  const started = await flow.start();
  await authorize(started.userCode, "deny");
  advance(5);
  eq("a refusal at github.com becomes denied", (await flow.poll(started.handle)).status, "denied");
  eq("and is not kept", flow.size, 0);
}
{
  // The server ages the code out while the client still believes it is live,
  // which is the only way to test that the client believes the server.
  const flow = login();
  const started = await flow.start();
  await authorize(started.userCode, "expire");
  advance(5);
  eq("a code the server has expired becomes expired", (await flow.poll(started.handle)).status, "expired");
}
{
  let message = "";
  try { await login({ clientId: "Iv1.nonexistent" }).start(); }
  catch (err) { message = err.message; }
  // The same bare "Not Found" the real github.com answers an unknown client id
  // with -- measured against it, and the reason device-flow.js rewrites it.
  check("a client id GitHub does not know becomes actionable advice",
        /client id/.test(message) && /device flow/.test(message), message);
  check("and does not say \"no description\"", !/no description/.test(message), message);
}
{
  let message = "";
  try { await login({ clientId: "Iv1.no-device-flow" }).start(); }
  catch (err) { message = err.message; }
  check("an app with the device flow unticked says so", /not enabled/.test(message), message);
}
{
  const flow = login();
  const started = await flow.start();
  const wrong = await post("/login/oauth/access_token",
    { grant_type: GRANT, client_id: "Iv1.no-device-flow", device_code: "x".repeat(40) });
  eq("a device code from another app is refused", wrong.body.error, "incorrect_device_code");
  await authorize(started.userCode);
}

// ------------------------------------------------------------- the interval

console.log("\nthe interval, enforced at both ends");
{
  // `DeviceLogin` will not poll early, so the server's half of this cannot be
  // reached through it -- which is the point. If that local guard ever goes,
  // this is the answer a real GitHub would start sending, and it is worth
  // knowing that it arrives correctly rather than assuming it.
  const flow = login();
  const started = await flow.start();
  const raw = await post("/login/oauth/access_token",
    { grant_type: GRANT, client_id: CLIENT, device_code: "z".repeat(40) });
  eq("an unknown code is not a slow_down", raw.body.error, "incorrect_device_code");

  const hurried = await post("/login/oauth/access_token",
    { grant_type: GRANT, client_id: CLIENT,
      device_code: (await (await fetch(`${fake.url}/login/device/code`, {
        method: "POST", headers: { Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded" },
        body: `client_id=${CLIENT}` })).json()).device_code });
  eq("polling faster than the interval earns a slow_down", hurried.body.error, "slow_down");
  eq("and a wider interval to obey", hurried.body.interval, 10);
  await authorize(started.userCode, "deny");
}

// ------------------------------------------------------------- the encodings

console.log("\nthe two encodings, which a fake fetch cannot have");
{
  const asked = await post("/login/device/code", { client_id: CLIENT }, "application/json");
  check("asked for JSON, it answers JSON", typeof asked.body === "object", asked.body);

  const unasked = await post("/login/device/code", { client_id: CLIENT }, "");
  check("asked for nothing, it answers form-encoded, as GitHub does",
        typeof unasked.body === "string" && unasked.body.startsWith("device_code="),
        unasked.body);
  // The trap above is armed, so this is the assertion that matters: the client
  // under test sends the header, and a change that dropped it would fail here
  // rather than in production.
  const flow = login();
  const started = await flow.start();
  check("and DeviceLogin asks, so it never meets the other one", Boolean(started.userCode));
  await authorize(started.userCode, "deny");
}
{
  const refusal = await post("/login/oauth/access_token", { grant_type: "password", client_id: CLIENT });
  eq("a grant nobody supports is named", refusal.body.error, "unsupported_grant_type");
  // GitHub answers a refused token request with a 200 and an error body. A
  // client that read the status code would call this a success.
  eq("and arrives as 200, the way GitHub sends it", refusal.status, 200);
}

// --------------------------------------------------- the web flow, for later

console.log("\nthe web flow, which is where a client secret starts mattering");
{
  const { verifier, challenge } = await pkcePair();
  check("the test's own PKCE pair is well formed", await verifyChallenge(verifier, challenge));

  const authorized = await fetch(
    `${fake.url}/login/oauth/authorize?response_type=code&client_id=${CLIENT}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK)}&state=st-1&scope=repo` +
    `&code_challenge=${challenge}&code_challenge_method=S256`,
    { redirect: "manual" });
  eq("authorizing redirects", authorized.status, 302);
  const back = new URL(authorized.headers.get("location"));
  eq("to the address the app registered", `${back.origin}${back.pathname}`, CALLBACK);
  eq("carrying the state it was given", back.searchParams.get("state"), "st-1");
  const code = back.searchParams.get("code");
  check("and a code", /^[0-9a-f]{40}$/.test(code || ""), code);

  const bare = await post("/login/oauth/access_token",
    { grant_type: "authorization_code", client_id: CLIENT, code,
      redirect_uri: CALLBACK, code_verifier: verifier });
  // Measured against the real github.com, PKCE and all: the secret is required
  // there, so a client that hoped to be a public client fails here too.
  eq("without the secret, the exchange is refused", bare.body.error, "incorrect_client_credentials");

  const wrong = await post("/login/oauth/access_token",
    { grant_type: "authorization_code", client_id: CLIENT, client_secret: "not-it",
      code, redirect_uri: CALLBACK, code_verifier: verifier });
  eq("and with the wrong one, refused the same way", wrong.body.error, "incorrect_client_credentials");

  const ok = await post("/login/oauth/access_token",
    { grant_type: "authorization_code", client_id: CLIENT, client_secret: SECRET,
      code, redirect_uri: CALLBACK, code_verifier: verifier });
  check("with the right one, a token", /^ghu_[0-9a-f]{40}$/.test(ok.body.access_token || ""),
        JSON.stringify(ok.body));

  const spent = await post("/login/oauth/access_token",
    { grant_type: "authorization_code", client_id: CLIENT, client_secret: SECRET,
      code, redirect_uri: CALLBACK, code_verifier: verifier });
  eq("and the code is spent", spent.body.error, "bad_verification_code");
}
{
  const { challenge, verifier } = await pkcePair();
  const authorized = await fetch(
    `${fake.url}/login/oauth/authorize?response_type=code&client_id=${CLIENT}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK)}&code_challenge=${challenge}` +
    `&code_challenge_method=S256`, { redirect: "manual" });
  const code = new URL(authorized.headers.get("location")).searchParams.get("code");

  // The script records the challenge and requires a verifier, and does not
  // compute the digest -- `app/idp.js` already decided that question for the
  // endpoint beside this one: busybox has sha256sum and no portable way to get
  // its output back into base64url, and whether the image carries openssl is
  // unverified. So this asserts what the script does check, and the pair itself
  // is checked above, where WebCrypto is.
  const silent = await post("/login/oauth/access_token",
    { grant_type: "authorization_code", client_id: CLIENT, client_secret: SECRET,
      code, redirect_uri: CALLBACK });
  eq("a challenge sent but no verifier is refused", silent.body.error, "invalid_request");
  check("and says which one is missing", /code_verifier/.test(silent.body.error_description || ""),
        silent.body.error_description);
  void verifier;
}
{
  const refused = await fetch(
    `${fake.url}/login/oauth/authorize?response_type=code&client_id=${CLIENT}` +
    `&redirect_uri=${encodeURIComponent("http://evil.test/cb")}`, { redirect: "manual" });
  eq("an address the app never registered gets no code", refused.status, 400);
  check("and is told why", /not registered/.test(await refused.text()));
}

// ------------------------------------------------------------- the machinery

console.log("\nthe fake itself");
{
  const missing = await fetch(`${fake.url}/login/nope`);
  eq("an endpoint it does not have is a 404", missing.status, 404);

  const page = await fetch(`${fake.url}/login/device`);
  const html = await page.text();
  check("the page a person would type a code into exists", /Enter the code/.test(html));
  check("and says it is not github.com", /not github\.com/.test(html), html.slice(0, 200));
}

} finally {
  await fake.close();
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
