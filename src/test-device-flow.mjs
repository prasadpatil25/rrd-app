// Tests for signing in to GitHub through the bridge.
//
// The real flow needs a registered app and a person typing a code into
// github.com, so GitHub is a double here: `fetch` and the clock are both
// injected, which makes the parts worth testing -- the interval, the one-shot
// token, and every way GitHub can say no -- deterministic instead of a wait.
//
// The interval is the one a careless implementation gets wrong: polling faster
// than GitHub allows earns a slow_down, and answering slow_down by polling again
// immediately earns a ban.
//
// Run with: node src/test-device-flow.mjs

import { DeviceLogin } from "./host/device-flow.js";

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

/** A GitHub that answers from a script, and records what it was asked. */
function fakeGitHub(script) {
  const calls = [];
  const queue = [...script];
  const fetch = async (url, options) => {
    const body = Object.fromEntries(new URLSearchParams(options.body));
    calls.push({ url, body });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    return {
      status: next.status || 200,
      async text() { return typeof next.body === "string" ? next.body : JSON.stringify(next.body); }
    };
  };
  return { fetch, calls };
}

const CODE = { device_code: "dev-1", user_code: "ABCD-1234",
               verification_uri: "https://github.com/login/device",
               expires_in: 900, interval: 5 };

let clock = 1_000_000;
const now = () => clock;
const login = (github, extra = {}) =>
  new DeviceLogin({ clientId: "Iv1.public", fetch: github.fetch, now, ...extra });

// ------------------------------------------------------------------- starting

console.log("\nasking for a code");
{
  const github = fakeGitHub([{ body: CODE }]);
  const flow = login(github);
  const started = await flow.start();
  eq("the user gets a code to type", started.userCode, "ABCD-1234");
  eq("and somewhere to type it", started.verificationUri, "https://github.com/login/device");
  check("and a handle that is not guessable", /^[0-9a-f]{32}$/.test(started.handle), started.handle);

  const asked = github.calls[0];
  check("it asks the device endpoint", asked.url.endsWith("/login/device/code"), asked.url);
  eq("with the public client id", asked.body.client_id, "Iv1.public");
  check("and no client secret, because a device flow has none",
        !("client_secret" in asked.body), JSON.stringify(asked.body));
}
{
  // A GitHub App takes its permissions from the app, so sending a scope would
  // be noise; an OAuth App needs one.
  const bare = fakeGitHub([{ body: CODE }]);
  await login(bare).start();
  check("no scope is sent when none was configured", !("scope" in bare.calls[0].body));

  const scoped = fakeGitHub([{ body: CODE }]);
  await login(scoped, { scope: "repo" }).start();
  eq("and one is sent when it was", scoped.calls[0].body.scope, "repo");
}
{
  const github = fakeGitHub([{ body: { error: "unauthorized_client",
                                       error_description: "device flow is not enabled" } }]);
  let message = "";
  try { await login(github).start(); } catch (err) { message = err.message; }
  check("an app without the device flow enabled says so", /not enabled/.test(message), message);
}
{
  // The first failure anyone setting this up will meet, and the one GitHub
  // describes worst: a bare "Not Found" with no description at all.
  const github = fakeGitHub([{ body: { error: "Not Found" } }]);
  let message = "";
  try { await login(github).start(); } catch (err) { message = err.message; }
  check("a bare Not Found is turned into something actionable",
        /client id/.test(message) && /device flow/.test(message), message);
  check("and it does not say \"no description\"", !/no description/.test(message), message);
}
{
  // GitHub answers HTML for a client id it does not know. A parse error here
  // would reach the user as a stack trace with nothing to act on.
  const github = fakeGitHub([{ status: 404, body: "<!doctype html><title>404</title>" }]);
  let message = "";
  try { await login(github).start(); } catch (err) { message = err.message; }
  check("an HTML answer becomes a sentence, not a parse error",
        /did not answer JSON/.test(message) && /client id/.test(message), message);
}
{
  let threw = false;
  try { new DeviceLogin({}); } catch { threw = true; }
  check("a login with no client id is refused", threw);
}

// -------------------------------------------------------------------- polling

console.log("\nwaiting for the user, at GitHub's pace");
{
  const github = fakeGitHub([{ body: CODE }, { body: { error: "authorization_pending" } }]);
  const flow = login(github);
  const { handle, interval } = await flow.start();
  eq("GitHub set the interval", interval, 5);

  const early = await flow.poll(handle);
  eq("polling before the interval does not touch the network", early.status, "pending");
  check("and really did not", early.waiting === true && github.calls.length === 1,
        `${github.calls.length} calls`);

  clock += 5000;
  const due = await flow.poll(handle);
  eq("once the interval has passed it asks", due.status, "pending");
  eq("and asked the token endpoint", github.calls.length, 2);
  check("with the device code and the device grant",
        github.calls[1].body.device_code === "dev-1" &&
        github.calls[1].body.grant_type === "urn:ietf:params:oauth:grant-type:device_code",
        JSON.stringify(github.calls[1].body));
}
{
  // slow_down means back off. Answering it at the old pace is how a client gets
  // itself rate limited, so the new interval has to stick.
  const github = fakeGitHub([{ body: CODE }, { body: { error: "slow_down", interval: 10 } }]);
  const flow = login(github);
  const { handle } = await flow.start();
  clock += 5000;
  const told = await flow.poll(handle);
  eq("slow_down is reported as still pending", told.status, "pending");
  eq("and the interval widens", told.interval, 10);

  clock += 5000;                       // the old interval, not the new one
  await flow.poll(handle);
  eq("polling at the old pace is refused locally", github.calls.length, 2);
  clock += 5000;                       // now the new one has passed
  await flow.poll(handle);
  eq("and allowed once the new interval has passed", github.calls.length, 3);
}

// ------------------------------------------------------------------- finishing

console.log("\nfinishing, once and only once");
{
  const github = fakeGitHub([{ body: CODE }, { body: { access_token: "gho_secret", scope: "repo" } }]);
  const flow = login(github);
  const { handle } = await flow.start();
  clock += 5000;
  const done = await flow.poll(handle);
  eq("the token comes back", done.status, "done");
  eq("with what it can reach", done.scope, "repo");
  eq("and the token itself", done.token, "gho_secret");

  const again = await flow.poll(handle);
  eq("asking again gets nothing: it is handed out once", again.status, "unknown");
  eq("and nothing is left holding it", flow.size, 0);
}
{
  for (const [error, status] of [["expired_token", "expired"], ["access_denied", "denied"]]) {
    const github = fakeGitHub([{ body: CODE }, { body: { error } }]);
    const flow = login(github);
    const { handle } = await flow.start();
    clock += 5000;
    eq(`${error} becomes ${status}`, (await flow.poll(handle)).status, status);
    eq(`and ${error} is not kept`, flow.size, 0);
  }
}
{
  const github = fakeGitHub([{ body: CODE }, { body: { error: "incorrect_client_credentials" } }]);
  const flow = login(github);
  const { handle } = await flow.start();
  clock += 5000;
  const bad = await flow.poll(handle);
  eq("an error nobody planned for is still reported", bad.status, "error");
  eq("by name", bad.error, "incorrect_client_credentials");
}
{
  // The code GitHub issued has a life, and a bridge left running overnight must
  // not keep offering one that died hours ago.
  const github = fakeGitHub([{ body: CODE }, { body: { error: "authorization_pending" } }]);
  const flow = login(github);
  const { handle } = await flow.start();
  clock += 901 * 1000;
  eq("a code past its expiry is expired without asking", (await flow.poll(handle)).status, "expired");
  eq("and it was not asked", github.calls.length, 1);
  eq("nor kept", flow.size, 0);
}
{
  const github = fakeGitHub([{ body: CODE }]);
  const flow = login(github);
  eq("an unknown handle is unknown", (await flow.poll("deadbeef")).status, "unknown");
  const { handle } = await flow.start();
  check("and a handle can be dropped on purpose", flow.forget(handle) && flow.size === 0);
}
{
  // Two flows at once must not see each other's tokens: the handle is the only
  // thing separating one caller on loopback from another.
  const github = fakeGitHub([{ body: CODE }]);
  const flow = login(github);
  const a = await flow.start();
  const b = await flow.start();
  check("two flows get different handles", a.handle !== b.handle);
  eq("and both are held", flow.size, 2);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) { console.log("failures: " + failures.join("; ")); process.exit(1); }
