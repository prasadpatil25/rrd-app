// Does the identity provider actually work, and if not, which layer is at fault?
//
// The same shape as `check-serve.js`, for the same reason: a flow that fails has
// several places to have failed, and they need different fixes. Each check here
// answers exactly one of them, in order, so the first failure names the layer.
//
// Everything runs through the tab's own stack -- `net.request` into busybox
// httpd -- so this needs no bridge and no node process. That is not a shortcut
// around the real path: it is the same TCP stack, the same emulated NIC and the
// same fork per request that `tools/bridge.mjs` would carry a curl over. What
// the bridge adds is a socket for things that are not a browser tab, which is
// not what is being tested here.
//
// It ends by spending a code twice and by offering a bad verifier, because an
// IdP that issues a token is only half working. The half worth checking is the
// half that refuses.
//
//   const c = await import("./check-idp.js");
//   await c.check(window.machine);

import { rc } from "../src/guest/fs.js";
import { ISSUER, pkcePair, verifyWithJwks } from "./idp.js";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const CLIENT = "test-client";
const REDIRECT = "urn:ietf:wg:oauth:2.0:oob";
const USER = "alice";

const form = (fields) =>
  Object.entries(fields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");

/**
 * @param {Object} session what demo-serve.js main() returned
 * @param {Object} [options]
 * @param {string} [options.directory] the served directory, where the CGI lives
 * @param {string} [options.root] where the fixtures live
 * @param {number} [options.port]
 * @returns {Promise<{ok: boolean, rows: Array}>}
 */
export async function check(session, {
  directory = "/disk/www", root = "/disk/idp", port = 80
} = {}) {
  const { run, net } = session;
  const rows = [];
  const record = async (layer, name, fn) => {
    const started = performance.now();
    try {
      const detail = await fn();
      rows.push({ layer, check: name, ok: true, detail, ms: Math.round(performance.now() - started) });
      return detail;
    } catch (err) {
      rows.push({ layer, check: name, ok: false, detail: err.message, ms: Math.round(performance.now() - started) });
      return null;
    }
  };

  const get = (path) => net.request({ port, path });
  const post = (path, fields) => net.request({
    port, method: "POST", path,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: encoder.encode(form(fields))
  });

  // --- the guest: is any of it actually on the disk? -------------------------

  await record("guest", "the fixtures are on the disk", async () => {
    const result = await rc(run, `ls ${root}/clients ${root}/users`);
    if (!result.ok) throw new Error(`${root} is not there. Run idp.install(machine.run) first`);
    if (!result.output.includes(CLIENT)) throw new Error(`no client fixture for ${CLIENT}`);
    if (!result.output.includes(USER)) throw new Error(`no user fixture for ${USER}`);
    return `${CLIENT}, ${USER}`;
  });

  await record("guest", "the endpoints are executable", async () => {
    const result = await rc(run, `test -x ${directory}/cgi-bin/authorize && test -x ${directory}/cgi-bin/token`);
    if (!result.ok) throw new Error(`the CGI is missing or not executable in ${directory}/cgi-bin`);
    return "authorize, token";
  });

  // --- the flow --------------------------------------------------------------

  const { verifier, challenge } = await pkcePair();
  let code = null;

  await record("flow", "authorize issues a code", async () => {
    const query = form({
      response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
      username: USER, scope: "openid profile", state: "check-idp",
      nonce: "n-check", code_challenge: challenge, code_challenge_method: "S256"
    });
    const response = await get(`/cgi-bin/authorize?${query}`);
    const body = decoder.decode(response.body);
    const location = response.headers.location || "";
    const found = (location || body).match(/[?&]code=([A-Za-z0-9_-]+)/);
    if (!found) {
      throw new Error(`no code came back: ${response.status} ${body.slice(0, 120)}`);
    }
    code = found[1];

    // The one thing that could not be checked without booting a guest: whether
    // this busybox turns `Status: 302` from a CGI into a real redirect. The flow
    // works either way, because the location is in the body too, but a real
    // client follows the header and would not find it. So this reports which
    // happened rather than only whether a code arrived.
    const redirected = response.status === 302 && !!location;
    return redirected
      ? `302, Location honoured -- code ${code.slice(0, 8)}...`
      : `code ${code.slice(0, 8)}... but answered ${response.status}, not 302: ` +
        `busybox did not honour Status:, so a client that follows redirects will not see it`;
  });

  await record("guest", "the code is recorded on the disk", async () => {
    if (!code) throw new Error("no code was issued, so there is nothing to look for");
    const result = await rc(run, `cat ${root}/codes/${code}`);
    if (!result.ok) throw new Error("the code file is not there");
    if (!result.output.includes(`sub=${USER}`)) throw new Error("the record does not name the user");
    if (!result.output.includes(`challenge=${challenge}`)) throw new Error("the record does not hold the challenge");
    return "client, redirect, challenge, sub, scope, nonce, expiry";
  });

  let issued = null;
  await record("flow", "token exchanges the code", async () => {
    if (!code) throw new Error("no code was issued, so there is nothing to exchange");
    const response = await post("/cgi-bin/token", {
      grant_type: "authorization_code", code, client_id: CLIENT,
      redirect_uri: REDIRECT, code_verifier: verifier
    });
    const body = decoder.decode(response.body);
    let parsed;
    try { parsed = JSON.parse(body); } catch { throw new Error(`not JSON: ${body.slice(0, 120)}`); }
    if (parsed.error) throw new Error(`${parsed.error}: ${parsed.error_description || ""}`);
    if (!parsed.access_token || !parsed.id_token) throw new Error("no tokens in the answer");
    issued = parsed;
    return `${parsed.token_type}, expires_in ${parsed.expires_in}`;
  });

  // --- the tokens, judged the way a client would -----------------------------
  //
  // Fetched rather than imported: a client verifies against the JWKS the static
  // host serves, and the failure this catches is that file disagreeing with the
  // key that signed. Importing the key from `idp.js` would check the signature
  // against itself and never notice.

  let verified = null;
  await record("tokens", "the id_token verifies against the published JWKS", async () => {
    if (!issued) throw new Error("no token was issued, so there is nothing to verify");
    const url = new URL("../idp-test/jwks.json", import.meta.url);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`the JWKS is not being served: ${response.status} at ${url}`);
    const { keys } = await response.json();
    verified = await verifyWithJwks(issued.id_token, keys);
    return `${verified.header.alg}, kid ${verified.header.kid}`;
  });

  await record("tokens", "the claims say what they should", async () => {
    // Only from the verified token. Reading claims out of a signature that did
    // not check is how a client gets told whatever an attacker likes.
    if (!verified) throw new Error("the token did not verify, so its claims are not worth reading");
    const { claims } = verified;
    if (claims.iss !== ISSUER) throw new Error(`iss is ${claims.iss}, not ${ISSUER}`);
    if (claims.sub !== USER) throw new Error(`sub is ${claims.sub}, not ${USER}`);
    if (claims.aud !== CLIENT) throw new Error(`aud is ${claims.aud}, not ${CLIENT}`);
    if (claims.nonce !== "n-check") throw new Error("the nonce did not survive the round trip");
    // The tab's clock, not the guest's. A machine restored from a commit has no
    // idea what time it is, and a token stamped from that would be rejected.
    const drift = Math.abs(claims.iat * 1000 - Date.now()) / 1000;
    if (drift > 120) throw new Error(`iat is ${Math.round(drift)}s from this tab's clock`);
    return `sub ${claims.sub}, aud ${claims.aud}, iat within ${Math.round(drift)}s`;
  });

  // --- the half worth checking ------------------------------------------------

  await record("refusals", "a spent code cannot be spent again", async () => {
    if (!code) throw new Error("no code was issued, so there is nothing to replay");
    const response = await post("/cgi-bin/token", {
      grant_type: "authorization_code", code, client_id: CLIENT,
      redirect_uri: REDIRECT, code_verifier: verifier
    });
    const parsed = JSON.parse(decoder.decode(response.body));
    if (parsed.access_token) throw new Error("the same code was exchanged twice");
    if (parsed.error !== "invalid_grant") throw new Error(`refused, but as ${parsed.error}`);
    return parsed.error_description;
  });

  await record("refusals", "a wrong code_verifier is refused", async () => {
    const fresh = await pkcePair();
    const query = form({
      response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT, username: USER,
      code_challenge: fresh.challenge, code_challenge_method: "S256"
    });
    const body = decoder.decode((await get(`/cgi-bin/authorize?${query}`)).body);
    const location = body.match(/[?&]code=([A-Za-z0-9_-]+)/);
    if (!location) throw new Error("could not get a second code to test with");

    const response = await post("/cgi-bin/token", {
      grant_type: "authorization_code", code: location[1], client_id: CLIENT,
      redirect_uri: REDIRECT, code_verifier: "not-the-verifier-that-was-hashed"
    });
    const parsed = JSON.parse(decoder.decode(response.body));
    if (parsed.access_token) throw new Error("PKCE did not stop a wrong verifier");
    if (parsed.error !== "invalid_grant") throw new Error(`refused, but as ${parsed.error}`);
    return "PKCE held";
  });

  await record("refusals", "an unregistered redirect_uri is refused", async () => {
    const fresh = await pkcePair();
    const query = form({
      response_type: "code", client_id: CLIENT, redirect_uri: "http://evil.test/cb",
      username: USER, code_challenge: fresh.challenge, code_challenge_method: "S256"
    });
    const response = await get(`/cgi-bin/authorize?${query}`);
    const body = decoder.decode(response.body);
    if (/[?&]code=/.test(body)) throw new Error("a code was issued for an unregistered redirect_uri");
    return body.trim().slice(0, 60);
  });

  const ok = rows.every((row) => row.ok !== false);
  if (typeof console.table === "function") console.table(rows);
  const failed = rows.find((row) => row.ok === false);
  console.log(failed
    ? `first failure: ${failed.layer} -- ${failed.check}: ${failed.detail}`
    : `the whole flow works: ${rows.length} checks, code issued, token signed and verified, replay refused.`);

  return { ok, rows, tokens: issued };
}
