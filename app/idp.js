// An identity provider whose state is a commit.
//
// The walking skeleton for `docs/oauth-test-idp.md`. Three pieces, in three
// places, because they have three different requirements:
//
//   idp-test/jwks.json, .well-known/    static, always up   -> a static host
//   /authorize, /token as CGI           versioned state     -> the guest
//   signing, and the claims             a key, a decision   -> here, the tab
//
// THE SIGNING KEY IN THIS FILE IS PUBLIC. It is committed, it is served in the
// JWKS, and anyone can forge any token this issues. That is the design and not
// an oversight: a test IdP has no secret to protect, and once that is true every
// objection to running an authorization server in a browser tab goes away --
// the disk that cannot forget has nothing to remember, a tunnel in the clear
// carries nothing, and weak entropy costs nothing. What is left is the part
// worth having, which is that the clients, the users and the consent records
// have a version history and can be restored byte for byte from a reference.
//
// The guardrail that makes this safe is that it must be unmistakable. The key
// id says so, the issuer says so, and this paragraph says so. Point it at
// anything real and the tokens it mints are worthless in the exact way that
// matters: anybody can mint them too.
//
// Why the tab signs rather than the guest: busybox has sha256sum but an HMAC
// built out of it in shell is a page of ipad/opad nobody should review, and
// whether the image carries openssl is unverified. The tab has WebCrypto, and
// `src/guest/control.js` already established the channel -- a program in the
// guest cannot call a function in the page, but it can open a socket.

import { serve } from "../src/net/http.js";

/** Where the signer listens, on the tab's own address. */
export const SIGNER_PORT = 8081;

export const KID = "test-key-do-not-trust";
export const ALG = "ES256";

/**
 * The issuer, which is a pair of files in a repository and therefore never
 * moves. The endpoints do move -- they are wherever the bridge is today -- and
 * that is why they are named in the discovery document rather than derived from
 * the issuer. A test suite runs on the same computer as the machine it tests, so
 * `localhost:9000` is a convention rather than an ephemeral tunnel name.
 */
export const ISSUER = "https://prasadpatil25.github.io/rrd-app/idp-test";

/** Published on purpose. See the header. */
export const PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "yx45R2kt_Fg8n2-OETPcF5N-wrqXvhNcHoLdOD2NPrY",
  y: "8GuiCVaCS_-2rRF1FjF0pcmmy78KqA3bNRI7PMZxg4M",
  d: "4Sa-Z2Y6gmUnAOalBeacGrBzMrzn3qwado9xVdmRnM0"
};

/** The same key without `d`, which is what `idp-test/jwks.json` serves. */
export const PUBLIC_JWK = {
  kty: "EC", crv: "P-256", x: PRIVATE_JWK.x, y: PRIVATE_JWK.y,
  kid: KID, alg: ALG, use: "sig"
};

export const JWKS = { keys: [PUBLIC_JWK] };

// --- the fixtures, which are the part with a history -------------------------
//
// These go onto the disk. They are what `rrd sync` commits and what a pinned
// restore brings back, so they are the reason this design exists at all.

/** Registered clients, as the redirect URIs each is allowed. */
export const CLIENTS = {
  "test-client": [
    "http://localhost:8080/callback",
    "http://127.0.0.1:8080/callback",
    "urn:ietf:wg:oauth:2.0:oob"
  ]
};

/** Users. No passwords: this is a fixture, not an authentication system. */
export const USERS = {
  alice: { name: "Alice Example", email: "alice@example.test" },
  bob: { name: "Bob Example", email: "bob@example.test" }
};

// --- signing -----------------------------------------------------------------

const encoder = new TextEncoder();

/** base64url, without padding, which is the only encoding a JWT uses. */
export function base64url(bytes) {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(at, at + 8192));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let imported = null;
async function signingKey() {
  if (!imported) {
    imported = await crypto.subtle.importKey(
      "jwk", { ...PRIVATE_JWK, key_ops: ["sign"], ext: false },
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
  }
  return imported;
}

/**
 * A JWT.
 *
 * WebCrypto's ECDSA signature is already the raw r||s that JWS calls ES256, so
 * there is no DER to unwrap here -- which is the one thing that usually makes
 * this fiddly.
 */
export async function signJwt(claims, { kid = KID } = {}) {
  const header = base64url(encoder.encode(JSON.stringify({ alg: ALG, typ: "JWT", kid })));
  const payload = base64url(encoder.encode(JSON.stringify(claims)));
  const input = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, await signingKey(), encoder.encode(input)
  );
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

/**
 * PKCE, S256 only.
 *
 * Compared with `===` rather than in constant time, deliberately. Everywhere
 * else in this project that would be wrong -- `tools/bridge.mjs` compares its
 * token in constant time and says why -- but there is no secret here to leak
 * the prefix of: the signing key is published, so a forged verifier buys an
 * attacker a token they could have minted themselves. Pretending otherwise
 * would be rigour pointed at nothing.
 */
export async function verifyChallenge(verifier, challenge) {
  if (!verifier || !challenge) return false;
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return base64url(new Uint8Array(digest)) === challenge;
}

/** A fresh PKCE pair. S256, which is the only method this accepts. */
export async function pkcePair() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

function bytesFromBase64url(text) {
  const binary = atob(String(text).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const segment = (text) => new TextDecoder().decode(bytesFromBase64url(text));

/**
 * Verify a token the way a client does: against keys it fetched, not the key in
 * this module.
 *
 * Checking a signature against the key that made it proves nothing about the
 * JWKS a client would actually use, and those disagreeing is the failure this
 * design is most likely to ship -- it would work perfectly on the machine that
 * wrote both.
 */
export async function verifyWithJwks(jwt, keys) {
  const [head, payload, signature] = String(jwt).split(".");
  if (!signature) throw new Error("that is not a JWT");
  const header = JSON.parse(segment(head));
  const jwk = (keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`the JWKS has no key with kid ${header.kid}`);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key,
    bytesFromBase64url(signature), encoder.encode(`${head}.${payload}`)
  );
  if (!valid) throw new Error("the signature does not verify: the JWKS and the signer disagree");
  return { header, claims: JSON.parse(segment(payload)) };
}

/**
 * Where the browser comes back to after signing in.
 *
 * The app's own origin, not the machine's -- which is not a concession to the
 * origin split but the thing a redirect URI is: the client's own address, and
 * the client here is the page holding the tab. Computed rather than written
 * down, so it is right on localhost and on a static host without being told
 * which one it is on.
 */
export function callbackUrl() {
  return new URL("callback.html", import.meta.url).href;
}

/**
 * Build and sign the token response.
 *
 * The tab decides the claims, not the guest. Here that is only tidiness -- the
 * key is public -- but it is the shape the note asks for, because a guest that
 * can get arbitrary bytes signed can mint any token it likes, and moving the
 * key without moving the authority is the mistake worth not learning twice.
 *
 * The clock is the tab's for the same reason `docs/oauth-test-idp.md` lists it
 * as an open question: a machine restored from a commit has no idea what time
 * it is, and a token whose `iat` predates its own issuance is rejected by any
 * client that checks.
 */
export async function issue({
  sub, aud, scope = "", nonce = "", name = "", email = "",
  issuer = ISSUER, lifetimeSeconds = 3600, now = Date.now
} = {}) {
  if (!sub) throw new Error("a subject is required");
  if (!aud) throw new Error("an audience is required");

  const iat = Math.floor(now() / 1000);
  const exp = iat + lifetimeSeconds;
  const jti = base64url(crypto.getRandomValues(new Uint8Array(12)));

  const access_token = await signJwt({ iss: issuer, sub, aud, scope, iat, exp, jti });

  const claims = { iss: issuer, sub, aud, iat, exp };
  if (nonce) claims.nonce = nonce;
  if (name) claims.name = name;
  if (email) { claims.email = email; claims.email_verified = true; }
  const id_token = await signJwt(claims);

  return { access_token, id_token, token_type: "Bearer", expires_in: lifetimeSeconds, scope };
}

// --- the guest-facing half ---------------------------------------------------

/**
 * Answer `/sign` on the tab's address, for the token CGI in the guest.
 *
 * Always 200, even for a refusal, for the reason `app/control.js` gives about
 * the control plane: busybox wget prints the body of a 200 and swallows the body
 * of anything else, so a status code here hides the one thing worth saying. The
 * CGI reads the body and chooses the status the caller actually sees.
 */
export function startSigner({
  net, port = SIGNER_PORT, issuer = ISSUER, now = Date.now, onEvent = () => {}
} = {}) {
  if (!net) throw new Error("a V86Net is required");

  const json = (value) => ({
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(value)
  });

  return serve(net.stack, {
    port,
    handler: async ({ path, query }) => {
      if (path !== "/sign") {
        return json({ error: "invalid_request", error_description: `no such endpoint: ${path}` });
      }
      try {
        const sub = query.get("sub") || "";
        const aud = query.get("aud") || "";
        const challenge = query.get("challenge") || "";
        const verifier = query.get("verifier") || "";

        if (!(await verifyChallenge(verifier, challenge))) {
          onEvent({ type: "refused", sub, aud, reason: "pkce" });
          return json({
            error: "invalid_grant",
            error_description: "the code_verifier does not match the code_challenge"
          });
        }

        const tokens = await issue({
          sub, aud, issuer, now,
          scope: query.get("scope") || "",
          nonce: query.get("nonce") || "",
          name: query.get("name") || "",
          email: query.get("email") || ""
        });
        onEvent({ type: "issued", sub, aud, scope: tokens.scope });
        return json(tokens);
      } catch (err) {
        onEvent({ type: "failed", error: err.message });
        return json({ error: "server_error", error_description: err.message });
      }
    }
  });
}

// --- writing it onto the disk ------------------------------------------------

/** Escape for a single-quoted shell string: end the quoting, emit a quote, resume. */
function quote(text) {
  return String(text).replace(/'/g, "'\\''");
}

/**
 * Write a file into the guest in pieces.
 *
 * The same reason `app/dynamic-site.js` does: the guest talks over the console
 * these commands travel on, and a line it interrupts is a line that never runs.
 */
async function writeFile(rc, run, path, text, timeoutMs) {
  const lines = String(text).replace(/\n$/, "").split("\n");
  for (let at = 0; at < lines.length; at += 3) {
    const chunk = lines.slice(at, at + 3).map((line) => `'${quote(line)}'`).join(" ");
    const wrote = await rc(run, `printf '%s\\n' ${chunk} ${at === 0 ? ">" : ">>"} ${path}`, timeoutMs);
    if (!wrote.ok) throw new Error(`could not write ${path}: ${wrote.output.trim()}`);
  }
}

/**
 * Install the IdP onto a machine's disk.
 *
 * @param {(command: string, options?: Object) => Promise<string>} run
 * @param {Object} options
 * @param {string} [options.root]      where the fixtures and codes live
 * @param {string} [options.directory] what busybox httpd serves
 */
export async function install(run, {
  root = "/disk/idp", directory = "/disk/idp/www", timeoutMs = 40000, fs = null
} = {}) {
  const rc = fs ? fs.rc : (await import("../src/guest/fs.js")).rc;

  await rc(run, `mkdir -p ${root}/clients ${root}/users ${root}/codes ${directory}/cgi-bin`, timeoutMs);

  // The app page is a client too, and its address is only knowable at runtime.
  // Everything else in the fixture is written down; this one is computed, which
  // is why it is added here rather than in CLIENTS.
  const callback = callbackUrl();
  for (const [id, redirects] of Object.entries(CLIENTS)) {
    const all = redirects.includes(callback) ? redirects : [...redirects, callback];
    await writeFile(rc, run, `${root}/clients/${id}`, all.join("\n"), timeoutMs);
  }
  for (const [name, profile] of Object.entries(USERS)) {
    await writeFile(rc, run, `${root}/users/${name}`,
                    `name=${profile.name}\nemail=${profile.email}`, timeoutMs);
  }

  // Only when the directory has no page of its own. Installing into a directory
  // that is already serving somebody's site must not replace their index with a
  // landing page for this one -- the same rule the Serve button follows.
  const present = await rc(run, `test -f ${directory}/index.html`, timeoutMs);
  if (!present.ok) await writeFile(rc, run, `${directory}/index.html`, INDEX, timeoutMs);

  for (const [name, script] of [["authorize", AUTHORIZE], ["token", TOKEN]]) {
    const path = `${directory}/cgi-bin/${name}`;
    await writeFile(rc, run, path, script.replace(/__ROOT__/g, root), timeoutMs);
    const marked = await rc(run, `chmod +x ${path}`, timeoutMs);
    if (!marked.ok) throw new Error(`could not make ${path} executable`);
  }

  return {
    root, directory,
    authorize: `${directory}/cgi-bin/authorize`,
    token: `${directory}/cgi-bin/token`
  };
}

export const INDEX =
  "<!doctype html><meta charset=utf-8><title>A test identity provider</title>" +
  "<style>body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:64ch;" +
  "margin:6vh auto;padding:0 20px;background:#EFF2F1;color:#131C1A}h1{font-size:20px}" +
  "code{background:#E1E7E5;padding:1px 4px;border-radius:3px}" +
  "@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}" +
  "code{background:#1E2A27}}</style>" +
  "<h1>A test identity provider</h1>" +
  "<p>Running inside a virtual machine in a browser tab. Its clients and users " +
  "are files on that machine&rsquo;s disk, so they have a version history and can " +
  "be restored byte for byte from a commit.</p>" +
  "<p><strong>The signing key is public.</strong> It is committed to the " +
  "repository and served in the JWKS. Anyone can forge any token this issues. " +
  "Point it at nothing that matters.</p>" +
  "<p>Endpoints: <code>cgi-bin/authorize</code>, <code>cgi-bin/token</code>.</p>";

// --- the CGI ----------------------------------------------------------------
//
// Written against busybox and nothing else: no curl, no jq, no bash. Everything
// that came from a query string is either escaped on the way into HTML or
// filtered to a safe character set before it becomes part of a filename, which
// is the whole of the input handling and is meant to be read.

export const AUTHORIZE = `#!/bin/sh
# The authorization endpoint. Issues a code; the token endpoint spends it.
BB=/disk/usr/local/bin/busybox
IDP=__ROOT__

field() { echo "$QUERY_STRING" | tr '&' '\\n' | grep "^$1=" | head -n 1 | cut -d= -f2-; }
decode() { $BB httpd -d "$(printf '%s' "$1" | tr '+' ' ')"; }
esc() { $BB httpd -e "$*"; }
enc() { printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/&/%26/g' -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/+/%2B/g'; }
# Anything that becomes part of a path is reduced to characters that cannot
# leave the directory it is looked up in.
safe() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._-'; }

fail() {
  echo "Status: 400 Bad Request"
  echo "Content-Type: text/plain; charset=utf-8"
  echo
  echo "$1"
  exit 0
}

rtype=$(decode "$(field response_type)")
client_id=$(safe "$(decode "$(field client_id)")")
redirect_uri=$(decode "$(field redirect_uri)")
state=$(decode "$(field state)")
scope=$(decode "$(field scope)")
nonce=$(decode "$(field nonce)")
challenge=$(decode "$(field code_challenge)")
method=$(decode "$(field code_challenge_method)")
username=$(safe "$(decode "$(field username)")")

[ -n "$client_id" ] || fail "client_id is required"
[ -f "$IDP/clients/$client_id" ] || fail "no such client: $client_id"
[ "$rtype" = "code" ] || fail "response_type must be code"
# The registered redirect URIs, one per line, matched whole.
grep -qxF "$redirect_uri" "$IDP/clients/$client_id" || fail "redirect_uri is not registered for $client_id"
[ -n "$challenge" ] || fail "code_challenge is required: this IdP is PKCE-only"
[ "$method" = "S256" ] || fail "code_challenge_method must be S256"

# No username yet, so ask. A GET form on purpose: a form submission is a
# top-level navigation, which is the one thing that still works when a machine
# has to share the app's origin behind a sandbox.
if [ -z "$username" ]; then
  echo "Content-Type: text/html; charset=utf-8"
  echo "Cache-Control: no-store"
  echo
  echo "<!doctype html><meta charset=utf-8><title>Sign in (test IdP)</title>"
  echo "<style>body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;"
  echo "max-width:60ch;margin:6vh auto;padding:0 20px;background:#EFF2F1;color:#131C1A}"
  echo "select,button{font:inherit;padding:8px 10px}"
  echo "@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}}</style>"
  echo "<h1>Sign in</h1>"
  echo "<p>A test identity provider. There is no password, because there is"
  echo "nothing to protect: the signing key is public.</p>"
  echo "<form method=get action=authorize>"
  for k in response_type client_id redirect_uri scope state nonce code_challenge code_challenge_method; do
    v=$(decode "$(field "$k")")
    echo "<input type=hidden name=$k value=\\"$(esc "$v")\\">"
  done
  echo "<select name=username>"
  for u in $(ls "$IDP/users"); do echo "<option>$(esc "$u")</option>"; done
  echo "</select> <button>Continue</button></form>"
  exit 0
fi

[ -f "$IDP/users/$username" ] || fail "no such user: $username"

# /dev/urandom in an emulator is not a strong source, and here that is fine:
# every token this IdP signs is forgeable anyway. It only has to not repeat.
code=$(head -c 18 /dev/urandom | $BB base64 | tr '+/' '-_' | tr -d '=\\n')
[ -n "$code" ] || fail "could not generate a code"

{
  echo "client_id=$client_id"
  echo "redirect_uri=$redirect_uri"
  echo "challenge=$challenge"
  echo "sub=$username"
  echo "scope=$scope"
  echo "nonce=$nonce"
  echo "expires=$(( $(date +%s) + 60 ))"
} > "$IDP/codes/$code"

sep='?'
case "$redirect_uri" in *\\?*) sep='&' ;; esac
location="$redirect_uri$sep""code=$code"
[ -n "$state" ] && location="$location&state=$(enc "$state")"

# The location goes in the body as well as the header. If busybox does not turn
# Status: into a real 302 on this build, a caller can still see where it was
# meant to go, which is the difference between a puzzle and a bug report.
echo "Status: 302 Found"
echo "Location: $location"
echo "Content-Type: text/plain; charset=utf-8"
echo "Cache-Control: no-store"
echo
echo "$location"
`;

export const TOKEN = `#!/bin/sh
# The token endpoint. Spends a code, asks the tab to sign, passes the answer on.
BB=/disk/usr/local/bin/busybox
IDP=__ROOT__
TAB=\${RRD_HOST:-10.0.2.2}:${SIGNER_PORT}

# A token request is a POST form; accept a query string too, because that is
# what a person testing by hand will reach for first.
params="$QUERY_STRING"
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
  params=$($BB head -c "$CONTENT_LENGTH")
fi

field() { echo "$params" | tr '&' '\\n' | grep "^$1=" | head -n 1 | cut -d= -f2-; }
decode() { $BB httpd -d "$(printf '%s' "$1" | tr '+' ' ')"; }
enc() { printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/&/%26/g' -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/+/%2B/g'; }
safe() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._-'; }

oops() {
  echo "Status: 400 Bad Request"
  echo "Content-Type: application/json"
  echo "Cache-Control: no-store"
  echo
  printf '{"error":"%s","error_description":"%s"}\\n' "$1" "$2"
  exit 0
}

grant=$(decode "$(field grant_type)")
code=$(safe "$(decode "$(field code)")")
verifier=$(decode "$(field code_verifier)")
client_id=$(safe "$(decode "$(field client_id)")")
redirect_uri=$(decode "$(field redirect_uri)")

[ "$grant" = "authorization_code" ] || oops unsupported_grant_type "only authorization_code is supported"
[ -n "$code" ] || oops invalid_request "code is required"
[ -n "$verifier" ] || oops invalid_request "code_verifier is required"

record="$IDP/codes/$code"
[ -f "$record" ] || oops invalid_grant "no such code, or it has already been used"

# Read it and remove it before anything else can fail. A code is one-time use,
# and the failure that matters is the one where a retry after an error gets a
# second token out of the same code.
saved=$(cat "$record")
rm -f "$record"
get() { echo "$saved" | grep "^$1=" | head -n 1 | cut -d= -f2-; }

[ "$(get client_id)" = "$client_id" ] || oops invalid_grant "this code was issued to another client"
[ "$(get redirect_uri)" = "$redirect_uri" ] || oops invalid_grant "redirect_uri does not match the one the code was issued for"
now=$(date +%s)
[ "$now" -le "$(get expires)" ] || oops invalid_grant "the code has expired"

sub=$(get sub)
name=""
email=""
if [ -f "$IDP/users/$sub" ]; then
  name=$(grep '^name=' "$IDP/users/$sub" | head -n 1 | cut -d= -f2-)
  email=$(grep '^email=' "$IDP/users/$sub" | head -n 1 | cut -d= -f2-)
fi

# The tab verifies PKCE, decides the claims and stamps the clock. This sends it
# a decision -- who consented, to what -- rather than bytes to sign.
q="sub=$(enc "$sub")&aud=$(enc "$client_id")&scope=$(enc "$(get scope)")"
q="$q&nonce=$(enc "$(get nonce)")&challenge=$(enc "$(get challenge)")&verifier=$(enc "$verifier")"
q="$q&name=$(enc "$name")&email=$(enc "$email")"

answer=$(wget -T 30 -qO- "http://$TAB/sign?$q") || oops server_error "the tab did not answer: is the signer running?"

# The tab always answers 200 so busybox wget will show us the body; the status
# the caller sees is decided here, from what the body says.
case "$answer" in
  *'"error"'*) echo "Status: 400 Bad Request" ;;
  *) echo "Status: 200 OK" ;;
esac
echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo
printf '%s\\n' "$answer"
`;
