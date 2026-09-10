# An identity provider whose state is a commit

A design note, not an implementation. It sketches the one OAuth-shaped thing
this project is actually good at, and says plainly why the obvious version of
the idea -- "the browser VM is my authorization server" -- is not it.

## The obvious version does not work

An authorization server is defined by a long-lived secret: the key its tokens
are signed with. Put that key on the guest disk and `rrd sync` commits it, and
`src/core/crypto.js:8` already says what happens next:

> A version-controlled disk cannot forget, so a secret written once and deleted
> in the guest survives in that commit's chunk until compaction and the host's
> garbage collector agree to remove it.

Deleting the key later does not help. That is the sentence. It also cuts against
the discipline the project already keeps -- `SECURITY.md:61`, *"The token is
never written to disk"* -- so an AS running in the guest is on the wrong side of
the origin split by construction, not by oversight.

Four more, each independently disqualifying for a real deployment:

| | |
|---|---|
| **Availability** | Refreshes and JWKS fetches arrive when clients decide. Close the tab and auth is down for everyone. |
| **Issuer stability** | `iss` is baked into every token minted and every client's config. A `trycloudflare` name that dies with the process cannot be an issuer. |
| **Confidentiality** | The tunnel operator sees every request in clear. For an AS those are codes, refresh tokens, client secrets, and whatever the user typed. |
| **Entropy** | Codes and keys from `/dev/urandom` inside a deterministic emulator, on a disk that is a published artifact. |

## The version that does work, and why

Point the same machinery at a **test** identity provider and every objection
above dissolves at once, because of a single property:

> A test IdP has no secret to protect. Its tokens guard nothing.

That is the load-bearing decision in this note. The signing key is *published on
purpose* -- committed to the disk, and served in the JWKS -- so committing it is
not a leak, it is the fixture. The tunnel seeing plaintext costs nothing. Weak
entropy costs nothing, and deterministic codes are arguably the point. The tab
is open because a test opened it, so availability is not a question. What is
left is the part this project is uniquely good at:

> the IdP's state -- its clients, its users, its consent records, its login page,
> its deliberately broken fixtures -- has a version history, and can be rebuilt
> byte for byte from a reference alone.

`mock-oauth2-server` gives you a fresh instance. Keycloak in Docker gives you a
hand-maintained realm export that drifts from the tests that need it. Neither
gives you *"the IdP, exactly as it was at `cb9ac37`."* This does, and the code
for it is already written.

### The guardrail this needs

A published signing key means anyone can forge any token this IdP issues. That
is fine, and it must stay obviously fine:

- `kid` is `test-key-do-not-trust`, not `key-1`.
- `iss` carries the word `test` in the path.
- The `README` sentence next to it says the key is public.

A fixture that can be mistaken for a real IdP is the only way this design hurts
anyone. Make it unmistakable.

## The split

Three pieces, three different requirements, three different homes. Only the
middle one is the VM.

| Piece | Requirement | Where |
|---|---|---|
| `jwks.json`, `openid-configuration` | public, always up, no secret | **GitHub Pages** -- static files, a correct fit |
| `/authorize`, consent, `/token` | a running machine, versioned state | **the guest**, as CGI |
| signing | a key, and a decision about claims | **the tab** (see below) |

The awkward part is that discovery lives on Pages and must name a token endpoint
that only exists while a tab is open. The resolution is that `iss` and
`jwks_uri` do not have to be the same host as the endpoints:

```json
{
  "issuer":                 "https://prasadpatil25.github.io/rrd-app/idp-test",
  "jwks_uri":               "https://prasadpatil25.github.io/rrd-app/idp-test/jwks.json",
  "authorization_endpoint": "http://localhost:9000/authorize",
  "token_endpoint":         "http://localhost:9000/token"
}
```

`iss` and `jwks_uri` are permanently stable, because they are files in a repo.
The endpoints point at the bridge, and `localhost:9000` is a fixed convention
for a local test run rather than an ephemeral tunnel name -- which is right,
because a test suite runs on the same computer as the machine it is testing
against. A tunnel is not needed at all in this design, and not wanting one is
the whole difference between this and the version that does not work.

## Where the signing happens

Not in busybox. `sha256sum` is there -- `app/dynamic-site.js` uses it -- but an
HMAC built out of it in shell is a page of `ipad`/`opad` nobody should review,
and whether the image has `openssl` is unverified (`grep -rn openssl src/ app/`
finds nothing, which is not the same as checking a booted guest).

Use the channel `src/guest/control.js` already established:

> A program in the guest cannot call a function in the page, but it can open a
> socket, and the tab is on the other end of the only network the guest has.

So the CGI asks the tab, exactly as `rrd` does:

```sh
jwt=$(wget -qO- "http://10.0.2.2/sign?sub=$sub&aud=$aud&scope=$scope")
```

and the tab signs with WebCrypto. This costs no new mechanism, and it keeps the
key off the disk for free -- which matters only for the variant below, but it
is the same code either way.

**The rule if the key ever stops being public.** The tab must build the claims,
not sign whatever bytes the guest hands it. A guest that can get arbitrary bytes
signed can mint any token it likes, and the key has moved without the authority
moving with it. The guest sends a decision -- *this user consented to this client
for these scopes* -- and the tab decides what that means in a JWT.

## Pinning a state

This is the part that already exists. `restore` in `src/core/machine.js:467`
takes a commit, and `manifestDigest` turns "byte-identical" from a claim into a
check:

```js
const idp = await restore({
  host, branch: "idp-test",
  commit: "cb9ac37",
  manifestDigest: "<pinned>"          // refuses a different or substituted state
});
```

The error it raises when the digest does not match (`machine.js:492`) is the
whole value proposition of this design, stated by the code rather than by a
README: *this is either a different state than the one pinned or a substituted
one; nothing has been written to the disk.*

And the question no other test IdP can answer -- *which change to the fixture
broke the login flow?* -- is `src/core/bisect.js`:

```js
await bisect({
  host, branch: "idp-test",
  test: async (disk) => (await runAuthCodeFlow(disk)).ok
});
```

## What a test run looks like

1. `node tools/bridge.mjs` -- the door for everything that is not a tab.
2. A tab boots the IdP machine at a pinned commit and connects the bridge client.
3. The suite fetches discovery and JWKS from Pages. Static, fast, always there.
4. The suite drives `/authorize` and `/token` on `localhost:9000` with curl,
   Postman, or whatever it already uses.
5. Tokens verify against the published JWKS.

Budget it honestly: roughly 0.2 s per guest request locally through the bridge,
so a full authorization-code flow is somewhere under a second. That is an
integration test, not a unit test. Nothing here belongs in a loop that runs on
every keystroke.

## What is built

The skeleton exists. `README.md` has the commands; this is what is where.

| | |
|---|---|
| `app/idp.js` | the key, `signJwt`, PKCE, the claims, the signer the guest calls, and `install` |
| `idp-test/jwks.json` | the public half, for a static host |
| `idp-test/.well-known/openid-configuration` | discovery |
| `app/check-idp.js` | the end-to-end check the UI button runs, a row per layer |
| `src/test-idp.mjs` | 64 assertions, no VM needed |

Four of them drive `check-idp.js` against a stand-in machine that is bent one
way at a time -- a JWKS that disagrees with the signer, an IdP that hands out a
second token for a spent code -- because a checker that only ever agrees with a
working system is not evidence. The replay case is the one that matters: every
other row stays green while it fails.

Two of the tests are there for a failure this design is unusually likely to
ship: the JWKS and the discovery document are static files that nothing at
runtime would ever notice disagreeing with the key that actually signs, and the
disagreement would work perfectly on the machine that wrote both. So the suite
reads those two files off disk and checks them against the module.

PKCE is checked against the worked example in RFC 7636 appendix B rather than
against this code's own output, which is the difference between testing an
implementation and testing a specification.

## Two origins, which were already there

The machine is served from an origin of its own so that a site running in a
guest cannot read the git token in the app's page. That split, adopted for a
security reason with nothing to do with OAuth, turns out to be exactly the
separation the protocol assumes:

    :8001   the machine     the identity provider
    :8000   the app page    the relying party

So the sign-in page opens on the machine's origin and the `redirect_uri` points
at the app's, and neither of those is a workaround: a redirect URI *is* the
client's own address. `app/callback.html` is that address. It is a separate file
rather than a route because a redirect URI has to be an exact registered string
and a static host has no routes, and the URL is computed from `import.meta.url`
at install time so the fixture is right on localhost and on a static host
without being told which it is on.

**The part that is not obvious.** The token exchange afterwards cannot be an
ordinary cross-origin `fetch` from the app page to the machine. A service worker
only receives `fetch` events for requests made by the clients *it controls*, and
a page on the app's origin is not one of them -- the request would sail past the
worker and reach the static server behind it, which knows nothing about any
machine. A browser tab can *navigate* to a machine; it cannot *fetch* one. So
the sign-in half travels as a navigation, which the worker does answer, and the
exchange goes over the stack the tab already holds.

That also settles a question worth not getting wrong twice: adding CORS headers
to the token endpoint would not have helped, because nothing would have been
there to send them.

## Open questions

Not gaps to be embarrassed about -- things that must be decided, and are cheaper
to decide now. Three from the first draft of this note are answered -- two by the
code, one by running it -- and have been struck.

- **The lease.** A CI job restoring a pinned state is a reader, not an owner.
  `src/core/lease.js` assumes one writer at a time; a replay that takes the
  lease and dies takes the machine with it. Probably: restore without taking a
  lease at all, and refuse to sync.
- **Concurrency.** One core, `fork` per request. Four bridge loops
  (`app/bridge-client.js`) will happily hand the guest four simultaneous token
  exchanges. The code directory is the shared state, and `authorize` writing a
  code file while `token` removes another is untested under that.
- **Passwords.** There are none: `/authorize` lists the fixture users and takes
  one. That is right for a fixture and wrong for testing a failed login, which
  is a path some suites will want. A `password=` line in the user file and one
  comparison would do it.

### Answered by running it

- ~~**`Status:` from CGI.**~~ **busybox honours it.** Measured on a booted guest
  through the bridge: `curl -i` on the authorize endpoint returns
  `HTTP/1.1 302 Found` with a real `Location` header, not a 200. The location is
  still printed in the body as well, which costs nothing and keeps the failure
  legible if another build disagrees. `check-idp.js` reports which of the two it
  saw rather than only whether a code arrived, so a build that stops honouring it
  says so instead of going quiet.

What it costs, measured end to end through the bridge on this machine:

    authorize, a code issued          458 ms
    token, a code exchanged and signed  616 ms
    token, a replay refused           260 ms

which is the fork-per-request cost the README already quotes for CGI under
emulation, plus a signature. A login is under a second and a half. An
integration test, not a unit test.

### Answered by building it

- ~~**`openssl` in the guest.**~~ Moot. The tab signs, over the channel
  `src/guest/control.js` already established, so no crypto is needed in busybox
  beyond what is already there. Whether the image carries openssl no longer
  matters.
- ~~**The guest clock.**~~ Fixed. `issue()` in `app/idp.js` stamps `iat` and
  `exp` from the tab's clock, and the test injects a fixed instant to prove it
  is not reading the guest's. A machine restored from a commit has no idea what
  time it is, and now does not need one.
