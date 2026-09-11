Security
========

What this is, in one line: a browser page that runs a Linux machine, holds a
token that can write to a git repository, and serves pages the machine produced
to other tabs. Every risk below falls out of that sentence.

This is a research artifact, not a hosted service. It has no users but the person
running it, no multi-tenancy, and no server to compromise. That narrows the
problem considerably, and it is why several things below are accepted rather than
fixed.


What is worth protecting
------------------------

**The token.** It can write to a git repository. Everything else here is
recoverable; a leaked token is not.

**The repository.** Its history is the machine. An attacker who can commit can
replace a machine with one of their choosing, and anyone who restores from that
ref boots it.

**The rest of the browser.** The token lives in a page. Whatever else that
browser profile holds -- other origins, other sessions -- is not this project's
to put at risk.


Who could go after them
-----------------------

**A site running in a machine.** The strongest adversary here, because it is
code the machine's owner did not write, executing in a browser that holds a
token. It is the reason for the origin split.

**A program inside a machine.** It can reach the control plane on the tab's
address and ask the tab to sync or publish. Accepted; see below.

**Another origin in the same browser.** Cannot read this one's storage, which is
the browser's guarantee rather than ours, and is what the origin split leans on.

**Somebody with a published URL.** Gets whatever the machine serves and nothing
else. There is no server behind it to attack.


Boundaries that exist, and what was measured
--------------------------------------------

**A machine's pages are served from an origin that is not the app's.** Measured:
with a token in the app's storage, a page on the machine origin reads
`Object.keys(localStorage)` as `[]`, reads the token as `null`, and a fetch back
to the app's origin is blocked.

**Where a second origin cannot be had, guest content is sandboxed instead.** The
CSP `sandbox` directive puts it in an opaque origin: `localStorage` raises a
SecurityError. It costs the page its own assets, because an opaque-origin
document is not controlled by a service worker, so a machine there serves one
self-contained document. The worker chooses, says which it chose, and the
fallback is not silent.

**The token is never written to disk.** Only the repository name and the host
kind are remembered between visits. The token lives in memory for as long as the
tab does.

**The control plane is reachable only from the guest.** It listens on the tab's
address on an emulated link with two hosts on it. Nothing outside the browser can
route to it.

**A machine has no way out unless one is opened.** The guest's only route is to
the tab. It cannot resolve a name, reach a mirror, or call an API, which means
nothing running in a machine can send anything anywhere. That is a property of
the design rather than a policy, and it holds until somebody starts a gateway.

**One writer at a time.** A lease on `<branch>-lease`, arbitrated by
fast-forward-only reference updates where the host has them. Advisory where it
does not, and it says which.


Found in this pass, and fixed
-----------------------------

**Reflected cross-site scripting in the example CGI.** `dynamic-site.js` echoed
the query string into HTML unescaped. It ran on the machine's own origin rather
than the app's, which is a smaller blast radius and not a defence -- and that
file is the one somebody copies when they write their own. Everything derived
from a request is now encoded on the way out, by busybox rather than by a hand
-written sed. Verified: `<script>alert(1)</script>` comes back as
`&#60;script&#62;alert&#40;1&#41;&#60;&#47;script&#62;`.

**The bridge would relay to anyone.** `machine-origin.html` fell back to
`postMessage(..., "*")` when given no parent origin, and accepted messages from
any origin in that case. An embedder could have received a machine's responses.
It now refuses to relay at all without an explicit parent origin.

**The binary a machine executes was never checked.** The page fetches a busybox
over the network and hands it to a machine to run. Its checksum was committed and
recorded in NOTICE, and nothing compared them. It is verified before the transfer
now, and a mismatch refuses rather than warns.


The gateway, which trades that away on purpose
----------------------------------------------

`src/net/gateway.js` is a door in the wall above: the guest speaks plain HTTP to
a proxy on the tab's address, and the tab satisfies each request with `fetch()`.
It exists because a machine with no way out cannot install anything, call
anything, or fetch its own source.

**It is off unless asked for, and it refuses to start with an empty allowlist**
-- a gateway that admits nothing is what not starting one already does, so an
empty list is a mistake rather than a configuration. `serveMachine` takes
`allowOutbound: ["api.github.com"]` and nothing else opens it.

What it deliberately cannot do. It will not answer `CONNECT`: tunnelling TLS
would mean terminating the guest's TLS in the tab and reading everything inside,
which is a man in the middle however well meant. And it can only reach hosts that
permit cross-origin reads, because the tab's `fetch` obeys the browser. Measured
from a page on localhost: `api.github.com`, `raw.githubusercontent.com`,
`registry.npmjs.org` and `httpbin.org` answer; `dl-cdn.alpinelinux.org` and
`example.com` do not. A package mirror is out of reach either way, which is why
this project vendors what a guest needs.

Every request through it is announced to the page that opened it, with the host,
the path, the status and the byte count. **Turning it on means a machine can
exfiltrate to the hosts you named.** That is the trade, stated rather than
buried: a machine that can fetch is a machine that can send.

The bridge, which is a development tool
---------------------------------------

`tools/bridge.mjs` lets curl and anything else outside the browser call a
machine, by listening on a port while the tab connects out to it. By default it
binds `127.0.0.1` and `::1` and nothing else, so it is reachable from that
computer and not from a network.

While it runs, **anything that can reach it can reach whatever the guest is
serving** -- on loopback that means another user account, another program, a
browser extension with local access. That is the same trust anyone extends to a
development server, and it is why this lives in `tools/` rather than in `app/`,
is started by hand, and stops when you stop it.

`--host 0.0.0.0` moves that boundary, so the boundary is replaced rather than
removed: **off loopback the bridge will not start without a token**, and given
none it generates one and prints it rather than coming up open. Every request
carries it, as `Authorization: Bearer` or `?token=`; the `/_bridge/*` endpoints
need it too, or a stranger could poll for pending requests and answer them
before the tab did. It is compared with `timingSafeEqual`, since `===` on a
secret leaks its prefix to anyone patient enough to measure.

What the token is not is a permission system. It is one secret for the whole
machine: whoever holds it can request anything the guest serves and run any CGI
in it, and it travels in the URL when it is on the query string, so it lands in
proxy logs and browser history. It is the difference between exposed and
exposed-to-anyone, not between exposed and safe.

**Signing in to GitHub through it.** Started with `--github-client-id`, the
bridge will run GitHub's device flow, which a browser cannot: GitHub's token
endpoints send no CORS headers, and a guest inherits that wall because its only
route out is the tab's own `fetch`. A device flow carries **no client secret**,
so nothing new is stored and nothing new can leak from the bridge at rest. What
does change is that a process which can reach loopback can now ask for a
sign-in. It cannot complete one: only the person at github.com can authorise a
code. What it could do is race for the result, so the handle is sixteen random
bytes and the token is handed out exactly once and forgotten in the same breath
-- a second poll on the same handle gets nothing. The token never reaches the
bridge's log, which prints the status and not the answer. It is held in the
page, in memory, exactly where a pasted one is held, and the flag is off unless
given. `python serve.py --bridge` starts one for you and stops it again, and is
a flag rather than the default so that "started by hand" stays true.

None of this reaches a deployed page, and that was measured rather than assumed:
a page on the real static host cannot open a connection to loopback at all, so a
bridge on a reader's machine is not something a published page can quietly talk
to. Answering the private-network preflight, which the bridge does, does not
change it. That is the browser's boundary rather than this project's, and it is
one worth having.

The public case adds a third party. A tunnel (`cloudflared tunnel --url
http://localhost:9000`) gives a public HTTPS URL without opening a port on the
router, and in exchange **the tunnel operator terminates the TLS and sees every
request and response in clear**. The address is unauthenticated and guessable in
the sense that anything that learns it -- a referrer header, a paste, a crawler
following a link -- can reach the bridge, which is the whole reason the token is
mandatory there. A quick tunnel's URL is new each time it starts and dies with
the process; nothing outlives the tab that answers it.

Accepted, deliberately
----------------------

**Any process in the guest can sync and publish.** The control plane has no
notion of which program is asking, and giving it one would mean inventing an
authentication scheme between a shell and the page hosting it. On a single-user
machine that is the right trade: a program that can run in your VM can already
write to your disk, and the disk is what gets committed. What limits the damage
is the token, which is why the site lane can take a repository -- and should take
a token -- of its own.

**The token is typed into a page that may be served publicly.** Deployed on a
static host, the page holding the token came from the internet. That is the same
trust anyone places in a web application, and the mitigations are the ordinary
ones: a fine-grained token, one repository, the shortest expiry the workflow
tolerates. Rotation is the only revocation this design offers, which the README
has always said.

**Machines in one browser profile are not isolated from each other.** They share
an origin per host arrangement, and a service worker that will serve whichever
machine a tab is hosting. Two machines belonging to the same person is the
assumed case.

**The guest executes third-party binaries.** A kernel and a busybox, both
recorded in NOTICE with their licences and their provenance. They are not
audited; they are pinned and checksummed.


Out of scope
------------

Denial of service against a machine by the person running it. Side channels
between the guest and the host page. The security of the git host itself.
Anything about `serve.py`, which binds to the loopback address and exists to
serve files on one developer's machine.


Reporting
---------

This is a research artifact with one user. If that changes, this section needs a
real address in it.
