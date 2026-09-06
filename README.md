# Repo as Root Disk

A browser-native Linux VM whose disk is committed into a git repository. The
guest's dirty block set becomes a commit, so a machine's state has a version
history and can be rebuilt on any device from a reference alone. There is no
server: a static page, the user's repository, and the user's browser.

This is the artifact for a paper of the same name, which is under review. The
manuscript is not distributed here; this repository is the code, the harnesses
and the data behind its measurements.

The engine does not know what a browser is. The contract it needs from a device
is five operations wide, and there are three implementations of it: in memory
for the tests, over v86's buffer for the browser, and over NBD for a real Linux
kernel.

## Quick start

Running a machine, and reaching the site it serves from another tab.

```
python serve.py --open
```

That is the whole of it. It serves the project on two ports, opens
`/app/?serve`, and from there nothing has to be typed: a machine boots, a web
server goes onto its disk, a site is served from it, every layer this side can
see is checked, and the panel prints a link.

1. **Run `python serve.py --open`.** It prints two addresses: `:8000` is the
   app, `:8001` is where machines appear. A browser opens on the first.
2. **Wait about a minute.** The Serve panel reports what it is doing; the log
   below it says more. It ends with `Serving. Open this in another tab:`
   followed by a link.
3. **Click the link** (or open `http://localhost:8001/`). The page should read
   *Served from inside the VM*, styled, and say that its stylesheet and script
   both loaded -- which is the part that proves a whole site is being served
   rather than one document.
4. **If it looks wrong, reload it once.** See the note under "Reaching the
   machine from another tab" for why that happens and when it stops.

To change what is served, click the terminal panel and type into the machine:

```
printf '%s' '<h1>hello</h1>' > /disk/www/hello.html    # then reload the tab
rrd serve /disk/site                                   # serve somewhere else
rrd sync "my page"                                     # keep it: the disk becomes a commit
rrd status                                             # what is running
```

To check what is happening from the app's own console, where `window.machine`
is the running machine:

```js
const c = await import("./check-serve.js");
await c.check(window.machine);
```

Nothing above needs a token or a network. The machine commits to a repository
held in memory, which is enough to see the thing work; attaching a real
repository is the Repository panel, and needs a token.

## Requirements

Node 20 or newer (developed on 22). No build step, no bundler, no framework.
Python 3 for the static server. A TeX installation only if you want to rebuild
the paper. 

## Reproducing the paper

Everything below runs from the repository root. The three that need no
credentials are the ones to start with, and they cover the paper's central
claims.

| Claim in the paper | Command | Needs a token |
|---|---|---|
| Restore cost is the live set plus three requests, constant in history | `node src/analysis/restore-scaling.mjs` | no |
| Write amplification and the chunk-size trade-off | `node src/analysis/report.mjs traces/mke2fs-256mb.json` | no |
| Every invariant the design rests on (799 tests, 14 suites) | see below | no |
| GitHub costs 20x the requests and 13x the time of a batch-commit host | `node src/analysis/batch-commit.mjs github <owner/repo>` then `gitlab` | **yes** |
| Whether a batch-commit host offers a compare-and-swap | `node src/analysis/cas-probe.mjs gitlab <owner/repo>` | **yes** |

`restore-scaling.mjs` runs 120 sequential syncs against an in-process host that
counts every request. The second half of its table is the result: the live set
stops growing while the history and the repository keep growing, and the restore
column stays flat. It emits LaTeX, which is what the paper's table is made of.

`report.mjs` reads a captured write trace and reports what each chunk size would
have cost. `traces/mke2fs-256mb.json` is a real capture of `mke2fs` on a 256 MB
disk, not a synthetic workload.

### Tests

```
for t in test test-engine test-device test-fs test-runner test-terminal \
         test-keyboard test-alpine test-sweep test-bisect test-nbd test-batch \
         test-net test-publish; do
  node src/$t.mjs
done
```

799 assertions. They need no network and no credentials. `test-nbd.mjs` speaks
the client half of the NBD protocol over a real socket, so the wire format and
the server loop are exercised rather than mocked; the one hop that needs Linux
is `nbd-client` binding the export to `/dev/nbd0`. `test-net.mjs` does the same
for the network: the stack is driven by a guest that speaks the server half of
TCP over real frames, and the HTTP parser is fed the bytes of a real Node HTTP
server over a real socket.

## Before you run anything that takes a token

**The two credentialed harnesses write real commits to a real repository and
consume real rate limit.** `batch-commit.mjs` uploads roughly 60 MB of random
data by default and leaves a branch behind, which it names on exit for you to
delete. Point them at a repository you are willing to fill with junk. Shrink a
run with `SIZES=1,2,4 ROUNDS=2 MAX_CHUNKS=16`.

Tokens are read from the environment, never from an argument, because arguments
are visible in the process table to every user on the machine:

```
GITHUB_TOKEN=... node src/analysis/batch-commit.mjs github owner/repo
GITLAB_TOKEN=... node src/analysis/batch-commit.mjs gitlab owner/repo
```

Use a fine-grained token scoped to the one repository, with the shortest expiry
your workflow tolerates. Rotation is the only revocation this design offers.

## The browser machine

```
python serve.py
```

then open `/app/`. Nothing else is needed: the emulator, its wasm, the BIOS and
the ISO are all committed, and a blank disk is built in the tab rather than
downloaded, so no disk image is fetched at all.

`spike-b/` and `spike-c/` are earlier prototypes, kept because the paper refers
to their measurements. Those two still load a blank image from disk, so if you
want to run them, create the zeros they expect:

```
truncate -s 16M  spike-c/images/blank-16mb.img
truncate -s 256M spike-c/images/blank-256mb.img
truncate -s 16M  spike-b/images/blank-16mb.img
```

## Reaching the machine from another tab

The guest gets a network card and nothing is on the other end of it but this
page. v86 emulates an NE2000 and puts both directions on its bus, and every
other project that turns this on points it at a WebSocket relay, which puts a
server back in the picture. `net_device: { type: "ne2k" }` with no `relay_url`
builds the card and connects it to nothing, and `src/net/` is the nothing: ARP,
IPv4, ICMP echo and TCP, in the tab.

So a server inside the VM accepts a connection whose far end is a function call
in the page, and a service worker turns that into a URL any other tab on the
browser can open. There is still no server: the tab is the origin.

The images this project boots ship a busybox built without httpd, without nc and
without any other applet that can accept a connection, so nothing in them can
listen on a port. `vendor/busybox/` is one static megabyte that can, and it goes
in the way every other binary does: over the 9p share, from this page's own
origin.

A machine is served from an origin of its own, so the server listens on two
ports rather than one. Both serve the same files; only the origin differs, which
is the whole reason there is a second one. `serve.py` does both from one process:

```
python serve.py
    http://localhost:8000/    the app
    http://localhost:8001/    machines
```

The whole of it, with nothing to type:

```
python serve.py --open
```

That serves both ports, opens `/app/?serve`, boots a machine, puts a web server
on its disk, serves it, checks every layer it can see from this side, and prints
the link for the other tab. `window.machine` is the session, for carrying on from
the console.

Or by hand, opening `/app/` on 8000 and, in the console:

```js
const s = await import("./demo-serve.js");
const m = await s.main();           // prints the URL to open in a second tab
```

That formats a disk, installs the server on it, writes a site, starts httpd
inside the guest, fetches all three files back through the stack, and syncs --
so the machine serving the site is itself a commit. A measured run:

```
busybox handed to the guest over 9p: 1061344 bytes
installed at /disk/usr/local/bin/busybox
guest addressed with ip: 10.0.2.15 via 10.0.2.2
ping from the guest to this tab: answered
busybox httpd is listening on port 80 inside the guest
direct /          -> 200 text/html 388b
direct /style.css -> 200 text/css 233b
direct /app.js    -> 200 application/javascript 134b
synced: 11 chunks dirty, 11 uploaded, commit c2
open this in a second tab: http://localhost:8001/
```

`demo-net.js` is the same path without the disk, for when only the network is
of interest. In the app itself there is a **Serve** panel that does the same to
the machine the page booted, once its disk is mounted.

### Driving it from inside the machine

Nothing above has to be typed in a browser console twice. The tab answers HTTP on
its own address, and the machine gets a client for it on its disk:

```
rrd status              what is running, and what is unsaved
rrd url                 where the site is being served
rrd serve [directory]   serve a directory  (default /disk/www)
rrd unserve             stop serving
rrd sync [message]      commit the disk, so the machine survives this tab
```

The arrangement is the one a cloud already uses: an instance asks a service on a
fixed local address about itself and about what the platform should do next. Here
the platform is a browser tab. Because `rrd` lives on the machine's disk it is
part of the machine -- restore that machine elsewhere and its commands come back
with it. It is a shell script over `wget`, so `wget -qO- http://10.0.2.2/status`
does the same thing if the shell's PATH has been reset.

**Expect to reload the other tab once.** The retry described below can take the
guest's server down between the moment a machine starts serving and the moment
another tab asks it for something. The hosting tab puts it back -- one repair
however many requests noticed it -- but a page already loading gets a 503 saying
to reload, and the reload works. Measured on a fresh boot: the first load asked
too early, the second returned the document, the third returned the document and
both its assets.

**One thing to know about this guest.** The vendored image retries its 9p mount
for as long as it runs, and each attempt prints two lines onto the same serial
console commands travel over. Landing mid-command, that text cuts the line in
half -- and the retry takes the machine's mount point, its address and its
running server with it. The demo bounds every command, presses Ctrl-C, puts the
disk, the network and the server back, and repeats the line; `serve-machine.js`
says so where it does it. A guest image that does not do this would need none of
that.

The guest is at 10.0.2.15 and the tab is at 10.0.2.2, which are v86's usual
addresses, so an image configured for the usual setup needs no change. A machine
is served at `/app/m/<name>/`, and the worker's scope is the directory it is
served from, so no host configuration is involved.

**A machine is served from an origin of its own, and that is not decoration.**
A page out of a VM is content the machine's owner did not write. Served from the
app's origin it runs where the git token lives and can read it, so it must not be
served from the app's origin.

The obvious patch is a CSP `sandbox` directive, and it half works. Measured in
Chrome: `localStorage` from a sandboxed page raises a SecurityError, so the token
is out of reach. But a sandboxed document has an opaque origin, and **a document
with an opaque origin is not controlled by a service worker**, so every
stylesheet, script and image it asks for bypasses the worker and 404s against the
real server. Under the sandbox a machine can serve one self-contained document
and nothing else. It is still what the worker does when a machine has to share
the app's origin, on the grounds that one page is a smaller loss than a token.

The fix is a real origin. Which shape of origin is not a matter of taste: a
browser partitions storage, service worker registrations included, by the site of
the top-level page. The bridge below registers the machine's worker from inside
an iframe, and that registration is only the one a top-level tab later finds if
the two are the same site. Ports are not part of a site, and subdomains of a real
domain are not either -- but Chrome treats every `*.localhost` name as a site of
its own, which is measurably not good enough:

    iframe on machine-1.localhost:8000 registers a worker
    top-level tab on machine-1.localhost:8000  ->  registrations: []

    iframe on localhost:8001 registers a worker
    top-level tab on localhost:8001  ->  controlled by /app/net-sw.js

So locally a machine takes a port of its own, and deployed it takes a subdomain.
Both are a different origin on the same site. Measured on the port form, with the
app holding a token in its own storage:

    app tab (localhost:8000)      localStorage.machine.token = github_pat_SECRET
    machine tab (localhost:8001)  Object.keys(localStorage) -> []
                                  localStorage.machine.token -> null
                                  fetch("http://localhost:8000/app/") -> blocked

and the site itself, which is the half the sandbox could not do:

    worker served /           -> 200, 388 bytes
    worker served /style.css  -> 200, 233 bytes
    worker served /app.js     -> 200, 134 bytes
    worker served /favicon.ico -> 404, from the guest

`app/machine-origin.html` is the bridge that makes this possible. A service
worker can only be registered by a page on its own origin, and the tab holding
the VM is not on the machine's origin, so a hidden iframe there registers the
worker and relays requests back by postMessage. Nothing of the app crosses that
boundary: out goes a method, a path and headers, back comes a status, headers and
bytes.

## Publishing a site to a static host

Serving a machine reaches other tabs in one browser. Publishing reaches everyone,
and costs no server at all, because what a static host wants is exactly what git
already holds: files, at paths, under a ref.

```
rrd publish "a first version"
```

A machine's disk is chunks -- blocks named by content hash, meaningless without
the manifest that orders them, and unservable by anything. So a published site
goes to a ref of its own, `<branch>-site`, as ordinary blobs under ordinary
paths. Two lanes, one repository, and they never share a ref: a host serving a
branch as a website would otherwise be serving a disk's chunks as one.

A measured run, from inside the machine:

```
published 3 files (755 bytes) from /disk/www
to served-mtpi97c4-site as c4

    app.js       1405b7c7  134 bytes
    index.html   eb88f113  388 bytes
    style.css    6114d747  233 bytes

# then, after adding a page in the guest
published 4 files (770 bytes) ... as c6      one parent: the history is a chain
```

Point a static host at that ref and the site is live with nothing running: the
tab can close, the machine can be thrown away, and the page stays up.

**How the site is read out.** Over the machine's own web server, not over the 9p
share and not by asking its shell. The share knocks the guest's state over; and
the shell cannot be used at all, because `rrd publish` is holding it -- a command
sent there would sit unread in a shell waiting for the very answer that command
is blocking. So the machine lists its own files first, leaves the list where its
web server will hand it over, and only then asks.

**Blob ids are computed before anything is uploaded.** Hosts differ in what they
do with one -- GitHub checks it against what the server returns, the batch-commit
hosts store by it -- and a file handed over without an id is the kind of thing
that works on one host and quietly publishes every file as the same blob on the
next. That is not hypothetical: it is what this lane did until a test double was
made to behave like a real host.

## Deploying to a static host

Everything here is static files and client-side code, so a static host serves it
unchanged. Two details decide whether machines work once it is deployed, and one
of them cannot be worked around.

`net-sw.js` sits at the deployment root rather than in `app/`. A service worker
may only claim a scope at or below its own directory unless the server sends a
`Service-Worker-Allowed` header, and GitHub Pages sends no custom headers at all.
A worker at the root claims the root by default, with nothing to configure. It
reads its scope from its own registration, so deploying the project under a
subpath works too; machines then live under that subpath.

**The part that needs a domain.** A machine must not share the app's origin, and
a Pages site is one origin. Every repository on `username.github.io` is a path
under that same origin, so a second repository does not give a second origin. Nor
does a second account: `github.io` is on the Public Suffix List, which makes
`a.github.io` and `b.github.io` different *sites*, and a browser partitions
service worker registrations by site, so the bridge would register a worker that
a top-level tab never finds.

What works is a custom domain, because subdomains of one registrable domain are
different origins on the same site:

    app.example.com       ->  Pages site A, the whole project
    machines.example.com  ->  Pages site B, the whole project again

Two repositories, two Pages sites, two CNAMEs, the same files in both. The second
site only strictly needs `net-sw.js` and `app/machine-origin.html`, but deploying
the same tree twice is one less thing to keep in step.

Then tell the app where machines live, in `app/index.html`:

```html
<meta name="machine-origin" content="https://machines.example.com">
```

**One origin, not one per machine.** Which machine a worker serves travels in its
registration -- it is registered as `net-sw.js?machine=<name>` -- so a name per
machine would buy nothing and cost a DNS record and a Pages site each. A hosting
tab holds one machine, and that is what its origin serves.

Without a domain -- with the meta tag left empty and nothing at
`machines.<this host>` -- the app falls back to serving machines under
`/m/<name>/` on its own origin behind a CSP `sandbox` directive, which protects the token and costs
the guest its assets: one self-contained document, no stylesheet, no script. The
worker chooses between the two on its own; nothing needs configuring for the
fallback.

Nothing about the host changes what serves a site. Pages hands out the page; the
machine in the tab serves the site.

## Attaching a repository to a real kernel

Linux only, and the last hop needs root:

```
GIT_DISK_TOKEN=... node src/nbd-daemon.mjs --host github --repo owner/name \
    --branch machine-1 --size 512M
```

```
modprobe nbd
nbd-client 127.0.0.1 10809 /dev/nbd0 -N disk
mkfs.ext4 /dev/nbd0        # first time only
mount /dev/nbd0 /mnt/disk
```

Unmount before stopping the daemon, or it commits a filesystem the kernel was
still writing to.

## Layout

```
src/core/       the sync engine: chunker, manifest, governor, machine, bisect
src/device/     the five-operation device contract, and its three implementations
src/host/       GitHub, GitLab and Forgejo adapters behind one interface
src/guest/      driving a guest shell: exit codes, mounts, Alpine, apk
src/net/        the tab's TCP/IP stack: wire format, connections, HTTP
src/core/publish.js  the publish lane: a site as a tree, on a ref of its own
net-sw.js       the worker that serves a machine, at the root so it can claim it
app/control.js  the control plane the guest talks to; src/guest/control.js is its client
src/ui/         terminal renderer and keyboard mapping
src/analysis/   the measurement harnesses behind the paper's tables
traces/         captured write traces
vendor/         redistributed third-party material; see NOTICE
```


## Licence

MIT, see `LICENSE`. Third-party material under `vendor/` keeps its own licences;
see `NOTICE`.
