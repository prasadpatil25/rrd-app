// Reference app: a machine whose disk lives in a git repository.
//
// This is assembly. Every decision it encodes was measured elsewhere and lives
// in /src; the app's job is to wire them to a real emulator and show what a sync
// costs. Vendored assets currently sit under /spike-c and should move to a
// shared vendor directory once the spikes are retired.

import { createHost } from "../src/host/index.js";
import { Machine, restore, ConflictError } from "../src/core/machine.js";
import { Lease, holderName } from "../src/core/lease.js";
import { V86Device, serialFlush } from "../src/device/v86.js";
import { Governor } from "../src/core/governor.js";
import { deriveCipher, randomSaltHex } from "../src/core/crypto.js";
import * as manifestModule from "../src/core/manifest.js";
import { Terminal } from "../src/ui/terminal.js";
import * as fsModule from "../src/guest/fs.js";
import * as alpineModule from "../src/guest/alpine.js";
import { makeRunner } from "../src/guest/runner.js";
import { serveMachine, stageFiles } from "./serve-machine.js";
import { bootOptions } from "./guest-image.js";
import * as dynamicSite from "./dynamic-site.js";
import { keyToBytes, textToBytes, pasteNeedsConfirming } from "../src/ui/keyboard.js";

const V86_ROOT = "../spike-c";

// One branch is one disk. These are subdirectories of it, surfaced where a guest
// expects them: same filesystem, same superblock, so a write through one path is
// visible through the others immediately. This image ships no /home and its
// shell's home is /root, so both are bound.
const BINDS = [
  { source: "home", target: "/home" },
  { source: "root", target: "/root" }
];
// Served from this page's own origin, like every other asset. Nothing here
// reaches a package mirror or a network relay.
const ALPINE_ROOTFS = "../vendor/alpine/alpine-minirootfs-3.20.10-x86.tar.gz";
const ALPINE_NAME = "alpine-minirootfs-3.20.10-x86.tar.gz";

const DISKS = {
  16: `${V86_ROOT}/images/blank-16mb.img`,
  256: `${V86_ROOT}/images/blank-256mb.img`
};

/**
 * How the disk reaches the emulator.
 *
 * A blank base is zeros, so it is built here rather than downloaded. That is
 * what makes this page deployable to a static host, where a 256 MB image cannot
 * be committed, and it saves a pointless transfer everywhere else.
 *
 * fixed_chunk_size on the streamed path turns on read caching. Without it every
 * unloaded block read is a network round trip and formatting a large disk takes
 * thousands of them.
 */
function diskFor(base, diskSize, baseIsBlank) {
  return baseIsBlank
    ? { buffer: new ArrayBuffer(diskSize) }
    : { url: base, size: diskSize, async: true, fixed_chunk_size: 256 * 1024 };
}

const $ = (id) => document.getElementById(id);
const state = {
  host: null, device: null, machine: null, emulator: null,
  governor: null, cipher: null, booted: false, mounted: false, alpine: null,
  lease: null, renewing: null
};

// --- output ------------------------------------------------------------------

function log(message, kind = "") {
  const el = $("log");
  if (el.dataset.empty) { el.textContent = ""; delete el.dataset.empty; }
  const line = document.createElement("div");
  if (kind) line.className = kind;
  line.textContent = message;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function status(text, kind = "idle") {
  const el = $("status");
  el.className = `status ${kind}`;
  el.textContent = text;
}

function setStep(id, kind) { $(id).className = `step${kind ? " " + kind : ""}`; }

function meters() {
  if (!state.machine || !state.machine.manifest) return;
  const s = state.machine.stats();
  $("m-chunks").innerHTML = `${s.chunksWritten}<span> / ${s.chunksTotal}</span>`;
  $("m-objects").textContent = s.distinctObjects;
  $("m-stored").innerHTML = `${(s.storedBytes / 1048576).toFixed(1)}<span> MB</span>`;
  $("m-occupancy").innerHTML = `${(s.occupancy * 100).toFixed(1)}<span> %</span>`;
  // Reported together deliberately: this ratio is occupancy, not compression.
  $("m-dedup").innerHTML = `${s.dedupRatio.toFixed(2)}<span> x</span>`;
  $("m-sync").textContent = state.machine.manifest.sync;
}

function enable(ids, on) { for (const id of ids) $(id).disabled = !on; }

// --- connection ----------------------------------------------------------------

try {
  const saved = localStorage.getItem("machine.repo");
  if (saved) $("repo").value = saved;
  const savedHost = localStorage.getItem("machine.hostKind");
  if (savedHost) $("hostKind").value = savedHost;
} catch { /* storage may be unavailable */ }

/**
 * Validate a token against the host and, if it can write, unlock booting.
 *
 * Split out of the button so that pasting a token runs it too: the token is
 * fetched by hand from another tab, and asking someone to paste and then also
 * press a button is one step more than the flow needs.
 */
async function connectRepository() {
  const token = $("token").value.trim();
  const [owner, repo] = $("repo").value.trim().split("/");
  const kind = $("hostKind").value;
  if (!token || !owner || !repo) {
    status("Enter a token and owner/repo.", "bad");
    return;
  }

  state.governor = new Governor({
    // 150 per minute against an enforced ceiling of 180. The documented 80 per
    // minute and 500 per hour were never observed to fire.
    ratePerMin: 150,
    concurrency: 8,
    onEvent: (e) => {
      if (e.type === "backpressure") {
        log(`backpressure: median ${e.medianMs}ms against ${e.baselineMs}ms baseline, ` +
            `concurrency now ${e.concurrency}`, "warn");
      } else if (e.type === "refused") {
        log(`rate limited, waiting ${e.retryAfterSeconds}s, concurrency now ${e.concurrency}`, "warn");
      }
    }
  });

  try {
    state.host = createHost(kind, { token, owner, repo, governor: state.governor });
    const info = await state.host.validate();
    if (!info.canWrite) throw new Error(`the token cannot write to ${owner}/${repo}`);
    const caps = state.host.constructor.capabilities;
    status(
      `Connected as ${info.login}. ${owner}/${repo} is ${info.private ? "private" : "public"}. ` +
      `${caps.batchCommit ? "Batch commit, one request per sync." : "Object writes, N+3 per sync."} ` +
      `${caps.orphanCommit ? "" : "No parentless commits, so compaction is unavailable."}`,
      "ok"
    );
    try {
      localStorage.setItem("machine.repo", `${owner}/${repo}`);
      localStorage.setItem("machine.hostKind", kind);
    } catch { /* ignore */ }
    enable(["boot"], true);
    if (!caps.orphanCommit) $("compact").title = "This host cannot create a parentless commit.";
  } catch (err) {
    status(err.message, "bad");
  }
}

$("connect").addEventListener("click", connectRepository);

/**
 * Sign in to GitHub, through the bridge.
 *
 * The user authenticates at github.com -- password, second factor, whatever
 * their account requires -- and this page is handed a token. It never sees the
 * password, and there is no token for anyone to create or paste. That is what
 * OAuth is for, and it is why the credentials go to GitHub's own page rather
 * than into a form here.
 *
 * The bridge does the one step a browser cannot. GitHub's token endpoints send
 * no CORS headers, and a machine inherits that refusal because its only route
 * out is this tab's `fetch`; the bridge is not a browser. The device flow is
 * the grant with no client secret, so there is nothing to deploy and nothing to
 * guard -- the same reason the `gh` command-line tool uses it.
 *
 * The token goes where a pasted one goes: the field, memory, and nowhere else.
 * `SECURITY.md` is the reason, and a sign-in button is not an excuse to start
 * writing it down.
 */
const BRIDGE = "http://localhost:9000";

/**
 * Say up front whether signing in is going to work.
 *
 * Finding out by pressing the button and reading a paragraph is the worst of
 * both: it fails at the moment you had decided to do something else. This asks
 * once, on load, and puts the answer where the decision is made.
 *
 * The interesting case is a page served over HTTPS -- a static host, which is
 * where this is deployed. `http://localhost` is a trustworthy origin, so mixed
 * content does not block it, but a public page reaching a local address is a
 * private network request and a browser preflights it. The bridge answers that
 * preflight; whether the browser then allows it depends on the browser. So this
 * tries, and if it cannot get through it says which of the two situations it is
 * in rather than "failed".
 */
async function checkBridge() {
  const chip = $("bridgeState");
  const hint = $("bridgeHint");
  const set = (text, on, help = "") => {
    chip.textContent = text;
    chip.className = `mountstate${on ? " on" : ""}`;
    hint.textContent = help;
  };

  try {
    const response = await fetch(`${BRIDGE}/_bridge/status`, { signal: AbortSignal.timeout(2500) });
    const status = await response.json();
    if (status.github) {
      set("sign-in ready", true);
    } else {
      set("bridge, no client id", false,
          "The bridge is running but was started without one, so it cannot sign anyone in. " +
          "Restart it with --github-client-id <id>, or set GITHUB_CLIENT_ID before starting it.");
    }
  } catch {
    // Which of the two situations this is turns on where the page came from, not
    // on whether it came over HTTPS. Measured: an HTTPS page on localhost reaches
    // the bridge and signs in normally, and a page on a public host does not
    // reach it at all -- a browser will not let a public page open a connection
    // into the machine of the person reading it, and answering the preflight
    // does not change that. So the address is what decides the message.
    const local = /^(localhost|127\.|\[?::1\]?$)/.test(location.hostname);
    if (!local) {
      set("no bridge", false,
          "This page is being served from " + location.hostname + ", and the bridge would run on " +
          "the machine of whoever is reading it. A browser will not let a page on a public host " +
          "open a connection into a reader's own machine, so this button cannot work here -- not " +
          "because the bridge is missing, but because nothing would be allowed to reach it. Run " +
          "the project locally to sign in this way. Everything else on this page works without it.");
    } else {
      set("no bridge", false,
          "Nothing is listening at " + BRIDGE + ". Start it beside the static server with " +
          "\"python serve.py --open --bridge\", having set GITHUB_CLIENT_ID, or run " +
          "\"node tools/bridge.mjs --github-client-id <id>\" yourself.");
    }
  }
}

addEventListener("load", () => { checkBridge(); });

$("ghSignIn").addEventListener("click", async () => {
  const help = $("tokenHelp");
  enable(["ghSignIn"], false);
  const say = (node) => { help.textContent = ""; help.append(node); };
  const line = (text) => { const d = document.createElement("div"); d.textContent = text; return d; };

  try {
    let started;
    try {
      started = await (await fetch(`${BRIDGE}/_bridge/github/start`)).json();
    } catch {
      say(line(
        `Nothing is listening at ${BRIDGE}. GitHub's token endpoints refuse browsers, so this ` +
        `needs the bridge: start it with "node tools/bridge.mjs --github-client-id <id>" and press this again.`
      ));
      status("the bridge is not running", "bad");
      return;
    }
    if (started.error) {
      say(line(started.detail ? `${started.error}: ${started.detail}` : started.error));
      status(started.error, "bad");
      return;
    }

    const panel = document.createElement("div");
    panel.append(line("Enter this code at GitHub and sign in there. Leave this tab open:"));
    const code = document.createElement("div");
    code.textContent = started.userCode;
    code.style.cssText = "font-size:22px;letter-spacing:.18em;margin:8px 0;user-select:all";
    panel.append(code);
    const link = document.createElement("a");
    link.href = started.verificationUri;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = started.verificationUri;
    panel.append(link);
    say(panel);
    status("Waiting for you to sign in at GitHub...", "idle");
    window.open(started.verificationUri, "_blank", "noopener");

    const every = Math.max(1, Number(started.interval) || 5) * 1000;
    const until = Date.now() + (Number(started.expiresIn) || 900) * 1000;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, every));
      const result = await (await fetch(
        `${BRIDGE}/_bridge/github/poll?handle=${encodeURIComponent(started.handle)}`)).json();

      if (result.status === "pending") continue;
      if (result.status === "done") {
        $("hostKind").value = "github";
        $("token").value = result.token;
        help.textContent = "Signed in as yourself at GitHub. The token is held in memory only, " +
                           "and is written nowhere.";
        const [owner, repo] = $("repo").value.trim().split("/");
        if (!owner || !repo) {
          status("Signed in. Now fill in owner / repo and press Connect.", "ok");
          return;
        }
        status("Signed in. Checking what the token can reach...", "idle");
        await connectRepository();
        return;
      }
      const why = {
        denied: "You declined it at GitHub.",
        expired: "The code expired. Press Sign in with GitHub again.",
        unknown: "The bridge has forgotten this sign-in. Press Sign in with GitHub again."
      }[result.status] ||
        `${result.error || result.status}${result.description ? ": " + result.description : ""}`;
      help.textContent = why;
      status(why, "bad");
      return;
    }
    status("The code expired before it was entered.", "bad");
  } finally {
    enable(["ghSignIn"], true);
    checkBridge();
  }
});

// Pasting a token still connects, for GitLab and Codeberg: they have no device
// flow here, so that field is the only way in for them.
$("token").addEventListener("paste", () => {
  // The field still holds the old value during the event; let the paste land.
  setTimeout(() => {
    if (!$("token").value.trim()) return;
    const [owner, repo] = $("repo").value.trim().split("/");
    if (!owner || !repo) {
      status("Token pasted. Fill in owner / repo and press Connect.", "idle");
      return;
    }
    status("Checking the token...", "idle");
    connectRepository();
  }, 0);
});

// --- boot ----------------------------------------------------------------------

$("boot").addEventListener("click", async () => {
  enable(["boot", "connect"], false);
  setStep("s1", "on");
  const branch = $("branch").value.trim() || `machine-${Date.now().toString(36)}`;
  $("branch").value = branch;

  try {
    // Look the machine up before building anything. Once a branch exists its
    // manifest is the authority on disk size, chunk size and base image, and
    // load() ignores what it is passed. Building the emulator from the dropdowns
    // first and discovering the mismatch afterwards would leave a device of the
    // wrong size wired to the machine.
    const existingManifest = await peekManifest(branch);

    let diskSize, chunkSize, base, baseIsBlank;
    if (existingManifest) {
      ({ diskSize, chunkSize, base, baseIsBlank } = existingManifest);
      const wantedMb = Number($("diskSize").value);
      const wantedChunk = Number($("chunkSize").value);
      if (diskSize !== wantedMb * 1024 * 1024 || chunkSize !== wantedChunk) {
        log(`${branch} already exists as a ${diskSize / 1048576} MB machine with ` +
            `${chunkSize / 1024} KB chunks. Using the machine's own geometry, ` +
            `not the selection.`, "warn");
      }
      // Reflect reality, so the controls do not keep claiming something else.
      $("diskSize").value = String(diskSize / 1048576);
      $("chunkSize").value = String(chunkSize);
    } else {
      const diskMb = Number($("diskSize").value);
      diskSize = diskMb * 1024 * 1024;
      chunkSize = Number($("chunkSize").value);
      base = DISKS[diskMb];
      // Every disk this page offers is blank. The name is recorded in the
      // manifest as the base's identity; the zeros are made locally.
      baseIsBlank = true;
    }

    const passphrase = $("passphrase").value;
    if (passphrase) {
      // Encryption normally costs deduplication. Here deduplication is the
      // reciprocal of occupancy and nothing more, so there is almost nothing to
      // lose by encrypting.
      const existingSalt =
        (existingManifest && existingManifest.encryption && existingManifest.encryption.salt) || null;
      const salt = existingSalt || randomSaltHex();
      state.cipher = await deriveCipher(passphrase, salt);
      log(`encryption on, salt ${salt.slice(0, 8)}...`);
    } else {
      state.cipher = null;
    }

    log(`booting: ${diskSize / 1048576} MB disk, ${chunkSize / 1024} KB chunks, ` +
        (baseIsBlank ? "blank base built locally" : `streamed from ${base}`));
    state.emulator = new V86({
      ...bootOptions({ screen: $("screen") }),
      hda: diskFor(base, diskSize, baseIsBlank)
    });
    wireSerial();

    state.device = new V86Device({
      emulator: state.emulator,
      diskSize,
      flush: serialFlush(state.emulator, { prompt: /[#$%>]\s*$/ }),
      onEvent: (e) => log(`device ${e.type}: ${e.path} (${e.streamed ? "streamed" : "in memory"})`)
    });
    await state.device.waitForDevice(30000);
    setStep("s2", "on");

    // Attach the engine before arming capture. Putting the machine back is a
    // write to the disk, and if capture were already on it would be recorded as
    // the guest's work and re-uploaded on the next sync.
    // One writer at a time. Conflict retry below settles two writes that meet;
    // it cannot settle two tabs that each believe they own this machine, and on
    // GitHub a fast-forward-only reference update is what decides between them.
    state.lease = new Lease({ host: state.host, branch, holder: holderName() });
    state.machine = new Machine({
      host: state.host, device: state.device, branch,
      cipher: state.cipher, governor: state.governor, lease: state.lease,
      onEvent: (e) => {
        if (e.type === "conflict-detected") log("another writer moved the branch first", "warn");
        if (e.type === "conflict-rebased") log(`rebased onto their commit; ${e.disjointChunks} chunks were disjoint`, "ok");
      }
    });
    const { existing } = await state.machine.load({
      diskSize, chunkSize, base, baseIsBlank: true
    });

    // Taken once the branch is known, and kept alive while this tab is. A lease
    // held by a tab that has gone away expires on its own, which is why it is a
    // lease: a lock nobody can release is worse than no lock.
    try {
      const taken = await state.lease.acquire();
      log(`lease on ${branch} held by ${taken.holder}` +
          (taken.enforced ? "" : ", advisory only: this host has no compare-and-swap"),
          taken.enforced ? "ok" : "warn");
      state.renewing = setInterval(
        () => state.lease.renew().catch((err) => log(`lease: ${err.message}`, "warn")),
        4 * 60 * 1000
      );
      addEventListener("pagehide", () => {
        if (state.lease) state.lease.release().catch(() => {});
      }, { once: true });
    } catch (err) {
      // Somebody else has it. Booting is still fine -- looking at a machine is
      // not writing to it -- but syncing will refuse until they let go.
      log(err.message, "bad");
      log("this tab can run the machine, but cannot sync it while somebody else holds it", "warn");
    }

    if (existing) {
      // The device was built from the base image, so it is blank. Without this
      // the guest boots an empty disk no matter what the branch holds.
      log(`attached to ${branch} at sync ${state.machine.manifest.sync}; ` +
          `putting its state back onto the disk`);
      const put = await state.machine.hydrate({
        onProgress: ({ applied, total }) => {
          if (applied === total || applied % 25 === 0) {
            status(`Restoring ${applied} of ${total} chunks onto the disk.`, "idle");
          }
        }
      });
      log(`${put.chunks} chunks written back; the guest will see the files it left`, "ok");
    } else {
      // Boot writes nothing to the repository. A git branch cannot exist without
      // a commit, and there is nothing to commit until the first sync, so saying
      // the machine is "on" a branch that is not there yet would be a lie the
      // user only discovers when they go looking for it.
      log(`new machine; ${branch} does not exist in the repository yet and is ` +
          `created by the first sync`);
    }

    state.device.start();
    log("capture armed; boot itself writes nothing to the disk");

    await waitForPrompt(180000);
    log(`shell is up; writes captured during boot: ${state.device.stats.writes}`);

    state.booted = true;
    meters();
    setStep("s3", "on");
    enable(["sync", "compact", "restoreBtn", "mount"], true);
    setMounted(false);

    // Mount without being asked. The mountpoint does not survive a boot, so
    // every session would otherwise start with the same two commands.
    await mountDisk();
    status(existing
      ? "Machine is running, attached to an existing branch."
      : `Machine is running. Nothing has been written to ${$("repo").value.trim()} yet. ` +
        `Sync creates the branch.`, "idle");
  } catch (err) {
    setStep("s1", "bad");
    log("ERROR: " + err.message, "bad");
    status(err.message, "bad");
    enable(["boot", "connect"], true);
  }
});

/**
 * Read an existing machine's manifest without attaching to it. Boot needs the
 * geometry and the salt before it can build anything, and both live here.
 * Returns null for a branch that does not exist yet.
 */
async function peekManifest(branch) {
  try {
    const ref = await state.host.resolveRef(branch);
    if (!ref) return null;
    const entries = await state.host.readTree(ref.tree);
    const entry = entries.find((e) => e.path === manifestModule.MANIFEST_PATH);
    if (!entry) return null;
    return manifestModule.parse(await state.host.readObject(entry.id));
  } catch { return null; }
}

// --- guest console ---------------------------------------------------------------

let terminal = null;
function wireSerial() {
  if (!terminal) terminal = new Terminal($("term"));
  // The guest emits a byte stream, not text. The terminal decodes UTF-8,
  // interprets colour and cursor sequences, and drops control bytes rather than
  // letting them render as characters.
  state.emulator.add_listener("serial0-output-byte", (byte) => terminal.writeByte(byte));
}

function waitForPrompt(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function poll() {
      // Match against escape-free text: a prompt preceded by a colour sequence
      // would otherwise never look like one. atPrompt also refuses a tail that
      // is still mid-echo, which a bare character test does not.
      if (terminal && fsModule.atPrompt(terminal.tail)) return resolve();
      if (Date.now() > deadline) return reject(new Error("no shell prompt appeared"));
      setTimeout(poll, 150);
    })();
  });
}

/**
 * Send a command and wait for the guest to come back to a prompt, returning what
 * it printed. The Send box does not need this, but anything the app decides
 * based on the result does.
 */
/**
 * Send a command to the guest and wait for it to finish. The runner is shared
 * with the library so there is one implementation of "is it done yet", which is
 * the part that is easy to get subtly wrong.
 */
const guestRun = makeRunner({
  send: (text) => {
    if (!state.emulator || !terminal) throw new Error("no guest is running");
    state.emulator.serial0_send(text);
  },
  tail: () => (terminal ? terminal.tail : ""),
  reset: () => { if (terminal) terminal.resetTail(); }
});

function setMounted(on) {
  state.mounted = on;
  $("mountstate").className = `mountstate${on ? " on" : ""}`;
  $("mountstate").textContent = on
    ? `${fsModule.MOUNTPOINT}, ${BINDS.map((b) => b.target).join(", ")}`
    : "not mounted";
  $("mount").disabled = on;
  $("unmount").disabled = !on;
  // Installing needs somewhere persistent to install to.
  $("install").disabled = !on;
  $("installBtn").disabled = !on || !$("install").files.length;
  // Serving needs the same: the web server and the site both live on the disk.
  // Saying why is the difference between a disabled button and a mystery.
  $("serveBtn").disabled = !on;
  if (!serving) {
    serveStatus(on
      ? "Ready. Serve puts a web server on the disk and gives the machine a URL."
      : "Mount the disk first — the web server and the site both live on it.");
  }
  $("alpine").disabled = !on || !!state.alpine;
  if (!on) { $("packages").disabled = true; $("packagesBtn").disabled = true; }
}

/**
 * Bring the disk up. Formatting is offered only when the disk genuinely has no
 * filesystem and the machine holds nothing: on a machine with chunks a mount
 * failure means something is wrong, and formatting would destroy the state the
 * user came back for.
 */
async function mountDisk() {
  $("mount").disabled = true;
  try {
    const empty = Object.keys(state.machine.manifest.chunks).length === 0;
    const result = await fsModule.open(guestRun, {
      allowFormat: empty,
      binds: BINDS,
      onStep: (s) => {
        if (s.type === "formatting") log("blank disk, putting a filesystem on it first");
        if (s.type === "bound") log(`${s.source} is now also ${s.target}`);
      }
    });
    setMounted(true);
    const distribution = await checkAlpine();
    if (distribution) {
      log(`this disk carries alpine ${distribution}; preparing its chroot`);
      await alpineModule.bootstrap(guestRun, { name: ALPINE_NAME });
      setAlpine(distribution);
    }

    await fsModule.ensureOnPath(guestRun);
    const shellPath = await fsModule.activateProfile(guestRun);
    if (shellPath.path.includes(fsModule.BIN)) {
      log(`${fsModule.MOUNTPOINT}/${fsModule.BIN} is on PATH, in this shell and on every boot`);
    }

    const paths = [result.mountpoint, ...result.bound.map((b) => b.target)].join(", ");
    log(result.formatted
      ? `formatted and mounted; one disk at ${paths}`
      : `mounted; one disk at ${paths}${result.alreadyMounted ? " (already was)" : ""}`, "ok");
    status(`One disk, visible at ${paths}. Write to any of them, then sync.`, "ok");
  } catch (err) {
    setMounted(false);
    log("mount failed: " + err.message, "bad");
    if (err.reason === fsModule.NO_FILESYSTEM) {
      // Refusing to format is the right outcome, so say why rather than
      // presenting it as a dead end.
      status("This machine has committed chunks but the disk has no readable " +
             "filesystem. Formatting would destroy it, so it was not done. " +
             "Check the branch, or restore to inspect what is there.", "bad");
    } else {
      status(err.message, "bad");
    }
    $("mount").disabled = false;
  }
}

$("mount").addEventListener("click", mountDisk);
$("unmount").addEventListener("click", async () => {
  $("unmount").disabled = true;
  try {
    // Binds come off first: they are separate mount entries onto the same
    // filesystem, and the disk cannot come down cleanly underneath them.
    const result = await fsModule.close(guestRun, { binds: BINDS });
    if (result.submounts.length) {
      log(`took down ${result.submounts.join(", ")} first`);
    }
    setMounted(false);
    setAlpine(state.alpine);   // the chroot is gone; its mounts are not there
    log(result.wasNotMounted ? "nothing was mounted" : "unmounted; the filesystem is clean", "ok");
  } catch (err) {
    log("unmount failed: " + err.message, "bad");
    if (err.output) {
      for (const line of String(err.output).split(/\r?\n/).slice(0, 3)) {
        if (line.trim()) log("  guest said: " + line.trim(), "bad");
      }
    }
    $("unmount").disabled = false;
  }
});

// --- the distribution on the disk --------------------------------------------

function setAlpine(version) {
  state.alpine = version || null;
  $("alpinestate").className = `mountstate${version ? " on" : ""}`;
  $("alpinestate").textContent = version ? `alpine ${version}, apk ready` : "no distribution";
  $("alpine").disabled = !!version || !state.mounted;
  $("packages").disabled = !version;
  $("packagesBtn").disabled = !version || !$("packages").files.length;
}

/** Report what is on the disk without changing anything. */
async function checkAlpine() {
  try {
    const version = await alpineModule.release(guestRun);
    setAlpine(version);
    return version;
  } catch { setAlpine(null); return null; }
}

$("alpine").addEventListener("click", async () => {
  $("alpine").disabled = true;
  try {
    log("--- putting a distribution on the disk ---");
    // From this page's own origin. No relay, no package mirror, no third party.
    const response = await fetch(ALPINE_ROOTFS);
    if (!response.ok) throw new Error(`${ALPINE_ROOTFS} is not being served`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    log(`fetched ${(bytes.length / 1048576).toFixed(2)} MB from this page's own origin`);

    state.emulator.create_file(ALPINE_NAME, bytes);
    const result = await alpineModule.bootstrap(guestRun, {
      name: ALPINE_NAME,
      onStep: (s) => {
        if (s.type === "unpacking") log("unpacking onto the disk, this takes a moment");
        if (s.type === "unpacked") log(`alpine ${s.release} unpacked`, "ok");
        if (s.type === "already-installed") log(`alpine ${s.release} was already here`);
        if (s.type === "prepared") log("proc, sys and dev mounted for the chroot");
        if (s.type === "ready") log(`${s.apk} runs inside it`, "ok");
      }
    });
    setAlpine(result.release);
    const packages = await alpineModule.installed(guestRun);
    log(`${packages.length} packages installed`);
    status(`Alpine ${result.release} is on the disk. Sync to keep it.`, "ok");
    meters();
  } catch (err) {
    log("could not put a distribution on the disk: " + err.message, "bad");
    if (err.output) log(err.output.split("\n").slice(0, 3).join(" | "), "bad");
    status(err.message, "bad");
    $("alpine").disabled = false;
  }
});

// --- packages ------------------------------------------------------------------

$("packages").addEventListener("change", () => {
  $("packagesBtn").disabled = !$("packages").files.length || !state.alpine;
});

$("packagesBtn").addEventListener("click", async () => {
  const files = [...$("packages").files];
  if (!files.length) return;
  $("packagesBtn").disabled = true;
  try {
    const total = files.reduce((sum, f) => sum + f.size, 0);
    log(`--- installing ${files.length} package${files.length > 1 ? "s" : ""}, ` +
        `${(total / 1048576).toFixed(1)} MB ---`);

    // Every package goes into the share first, then all are handed to apk at
    // once. Offline, apk resolves only the set it is given, so a package sent on
    // its own fails whenever something it needs is in the next file.
    for (const file of files) {
      state.emulator.create_file(file.name, new Uint8Array(await file.arrayBuffer()));
    }
    log(`${files.length} written to the transfer share`);

    const result = await alpineModule.installPackages(guestRun, {
      names: files.map((f) => f.name),
      onStep: (s) => {
        if (s.type === "staged") log(`staged ${s.name}`);
        if (s.type === "installing") log(`handing all ${s.count} to apk in one go`);
      }
    });

    log(result.added.length
      ? `installed: ${result.added.join(", ")}`
      : "apk reported success but nothing new appeared", "ok");
    status(`${result.added.length} packages installed. Sync to keep them.`, "ok");
    $("packages").value = "";
    meters();
  } catch (err) {
    log("install failed: " + err.message, "bad");
    if (err.output) {
      for (const line of err.output.split("\n").slice(0, 4)) if (line.trim()) log("  " + line.trim(), "bad");
    }
    status(err.message, "bad");
  }
  $("packagesBtn").disabled = !$("packages").files.length;
});

// --- installing a program ----------------------------------------------------
//
// No package manager, no network. A file goes in through the emulator's 9p
// share, which the guest mounts at /mnt, and from there onto the disk, which is
// the part that survives.

$("install").addEventListener("change", () => {
  $("installBtn").disabled = !$("install").files.length || !state.mounted;
});

$("installBtn").addEventListener("click", async () => {
  const file = $("install").files[0];
  if (!file) return;
  $("installBtn").disabled = true;
  try {
    log(`--- installing ${file.name} (${(file.size / 1024).toFixed(1)} KB) ---`);
    const bytes = new Uint8Array(await file.arrayBuffer());

    // Into the share first. This lives in browser memory and is empty again
    // after a reload, so it is a staging area and never the destination.
    state.emulator.create_file(file.name, bytes);
    log(`written to the transfer share at ${fsModule.TRANSFER}/${file.name}`);

    const installed = await fsModule.install(guestRun, { name: file.name });
    log(`copied to ${installed.path} and made executable`, "ok");
    if (installed.kind) log(`what it is: ${installed.kind}`);

    // Reporting the architecture matters: a binary for the wrong one copies
    // perfectly and then fails to run with a message that explains nothing.
    if (/x86-64|ARM|aarch64/i.test(installed.kind)) {
      log("that is not an i686 binary; this guest will not be able to run it", "warn");
    } else if (/dynamically linked/i.test(installed.kind)) {
      log("dynamically linked: it needs uClibc, not glibc. A static build is safer.", "warn");
    }

    const onPath = await fsModule.rc(guestRun, `command -v ${file.name}`);
    log(onPath.ok
      ? `available as: ${file.name}`
      : `installed, but not on PATH under that name. Run it as ${installed.path}.`,
      onPath.ok ? "ok" : "warn");

    status(`${file.name} is on the disk. Sync to keep it, or it is gone on reload.`, "ok");
    meters();
  } catch (err) {
    log("install failed: " + err.message, "bad");
    status(err.message, "bad");
  }
  $("installBtn").disabled = false;
});

// --- the terminal takes input directly ---------------------------------------
//
// Not a text box that submits a line. Keystrokes are turned into the bytes a
// terminal sends and handed to the guest as they are pressed, and whatever comes
// back is displayed. Nothing is echoed locally: the tty echoes, and a terminal
// that echoed as well would double every character and would show a password
// the far side had deliberately stopped echoing.
//
// Everything that looks like a feature follows from that. History, tab
// completion, Ctrl+C and multi-line constructs work because the shell and the
// line discipline are doing them, not because this page implements them.

function sendToGuest(bytes) {
  if (!state.emulator || !bytes || !bytes.length) return;
  if (typeof state.emulator.serial_send_bytes === "function") {
    state.emulator.serial_send_bytes(0, new Uint8Array(bytes));
  } else {
    state.emulator.serial0_send(String.fromCharCode(...bytes));
  }
}

$("term").addEventListener("keydown", (event) => {
  if (!state.emulator) return;
  const bytes = keyToBytes(event);
  if (!bytes) return;          // let the browser keep its own shortcuts
  event.preventDefault();
  sendToGuest(bytes);
});

$("term").addEventListener("paste", (event) => {
  if (!state.emulator) return;
  event.preventDefault();
  const text = event.clipboardData.getData("text");
  if (!text) return;

  // A paste carrying a newline runs whatever preceded it without the user
  // pressing anything, which is how people end up running a line they did not
  // read. Terminals that care about this ask first.
  if (pasteNeedsConfirming(text)) {
    // Split for the preview only. Line endings vary, so normalise on the
    // line feed and drop any carriage return that came with it.
    const LF = String.fromCharCode(10);
    const CR = String.fromCharCode(13);
    const lines = text.trim().split(LF).map((l) => l.split(CR).join(""));
    const shown = lines.slice(0, 3).join(LF);
    const more = lines.length > 3 ? LF + "... and " + (lines.length - 3) + " more" : "";
    if (!confirm("Run " + lines.length + " lines in the guest?" + LF + LF + shown + more)) return;
  }
  sendToGuest(textToBytes(text));
});

$("term").addEventListener("focus", () => {
  if (terminal) { terminal.showCursor = true; terminal.render(); }
});
$("term").addEventListener("blur", () => {
  if (terminal) { terminal.showCursor = false; terminal.render(); }
});

// --- sync ------------------------------------------------------------------------

$("sync").addEventListener("click", async () => {
  enable(["sync", "compact", "restoreBtn"], false);
  try {
    log("--- sync ---");
    if (state.alpine) {
      // These are kernel state, not disk state. Leaving them mounted would
      // commit a filesystem with /proc and /dev grafted into it.
      await alpineModule.release_(guestRun);
      log("chroot mounts taken down before sealing");
    }
    const creating = state.machine.head === null;
    const result = await state.machine.sync({ message: $("message").value || undefined });
    if (result.skipped) {
      log("nothing dirty since the last sync");
      status("Nothing to sync.", "idle");
    } else if (creating && result.chunks === 0) {
      // The branch had to be created even with a clean disk, or the manifest
      // would never leave this tab.
      log(`created ${state.machine.branch} at ${result.commit.slice(0, 8)}; the disk is ` +
          `untouched so far, only the manifest was written`, "ok");
      addRow(result);
      status(`Branch ${state.machine.branch} now exists in the repository.`, "ok");
    } else {
      log(`${result.chunks} dirty chunks, ${result.uploaded} uploaded, ${result.reused} already present`);
      log(`${(result.bytesUploaded / 1048576).toFixed(2)} MB in ${result.requests} requests, ` +
          `${result.seconds.toFixed(1)}s -> ${result.commit.slice(0, 8)}`, "ok");
      addRow(result);
      status(`Synced to ${result.commit.slice(0, 8)}.`, "ok");
    }
    meters();
    setStep("s4", "on");
  } catch (err) {
    if (err instanceof ConflictError) {
      log(`conflict: ${err.overlappingChunks.length} chunks changed by both writers ` +
          `(${err.overlappingChunks.slice(0, 8).join(", ")}). Fork to a new branch.`, "bad");
      status("Conflicting writers. These states cannot be merged.", "bad");
    } else {
      log("ERROR: " + err.message, "bad");
      status(err.message, "bad");
    }
  }
  enable(["sync", "compact", "restoreBtn"], true);
});

function addRow(result) {
  const body = $("rows");
  if (body.dataset.empty) { body.innerHTML = ""; delete body.dataset.empty; }
  const tr = document.createElement("tr");
  tr.innerHTML =
    `<td>${state.machine.manifest.sync}</td>` +
    `<td>${result.chunks}</td>` +
    `<td class="hi">${result.uploaded}</td>` +
    `<td>${result.reused}</td>` +
    `<td>${(result.bytesUploaded / 1048576).toFixed(2)}</td>` +
    `<td>${result.requests}</td>` +
    `<td>${result.seconds.toFixed(1)}</td>`;
  body.appendChild(tr);
}

// --- compaction --------------------------------------------------------------------

$("compact").addEventListener("click", async () => {
  const caps = state.host.constructor.capabilities;
  if (!caps.orphanCommit) {
    status("This host cannot create a parentless commit, so history cannot be dropped atomically.", "bad");
    return;
  }
  if (!confirm(
    "Compaction rewrites the branch to a single parentless commit and discards its " +
    "history. On a full machine this reads the whole disk and can take minutes, " +
    "because it is bounded by the write rate rather than by bandwidth.\n\nContinue?"
  )) return;

  enable(["sync", "compact", "restoreBtn"], false);
  try {
    log("--- compaction ---");
    const result = await state.machine.compact({});
    log(`read ${result.chunksRead} chunks in ${result.readSeconds.toFixed(1)}s, ` +
        `${result.distinctObjects} distinct`);
    log(`uploaded ${result.uploaded}, ${result.unreachableAfter} objects now collectable, ` +
        `${result.requests} requests, ${result.seconds.toFixed(1)}s`, "ok");
    meters();
    status(`Compacted to ${result.commit.slice(0, 8)}. History dropped.`, "ok");
  } catch (err) {
    log("ERROR: " + err.message, "bad");
    status(err.message, "bad");
  }
  enable(["sync", "compact", "restoreBtn"], true);
});

// --- restore -----------------------------------------------------------------------

$("restoreBtn").addEventListener("click", async () => {
  enable(["sync", "compact", "restoreBtn"], false);
  try {
    log("--- restore from the repository alone ---");
    if (state.emulator) {
      try { await state.emulator.destroy(); } catch { /* already gone */ }
      state.emulator = null;
    }
    if (terminal) terminal.clear();

    const branch = $("branch").value.trim();
    const result = await restore({
      host: state.host, branch,
      cipher: state.cipher || undefined,
      // Restoration is base plus written chunks. A blank base takes the zeros
      // fast path; anything else must actually be fetched.
      fetchBase: async (url) => new Uint8Array(await (await fetch(url)).arrayBuffer()),
      onEvent: (e) => log(`restore: ${e.type}${e.url ? " " + e.url : ""}`)
    });
    log(`resolved ${branch} -> ${result.commit.slice(0, 8)}, applied ${result.chunksApplied} chunks`);

    state.emulator = new V86({
      ...bootOptions({ screen: $("screen") }),
      hda: { buffer: result.disk.buffer }
    });
    wireSerial();

    // Rebind the engine to the new emulator. The old device wrapped a buffer
    // belonging to an emulator that has just been destroyed, so leaving it in
    // place would make the next sync read a disk that no longer exists.
    state.device = new V86Device({
      emulator: state.emulator,
      diskSize: result.disk.length,
      flush: serialFlush(state.emulator, { prompt: /[#$%>]\s*$/ }),
      onEvent: (e) => log(`device ${e.type}: ${e.path} (${e.streamed ? "streamed" : "in memory"})`)
    });
    await state.device.waitForDevice(30000);
    state.lease = new Lease({ host: state.host, branch, holder: holderName() });
    state.machine = new Machine({
      host: state.host, device: state.device, branch,
      cipher: state.cipher, governor: state.governor, lease: state.lease
    });
    await state.machine.load();
    // The disk was built from this very state, so it is already put back.
    state.machine.markHydrated();
    state.device.start();

    await waitForPrompt(180000);
    meters();
    setMounted(false);
    await mountDisk();
    log("a machine rebuilt from the repository alone is running, and syncing " +
        "from here continues its history", "ok");
    status(`Rebuilt from ${result.commit.slice(0, 8)}. Check the shell.`, "ok");
  } catch (err) {
    log("ERROR: " + err.message, "bad");
    status(err.message, "bad");
  }
  enable(["restoreBtn", "sync", "compact"], true);
});


// --- serving ------------------------------------------------------------------
//
// The same sequence the demo runs, on the machine this page booted. It needs the
// disk mounted, because what gets served lives on it and so does the web server.

let serving = null;

function serveStatus(message, kind = "idle") {
  const el = $("serveStatus");
  el.textContent = message;
  el.className = `status ${kind}`;
}

$("serveBtn").addEventListener("click", async () => {
  enable(["serveBtn"], false);
  const directory = $("serveDir").value.trim() || "/disk/www";
  serveStatus("Putting a web server on the disk...", "idle");
  try {
    if (!state.mounted) throw new Error("mount the disk first: what gets served lives on it");
    const staged = await stageFiles(state.emulator, terminal);
    log(`handed to the guest: busybox (${staged.bytes} bytes) and rrd`);

    // The same site the demo serves, and only when the directory has no page of
    // its own: a machine that already holds somebody's site must not have it
    // overwritten by a demonstration of what a site is.
    await guestRun(`mkdir -p ${directory}`);
    const present = await guestRun(`test -f ${directory}/index.html; echo rc=$?`,
      { until: (tail) => /rc=\d/.test(tail) });
    if (!/rc=0/.test(present)) {
      await dynamicSite.install(guestRun, { directory });
      log(`wrote a demonstration site to ${directory}, form and all`);
    } else {
      log(`${directory} already holds an index.html; serving what is there`);
    }

    serving = await serveMachine({
      emulator: state.emulator,
      run: guestRun,
      device: state.device,
      engine: state.machine,
      branch: state.machine ? state.machine.branch : null,
      directory,
      onStep: (message) => log(message)
    });
    serveStatus(`Serving ${directory} at ${serving.url} — open it in another tab. ` +
                `Inside the machine, "rrd help" lists what it can do from there.`, "ok");
    enable(["unserveBtn", "idpBtn"], true);
    idpStatus("Ready. This installs an IdP onto the disk and runs a full flow against it.");
  } catch (err) {
    serveStatus(err.message, "bad");
    enable(["serveBtn"], true);
  }
});

function idpWho(message, kind = "idle") {
  const el = $("idpWho");
  el.textContent = message;
  el.className = `status ${kind}`;
}

/**
 * Sign in, as a person would.
 *
 * The machine is the identity provider and this page is the client, and they are
 * on different origins already -- which is the arrangement OAuth assumes and the
 * arrangement this project adopted for its own reasons. So the sign-in page
 * opens on the machine's origin, and the code comes back here, to a callback
 * that is a real registered address on this one.
 *
 * The exchange afterwards goes over the tab's own stack rather than a fetch to
 * the machine's origin, and that is not laziness: a service worker only answers
 * for the clients it controls, so a fetch from this page to the machine's origin
 * would sail past the worker and hit the static server behind it. A browser tab
 * can navigate to a machine; it cannot fetch one.
 */
$("idpLoginBtn").addEventListener("click", async () => {
  enable(["idpLoginBtn"], false);
  let listener = null;
  let popup = null;
  try {
    const session = idpSession();
    if (!session) throw new Error("no machine is running");
    const machineUrl = (window.machine && window.machine.url) || (serving && serving.url);
    if (!machineUrl) throw new Error("the machine has no origin of its own to sign in on");

    const idp = await import("./idp.js");
    const { verifier, challenge } = await idp.pkcePair();
    const state = idp.base64url(crypto.getRandomValues(new Uint8Array(12)));
    const nonce = idp.base64url(crypto.getRandomValues(new Uint8Array(12)));
    const redirect = idp.callbackUrl();

    const authorize = new URL("cgi-bin/authorize", machineUrl);
    authorize.search = new URLSearchParams({
      response_type: "code", client_id: "test-client", redirect_uri: redirect,
      scope: "openid profile email", state, nonce,
      code_challenge: challenge, code_challenge_method: "S256"
    });

    idpWho("Waiting for the sign-in window...", "idle");
    popup = window.open(authorize, "rrd-idp-login", "width=520,height=620");
    if (!popup) throw new Error("the sign-in window was blocked; allow popups for this page");

    const back = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("nobody signed in within two minutes")), 120000);
      listener = (event) => {
        // Same origin only, and our own message shape: this page has a token in
        // it, and a message handler is something any site can reach.
        if (event.origin !== location.origin) return;
        if (!event.data || event.data.source !== "rrd-idp-callback") return;
        clearTimeout(timer);
        resolve(event.data);
      };
      addEventListener("message", listener);
    });

    if (back.error) throw new Error(`${back.error}${back.errorDescription ? ": " + back.errorDescription : ""}`);
    if (back.state !== state) throw new Error("the state that came back is not the one that went out");
    if (!back.code) throw new Error("no code came back");

    idpWho("Exchanging the code...", "idle");
    const response = await session.net.request({
      port: 80, method: "POST", path: "/cgi-bin/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new TextEncoder().encode(new URLSearchParams({
        grant_type: "authorization_code", code: back.code, client_id: "test-client",
        redirect_uri: redirect, code_verifier: verifier
      }).toString())
    });
    const tokens = JSON.parse(new TextDecoder().decode(response.body));
    if (tokens.error) throw new Error(`${tokens.error}: ${tokens.error_description || ""}`);

    const { keys } = await (await fetch(new URL("../idp-test/jwks.json", import.meta.url))).json();
    const { claims } = await idp.verifyWithJwks(tokens.id_token, keys);
    if (claims.nonce !== nonce) throw new Error("the nonce did not survive: this token answers another request");

    idpWho(`Signed in as ${claims.name || claims.sub}` +
           `${claims.email ? ` (${claims.email})` : ""}. Verified against the JWKS this site serves. ` +
           `The key is public, so this proves nothing — which is the point.`, "ok");
    log(`signed in as ${claims.sub}, token verified against the published JWKS`);
  } catch (err) {
    idpWho(err.message, "bad");
    log(err.message, "bad");
  } finally {
    if (listener) removeEventListener("message", listener);
    if (popup && !popup.closed) popup.close();
    enable(["idpLoginBtn"], true);
  }
});

function idpStatus(message, kind = "idle") {
  const el = $("idpStatus");
  el.textContent = message;
  el.className = `status ${kind}`;
}

/**
 * Whichever machine is running, in the shape the checks want.
 *
 * There are two ways to have one and they carry it differently: /app/?serve
 * builds its own emulator inside demo-serve.js and leaves the session on
 * window.machine, while the Serve button drives this page's emulator through
 * guestRun. Both end up with a runner and a stack, which is all that is needed.
 */
function idpSession() {
  if (window.machine && window.machine.run && window.machine.net) {
    return { run: window.machine.run, net: window.machine.net,
             directory: window.machine.directory || "/disk/www" };
  }
  if (serving && serving.net) {
    return { run: guestRun, net: serving.net, directory: serving.directory || "/disk/www" };
  }
  return null;
}

let signer = null;

$("idpBtn").addEventListener("click", async () => {
  enable(["idpBtn"], false);
  try {
    const session = idpSession();
    if (!session) {
      throw new Error("serve a directory first: the endpoints are CGI, and something has to run them");
    }

    const idp = await import("./idp.js");

    // Once per tab. Starting it twice would try to listen on a port the stack
    // is already listening on, which throws rather than quietly replacing it.
    if (!signer) {
      signer = idp.startSigner({
        net: session.net,
        onEvent: (e) => log(`idp signer: ${e.type}${e.sub ? ` ${e.sub}` : ""}` +
                            `${e.reason ? ` (${e.reason})` : ""}${e.error ? ` ${e.error}` : ""}`,
                            e.type === "failed" ? "bad" : "")
      });
      log(`the signer is listening on ${session.net.ip}:${signer.port}. Its key is public on purpose.`);
    }

    idpStatus("Installing the identity provider onto the disk...", "idle");
    const where = await idp.install(session.run, { directory: session.directory });
    $("idpState").className = "mountstate on";
    $("idpState").textContent = "installed";
    enable(["idpLoginBtn"], true);
    log(`identity provider: fixtures in ${where.root}, endpoints in ${where.directory}/cgi-bin`);

    idpStatus("Running an authorization code flow against it...", "idle");
    const { check } = await import("./check-idp.js");
    const report = await check(session, { directory: session.directory, root: where.root });

    for (const row of report.rows) {
      log(`idp ${row.ok ? "ok  " : "FAIL"} ${row.layer}: ${row.check} - ${row.detail}`,
          row.ok === false ? "bad" : "");
    }

    const failed = report.rows.filter((row) => row.ok === false);
    idpStatus(failed.length
      ? `${failed[0].layer}: ${failed[0].check} - ${failed[0].detail}`
      : `The whole flow works. ${report.rows.length} checks: a code issued and spent once, ` +
        `a token signed in this tab and verified against the JWKS this site serves as a file.`,
      failed.length ? "bad" : "ok");
  } catch (err) {
    idpStatus(err.message, "bad");
    log(err.message, "bad");
  }
  enable(["idpBtn"], true);
});

$("unserveBtn").addEventListener("click", async () => {
  enable(["unserveBtn"], false);
  try {
    if (serving) await serving.stop();
    serving = null;
    serveStatus("Not serving. The disk is untouched.", "idle");
    // The endpoints are CGI: with nothing serving them there is nothing to test,
    // though what was installed stays on the disk.
    enable(["idpBtn", "idpLoginBtn"], false);
    idpStatus("Not serving, so there is nothing running the endpoints.", "idle");
  } catch (err) {
    serveStatus(err.message, "bad");
  }
  enable(["serveBtn"], true);
});


$("reset").addEventListener("click", () => location.reload());

// --- starting without being asked twice ---------------------------------------
//
// /app/?serve boots a machine, serves it, checks it and prints the link. There
// is nothing here a person could not do from the console; what it removes is
// having to. A machine started this way needs no token, because it commits to a
// repository held in memory: it is for seeing the thing work, not for keeping it.

async function autoServe() {
  const panel = $("serveStatus");
  const say = (message, kind = "idle") => { panel.textContent = message; panel.className = `status ${kind}`; };
  try {
    say("Starting a machine. This takes about a minute...", "idle");
    const module = await import("./demo-serve.js");
    const session = await module.main({ onStep: (message) => log(message) });
    // Before the checking starts, not after: the console is the first place
    // anyone reaches for when something looks wrong, and the check takes a while.
    window.machine = session;
    serving = { url: session.url, stop: () => session.stop() };
    enable(["unserveBtn", "idpBtn"], true);
    idpStatus("Ready. This installs an IdP onto the disk and runs a full flow against it.");

    panel.className = "status ok";
    panel.textContent = "";
    const link = document.createElement("a");
    link.href = session.url;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = session.url;
    link.style.cssText = "font-weight:500;text-decoration:underline";
    panel.append("Serving. Open this in another tab: ", link);

    // Worth saying plainly. A machine started this way never went through the
    // Repository panel, so nothing here is attached to a repository: it commits
    // to a Map in this tab, and closing the tab is the end of it. Everything
    // else about it is real, which is exactly what makes that easy to forget.
    const throwaway = document.createElement("div");
    throwaway.style.cssText = "margin-top:8px";
    throwaway.textContent =
      "This is a throwaway machine: no token, no repository, committing to memory. " +
      "Closing this tab ends it. For one that survives, connect a repository above, " +
      "boot, mount, and press Serve.";
    panel.append(throwaway);

    const { check } = await import("./check-serve.js");
    const report = await check(session, { directory: "/disk/www" });
    const failed = report.rows.filter((row) => row.ok === false);
    const note = document.createElement("div");
    note.style.cssText = "margin-top:8px";
    note.textContent = failed.length
      ? `${failed[0].layer}: ${failed[0].check} — ${failed[0].detail}`
      : `Checked: ${report.rows.filter((r) => r.ok).length} of ${report.rows.length} layers healthy, ` +
        `the last one is for the other tab to answer.`;
    panel.append(note);
    if (failed.length) panel.className = "status bad";

    log("the machine is in window.machine; try: await window.machine.run('ls /disk/www')");
  } catch (err) {
    say(err.message, "bad");
    log(err.message, "bad");
  }
}

if (new URLSearchParams(location.search).has("serve")) {
  addEventListener("load", () => { autoServe(); });
}


if (location.protocol === "file:") {
  status("Serve this over http. Modules, wasm and the streamed disk all fail on file://.", "bad");
  enable(["connect"], false);
}
