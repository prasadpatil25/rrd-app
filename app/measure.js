// What the network lane costs, measured rather than asserted.
//
// The rest of this repository reports numbers; the network and serving lanes
// arrived with correctness tests and none, which is the wrong way round. These
// are the three a person deciding whether to use this would ask for: how long
// until a machine is serving, how long a request takes, and how fast bytes move.
//
// One measurement that is deliberately absent: a comparison against a WebSocket
// relay. There is no relay in this project to compare against, and building one
// to lose a race to would be a benchmark written to a conclusion. What is here
// instead is the breakdown -- the guest's own work, the stack in the tab, and
// the service worker hop -- which is the part a reader can act on.
//
//   const m = await import("./measure.js");
//   await m.measure(window.machine);

/** Milliseconds, to the tenth. performance.now() is sub-millisecond here. */
const ms = (n) => Math.round(n * 10) / 10;

function summarise(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  return {
    n: sorted.length,
    min: ms(sorted[0]),
    median: ms(at(0.5)),
    p95: ms(at(0.95)),
    max: ms(sorted[sorted.length - 1])
  };
}

/**
 * @param {Object} session what demo-serve.js main() returned
 * @param {Object} [options]
 * @param {number} [options.requests] how many latency samples
 * @param {number} [options.megabytes] how large a file to move
 */
export async function measure(session, { requests = 40, megabytes = 4 } = {}) {
  const { net, run, steps } = session;
  const { rc } = await import("../src/guest/fs.js");
  const out = { boot: {}, latency: {}, throughput: {} };

  // --- how long until it was serving ----------------------------------------
  //
  // Taken from what the boot already reported rather than by booting again: the
  // machine under measurement is the one that ran.
  for (const line of steps) {
    let match = /shell up after ([\d.]+)s/.exec(line);
    if (match) out.boot.toShell = Number(match[1]);
    if (/httpd is listening|serving .* from inside the guest/.test(line)) out.boot.serving = true;
  }

  // --- a request, forty times -----------------------------------------------
  //
  // Two shapes. A static file is the guest reading from its disk; the CGI is the
  // guest forking a shell and running a program, which is the cost of being
  // dynamic rather than the cost of the network.
  for (const [name, path] of [["static", "/style.css"], ["dynamic", "/cgi-bin/process.cgi?text=x&calc=1%2B1"]]) {
    const samples = [];
    for (let i = 0; i < requests; i++) {
      const started = performance.now();
      const response = await net.request({ port: 80, path });
      if (response.status !== 200) throw new Error(`${path} answered ${response.status}`);
      samples.push(performance.now() - started);
    }
    out.latency[name] = summarise(samples);
  }

  // --- moving something large ------------------------------------------------
  const bytes = megabytes * 1024 * 1024;
  const made = await rc(run, `dd if=/dev/zero of=/disk/www/big.bin bs=1024 count=${megabytes * 1024} 2>/dev/null; ls -l /disk/www/big.bin`, 120000);
  if (!made.ok) throw new Error("could not make a large file in the guest");

  const started = performance.now();
  const big = await net.request({ port: 80, path: "/big.bin", timeoutMs: 180000 });
  const seconds = (performance.now() - started) / 1000;
  out.throughput = {
    bytes: big.body.length,
    seconds: Math.round(seconds * 100) / 100,
    mbPerSecond: Math.round((big.body.length / 1024 / 1024 / seconds) * 100) / 100,
    correct: big.body.length === bytes
  };
  await rc(run, "rm -f /disk/www/big.bin", 30000);

  // --- what the tab's own stack did while doing it ---------------------------
  out.stack = { ...net.stats };
  out.url = session.url;
  return out;
}

/** The same request as seen from a tab that is not hosting the machine. */
export function browserSideScript(url, count = 20) {
  return `(async () => {
    const samples = [];
    for (let i = 0; i < ${count}; i++) {
      const started = performance.now();
      const response = await fetch(${JSON.stringify(url)} + "style.css?" + i, { cache: "no-store" });
      await response.arrayBuffer();
      samples.push(performance.now() - started);
    }
    samples.sort((a, b) => a - b);
    return {
      n: samples.length,
      min: Math.round(samples[0] * 10) / 10,
      median: Math.round(samples[Math.floor(samples.length / 2)] * 10) / 10,
      p95: Math.round(samples[Math.floor(samples.length * 0.95)] * 10) / 10
    };
  })()`;
}
