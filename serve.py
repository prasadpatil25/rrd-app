#!/usr/bin/env python3
"""Static file server with HTTP Range support, rooted at the project.

python -m http.server ignores Range and returns 200 with the whole file.
v86's AsyncXHRBuffer streams a disk image with `Range: bytes=...`, so the
async-buffer test needs a server that answers 206 properly.

    python serve.py [port ...]    default 8000 8001
    python serve.py --open        the same, and open a machine in a browser
    python serve.py --bridge      the same, and start tools/bridge.mjs beside it
    python serve.py --bridge --github-client-id ID    ... offering GitHub sign-in

--bridge is opt-in on purpose. The bridge is a server, which the rest of this
project is at pains not to be, and SECURITY.md's claim that it "is started by
hand, and stops when you stop it" should stay true: a flag is a hand. What it
removes is the second terminal, not the decision. It needs node. Give it
--github-client-id (or set GITHUB_CLIENT_ID here) to offer GitHub sign-in; the
id is passed on as an argument rather than through the environment, because an
environment does not always survive a platform boundary and the failure when it
does not is silent. --github-base moves which GitHub it signs in to, which is
how tools/fake-github.mjs gets tested from the app.

Serves the whole project so /app can import /src directly. Range support is
required: v86's streamed disk fetches with Range, and python -m http.server
ignores it and returns the whole file with a 200.

Two ports, not one, and the second is not there to serve anything the first
cannot. A machine's pages must not come from the origin the git token lives on,
or a site running in a guest could read that token; and locally, a different
origin means a different port. The same files are served on both. The first port
is the app, the second is where machines appear.
"""
import http.server
import io
import subprocess
import os
import re
import signal
import socketserver
import sys
import threading
import webbrowser

ARGV = sys.argv[1:]
OPEN = "--open" in ARGV
BRIDGE = "--bridge" in ARGV


def option(name):
    """The value after a flag, if there is one that is not itself a flag."""
    if name in ARGV:
        at = ARGV.index(name)
        if at + 1 < len(ARGV) and not ARGV[at + 1].startswith("--"):
            return ARGV[at + 1]
    return None


# Passed to the bridge as an argument rather than left to the environment. An
# environment is not always inherited across a platform boundary -- WSL forwards
# only what WSLENV names, so a Windows node started from a Linux python sees
# nothing -- and the failure is silent: the bridge comes up without sign-in and
# nothing says why. An argument crosses every boundary there is.
CLIENT_ID = option("--github-client-id") or os.environ.get("GITHUB_CLIENT_ID")
# Where the bridge should look for GitHub. Passed on for the same reason and
# by the same route as the client id, and the reason to want it is
# tools/fake-github.mjs: pointed at that, the sign-in button can be pressed
# without registering an app or typing a code into github.com.
CLIENT_BASE = option("--github-base") or os.environ.get("GITHUB_BASE")

_taken = set()
for _flag in ("--github-client-id", "--github-base"):
    if _flag in ARGV:
        _taken.add(ARGV.index(_flag) + 1)
ARGS = [a for i, a in enumerate(ARGV) if not a.startswith("--") and i not in _taken]
PORTS = [int(a) for a in ARGS] or [8000, 8001]


class RangeHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def end_headers(self):
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_head(self):
        rng = self.headers.get("Range")
        if not rng:
            return super().send_head()

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            return super().send_head()
        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(404, "File not found")
            return None

        size = os.fstat(f.fileno()).st_size
        m = re.match(r"bytes=(\d*)-(\d*)\s*$", rng)
        if not m:
            f.close()
            self.send_error(400, "Malformed Range header")
            return None

        start_s, end_s = m.group(1), m.group(2)
        if start_s == "":
            if end_s == "":
                f.close()
                self.send_error(400, "Malformed Range header")
                return None
            length = int(end_s)
            start = max(0, size - length)
            end = size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1

        end = min(end, size - 1)
        if start > end or start >= size:
            f.close()
            self.send_response(416)
            self.send_header("Content-Range", "bytes */%d" % size)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None

        f.seek(start)
        data = f.read(end - start + 1)
        f.close()

        self.send_response(206)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        return io.BytesIO(data)

    def log_message(self, fmt, *args):
        if "Range" in str(self.headers.get("Range") or ""):
            return  # range chatter is noisy once a disk starts streaming
        super().log_message(fmt, *args)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Ctrl-C raises KeyboardInterrupt and the cleanup below runs. A SIGTERM --
    # from `kill`, from a supervisor, from a shell tearing down a job -- exits
    # without unwinding, and the bridge is left holding port 9000 with nothing
    # left that knows it started it. Turning it into SystemExit runs the same
    # finally block that Ctrl-C does. Measured: without this, a killed serve.py
    # orphans its bridge.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    servers = [Server(("127.0.0.1", port), RangeHandler) for port in PORTS]

    print("serving %s with Range support" % os.getcwd(), flush=True)
    for index, port in enumerate(PORTS):
        role = "the app" if index == 0 else "machines"
        print("    http://localhost:%d/    %s" % (port, role), flush=True)

    # One process, one port each. They serve the same files; only the origin
    # differs, which is the entire reason there is more than one.
    for httpd in servers[1:]:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    bridge = None
    if BRIDGE:
        # Inherit stdio: the bridge announces its own address, its token if it
        # made one, and every request it carries. Swallowing that would make the
        # convenience cost more than the second terminal did.
        try:
            command = [os.environ.get("NODE", "node"), "tools/bridge.mjs"]
            if CLIENT_ID:
                command += ["--github-client-id", CLIENT_ID]
            if CLIENT_BASE:
                command += ["--github-base", CLIENT_BASE]
            bridge = subprocess.Popen(command)
            print("    started tools/bridge.mjs (pid %d)" % bridge.pid, flush=True)
        except FileNotFoundError:
            print("    no node on PATH, so no bridge. Everything else still works;",
                  flush=True)
            print("    signing in to GitHub is the only thing that needs it.", flush=True)
        except OSError as err:
            print("    could not start the bridge: %s" % err, flush=True)

    if OPEN:
        # ?serve boots a machine, serves it and checks it, with nothing to type.
        start = "http://localhost:%d/app/?serve" % PORTS[0]
        print("    opening %s" % start, flush=True)
        threading.Timer(1.0, lambda: webbrowser.open(start)).start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        # The bridge outlives this process otherwise, and the next run then finds
        # port 9000 taken by something it did not start and cannot see.
        if bridge and bridge.poll() is None:
            bridge.terminate()
            try:
                bridge.wait(timeout=5)
            except subprocess.TimeoutExpired:
                bridge.kill()
            print("stopped the bridge")
        for httpd in servers:
            httpd.shutdown()
