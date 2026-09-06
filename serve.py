#!/usr/bin/env python3
"""Static file server with HTTP Range support, rooted at the project.

python -m http.server ignores Range and returns 200 with the whole file.
v86's AsyncXHRBuffer streams a disk image with `Range: bytes=...`, so the
async-buffer test needs a server that answers 206 properly.

    python serve.py [port ...]    default 8000 8001
    python serve.py --open        the same, and open a machine in a browser

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
import os
import re
import socketserver
import sys
import threading
import webbrowser

ARGS = [a for a in sys.argv[1:] if a != "--open"]
OPEN = "--open" in sys.argv[1:]
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
    servers = [Server(("127.0.0.1", port), RangeHandler) for port in PORTS]

    print("serving %s with Range support" % os.getcwd(), flush=True)
    for index, port in enumerate(PORTS):
        role = "the app" if index == 0 else "machines"
        print("    http://localhost:%d/    %s" % (port, role), flush=True)

    # One process, one port each. They serve the same files; only the origin
    # differs, which is the entire reason there is more than one.
    for httpd in servers[1:]:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

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
        for httpd in servers:
            httpd.shutdown()
