// HTTP/1.1 over one of our sockets.
//
// Just enough of the protocol to carry a browser's request into a server in the
// guest and bring the answer back: a request writer, and a response parser that
// is fed bytes as they arrive. The parser is separate from the socket so it can
// be tested against the output of a real HTTP server, which is what the suite
// does -- a hand-written sample of a protocol proves the parser agrees with the
// person who wrote the sample, and nothing more.
//
// Bodies are assembled in memory. A machine served out of a browser tab is not
// the place to stream a gigabyte, and a cap that refuses is better than a tab
// that dies.

const CR = 13, LF = 10;
const DEFAULT_MAX_BODY = 32 * 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Serialise a request.
 *
 * The Host header is not optional in 1.1, and Connection: close is deliberate:
 * one request per connection costs a handshake we can afford on a link with no
 * latency, and it removes every way a pipelined or half-read response can
 * desynchronise the next request on the same socket.
 */
export function encodeRequest({ method = "GET", path = "/", host, headers = {}, body = null }) {
  const lines = [`${method.toUpperCase()} ${path} HTTP/1.1`];
  const sent = new Set();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || value === null) continue;
    sent.add(name.toLowerCase());
    lines.push(`${name}: ${value}`);
  }
  if (!sent.has("host")) lines.push(`Host: ${host}`);
  if (!sent.has("connection")) lines.push("Connection: close");
  const payload = body ? (body instanceof Uint8Array ? body : encoder.encode(String(body))) : null;
  if (payload && !sent.has("content-length")) lines.push(`Content-Length: ${payload.length}`);

  const head = encoder.encode(lines.join("\r\n") + "\r\n\r\n");
  if (!payload) return head;
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

/**
 * An incremental response parser.
 *
 * Feed it whatever arrives. `done` turns true when the response is complete by
 * its own framing; a body delimited by nothing but the connection closing is
 * finished by calling `end()`.
 */
export class ResponseParser {
  constructor({ maxBody = DEFAULT_MAX_BODY } = {}) {
    this.maxBody = maxBody;
    this.status = 0;
    this.statusText = "";
    this.headers = {};
    this.done = false;
    this.error = null;

    this._buffer = new Uint8Array(0);
    this._body = [];
    this._bodyLength = 0;
    this._phase = "head";      // head -> length | chunk-size/data/trailer | close -> done
    this._remaining = 0;
  }

  /** @param {Uint8Array} bytes */
  push(bytes) {
    if (this.done || this.error) return;
    this._buffer = concat(this._buffer, bytes);
    try {
      this._run();
    } catch (err) {
      this.error = err;
    }
  }

  /** The peer closed. Whether that completed the response depends on its framing. */
  end() {
    if (this.done || this.error) return;
    if (this._phase === "close") {
      this._takeBody(this._buffer);
      this._buffer = new Uint8Array(0);
      this.done = true;
      return;
    }
    if (this._phase === "head") {
      this.error = new Error("the guest closed the connection before sending a complete response");
      return;
    }
    this.error = new Error(
      `the guest closed the connection with ${this._remaining} bytes of the body still to come`
    );
  }

  /** The body so far, as one array. */
  body() {
    const out = new Uint8Array(this._bodyLength);
    let at = 0;
    for (const part of this._body) { out.set(part, at); at += part.length; }
    return out;
  }

  _run() {
    for (;;) {
      if (this._phase === "head") {
        const head = findHead(this._buffer);
        if (!head) return;
        this._parseHead(decoder.decode(this._buffer.subarray(0, head.at)));
        this._buffer = this._buffer.subarray(head.at + head.length);
        continue;
      }

      if (this._phase === "length") {
        const take = Math.min(this._remaining, this._buffer.length);
        if (take) {
          this._takeBody(this._buffer.subarray(0, take));
          this._buffer = this._buffer.subarray(take);
          this._remaining -= take;
        }
        if (this._remaining > 0) return;
        this.done = true;
        return;
      }

      if (this._phase === "chunk-size") {
        const line = findLineEnd(this._buffer);
        if (!line) return;
        // A chunk size may carry extensions after a semicolon; they are not ours.
        const text = decoder.decode(this._buffer.subarray(0, line.at)).split(";")[0].trim();
        const size = parseInt(text, 16);
        if (!Number.isInteger(size) || size < 0) throw new Error(`not a chunk size: "${text}"`);
        this._buffer = this._buffer.subarray(line.at + line.length);
        if (size === 0) { this._phase = "trailer"; continue; }
        this._remaining = size;
        this._phase = "chunk-data";
        continue;
      }

      if (this._phase === "trailer") {
        // Trailers may follow the last chunk; the response ends at the blank
        // line after them, or immediately when there are none. This is a phase
        // of its own because the terminator can arrive one byte at a time, and
        // waiting for it while still in chunk-size reads the final CRLF as
        // another chunk header.
        const blank = startsWithNewline(this._buffer);
        if (blank) {
          this._buffer = this._buffer.subarray(blank);
          this.done = true;
          return;
        }
        const trailers = findHead(this._buffer);
        if (!trailers) return;                  // trailers still arriving
        this._buffer = this._buffer.subarray(trailers.at + trailers.length);
        this.done = true;
        return;
      }

      if (this._phase === "chunk-data") {
        // The data, then the line break that closes it -- one byte or two,
        // depending on who wrote it.
        if (this._buffer.length < this._remaining + 1) return;
        const after = this._buffer.subarray(this._remaining);
        const ending = startsWithNewline(after);
        if (!ending) {
          if (after.length < 2) return;                 // a lone CR, still waiting on its LF
          throw new Error("a chunk did not end with a line break");
        }
        this._takeBody(this._buffer.subarray(0, this._remaining));
        this._buffer = this._buffer.subarray(this._remaining + ending);
        this._remaining = 0;
        this._phase = "chunk-size";
        continue;
      }

      return;   // close-delimited: everything is body until end()
    }
  }

  _parseHead(text) {
    const [statusLine, ...headerLines] = text.split(/\r?\n/);
    const match = /^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/.exec(statusLine);
    if (!match) throw new Error(`not an HTTP response: "${statusLine.slice(0, 60)}"`);
    this.status = Number(match[2]);
    this.statusText = match[3] || "";

    for (const line of headerLines) {
      const at = line.indexOf(":");
      if (at < 0) continue;
      const name = line.slice(0, at).trim().toLowerCase();
      const value = line.slice(at + 1).trim();
      // Repeated headers join with a comma, which is what a reader expects for
      // every header where repetition is legal.
      this.headers[name] = name in this.headers ? `${this.headers[name]}, ${value}` : value;
    }

    const encoding = (this.headers["transfer-encoding"] || "").toLowerCase();
    if (encoding.includes("chunked")) {
      this._phase = "chunk-size";
    } else if ("content-length" in this.headers) {
      const length = Number(this.headers["content-length"]);
      if (!Number.isInteger(length) || length < 0) throw new Error("a Content-Length that is not a length");
      this._remaining = length;
      this._phase = "length";
    } else if (this.status === 204 || this.status === 304 || (this.status >= 100 && this.status < 200)) {
      this.done = true;                      // defined to have no body at all
    } else {
      this._phase = "close";
    }
  }

  _takeBody(bytes) {
    if (!bytes.length) return;
    this._bodyLength += bytes.length;
    if (this._bodyLength > this.maxBody) {
      throw new Error(`the response is larger than the ${this.maxBody}-byte cap this tab will hold`);
    }
    this._body.push(new Uint8Array(bytes));
  }
}

/**
 * One request, over one connection, to a port in the guest.
 *
 * @param {import("./stack.js").NetStack} stack
 * @param {Object} options
 * @returns {Promise<{status: number, statusText: string, headers: Object, body: Uint8Array}>}
 */
export async function request(stack, { port = 80, method, path, headers, body, timeoutMs = 30000, maxBody } = {}) {
  const socket = await stack.connect(port, { timeoutMs });
  const parser = new ResponseParser({ maxBody });

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    socket.onData = (bytes) => {
      parser.push(bytes);
      if (parser.error) { socket.destroy(); return finish(reject, parser.error); }
      // A framed response is complete before the connection closes, and waiting
      // for a close the guest may take its time over would add a whole RTT to
      // every request.
      if (parser.done) {
        socket.end();
        finish(resolve, result(parser));
      }
    };
    socket.onEnd = () => {
      parser.end();
      socket.end();
      if (parser.error) return finish(reject, parser.error);
      if (parser.done) return finish(resolve, result(parser));
    };
    socket.onClose = (err) => {
      if (settled) return;
      if (err) return finish(reject, err);
      parser.end();
      if (parser.error) return finish(reject, parser.error);
      if (parser.done) return finish(resolve, result(parser));
      finish(reject, new Error("the connection closed with no response"));
    };

    socket.write(encodeRequest({ method, path, host: stack.peerIp, headers, body }));
  });
}

function result(parser) {
  return {
    status: parser.status,
    statusText: parser.statusText,
    headers: parser.headers,
    body: parser.body()
  };
}


// --- the other direction -----------------------------------------------------
//
// Answering HTTP rather than asking it, so a program inside the guest can drive
// the tab: `wget -qO- http://10.0.2.2/status` from a shell in the VM reaches a
// handler in this page. The shape is deliberately the one a cloud already uses,
// where an instance asks a service on a link-local address about itself.

/** An incremental request parser, the mirror of ResponseParser. */
export class RequestParser {
  constructor({ maxBody = DEFAULT_MAX_BODY } = {}) {
    this.maxBody = maxBody;
    this.method = "";
    this.target = "";
    this.headers = {};
    this.done = false;
    this.error = null;
    this._buffer = new Uint8Array(0);
    this._body = [];
    this._length = 0;
    this._remaining = 0;
    this._phase = "head";
  }

  push(bytes) {
    if (this.done || this.error) return;
    this._buffer = concat(this._buffer, bytes);
    try {
      if (this._phase === "head") {
        const head = findHead(this._buffer);
        if (!head) return;
        this._parseHead(decoder.decode(this._buffer.subarray(0, head.at)));
        this._buffer = this._buffer.subarray(head.at + head.length);
      }
      if (this._phase !== "body") return;
      const take = Math.min(this._remaining, this._buffer.length);
      if (take) {
        this._length += take;
        if (this._length > this.maxBody) throw new Error("the request body is larger than this page will hold");
        this._body.push(this._buffer.subarray(0, take));
        this._buffer = this._buffer.subarray(take);
        this._remaining -= take;
      }
      if (this._remaining === 0) this.done = true;
    } catch (err) {
      this.error = err;
    }
  }

  body() {
    const out = new Uint8Array(this._length);
    let at = 0;
    for (const part of this._body) { out.set(part, at); at += part.length; }
    return out;
  }

  /** The path and query, separated, since a caller wants them apart. */
  get path() { return this.target.split("?")[0]; }
  get query() { return new URLSearchParams(this.target.split("?").slice(1).join("?")); }

  _parseHead(text) {
    const [requestLine, ...headerLines] = text.split(/\r?\n/);
    const match = /^([A-Z]+) (\S+) HTTP\/(\d\.\d)$/.exec(requestLine);
    if (!match) throw new Error(`not an HTTP request: "${requestLine.slice(0, 60)}"`);
    this.method = match[1];
    this.target = match[2];
    for (const line of headerLines) {
      const at = line.indexOf(":");
      if (at < 0) continue;
      this.headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
    }
    const length = Number(this.headers["content-length"] || 0);
    if (!Number.isInteger(length) || length < 0) throw new Error("a Content-Length that is not a length");
    this._remaining = length;
    this._phase = length ? "body" : "done";
    if (!length) this.done = true;
  }
}

/** Serialise a response. */
export function encodeResponse({ status = 200, statusText = "", headers = {}, body = null }) {
  const payload = body === null || body === undefined ? new Uint8Array(0)
    : (body instanceof Uint8Array ? body : encoder.encode(String(body)));
  const lines = [`HTTP/1.1 ${status} ${statusText || reasonFor(status)}`];
  const sent = new Set();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || value === null) continue;
    sent.add(name.toLowerCase());
    lines.push(`${name}: ${value}`);
  }
  if (!sent.has("content-length")) lines.push(`Content-Length: ${payload.length}`);
  if (!sent.has("connection")) lines.push("Connection: close");
  const head = encoder.encode(lines.join("\r\n") + "\r\n\r\n");
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

function reasonFor(status) {
  return ({ 200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request",
            404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error" })[status] || "";
}

/**
 * Answer HTTP on a port, for requests coming from the guest.
 *
 * @param {import("./stack.js").NetStack} stack
 * @param {Object} options
 * @param {number} [options.port]
 * @param {(request: {method: string, path: string, query: URLSearchParams, headers: Object, body: Uint8Array}) => any} options.handler
 *        returns a response object, a string, or a promise of either
 * @returns {{port: number, close: () => void}}
 */
export function serve(stack, { port = 80, handler, maxBody } = {}) {
  if (typeof handler !== "function") throw new Error("a handler is required");

  return stack.listen(port, (socket) => {
    const parser = new RequestParser({ maxBody });
    let answered = false;

    const answer = async () => {
      if (answered) return;
      answered = true;
      let response;
      try {
        const result = await handler({
          method: parser.method, path: parser.path, query: parser.query,
          headers: parser.headers, body: parser.body()
        });
        response = typeof result === "string" || result instanceof Uint8Array
          ? { status: 200, body: result }
          : (result || { status: 204 });
      } catch (err) {
        // The guest is a shell; a readable line is worth more than a status.
        response = { status: 500, headers: { "Content-Type": "text/plain" }, body: `${err.message}\n` };
      }
      socket.write(encodeResponse(response));
      socket.end();
    };

    socket.onData = (bytes) => {
      parser.push(bytes);
      if (parser.error) {
        answered = true;
        socket.write(encodeResponse({ status: 400, body: `${parser.error.message}\n` }));
        socket.end();
        return;
      }
      if (parser.done) answer();
    };
    // A request with no body and no Content-Length is complete at the blank
    // line, but one that ends by closing has to be answered on the close.
    socket.onEnd = () => { if (parser.done) answer(); };
  });
}

// --- bytes -------------------------------------------------------------------

function concat(a, b) {
  if (!a.length) return new Uint8Array(b);
  if (!b.length) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Where a header block ends, and how long its terminator is.
 *
 * CRLF is what the specification says and what a server written to it sends. It
 * is not what everything sends: a CGI script writes its headers with echo, and
 * what reaches the client is separated by bare line feeds. A parser that insists
 * on CRLF reads that as a response whose headers never ended -- which is a
 * confusing way to be told a shell script printed a newline.
 *
 * @returns {{at: number, length: number}|null}
 */
function findHead(bytes) {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === CR && bytes[i + 1] === LF && bytes[i + 2] === CR && bytes[i + 3] === LF) {
      return { at: i, length: 4 };
    }
    if (bytes[i] === LF && bytes[i + 1] === LF) return { at: i, length: 2 };
  }
  return null;
}

/** The offset of the line ending, and its length, or null. */
function findLineEnd(bytes) {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === CR && bytes[i + 1] === LF) return { at: i, length: 2 };
    if (bytes[i] === LF) return { at: i, length: 1 };
  }
  return null;
}

/** The length of a line ending at the start of these bytes, or 0. */
function startsWithNewline(bytes) {
  if (bytes.length >= 2 && bytes[0] === CR && bytes[1] === LF) return 2;
  if (bytes.length >= 1 && bytes[0] === LF) return 1;
  return 0;
}
