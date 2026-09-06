// A site that is not a set of files.
//
// Serving a directory shows that a machine can hand over what it already has.
// This shows the other half: a request arrives, a program in the guest runs, and
// what comes back did not exist until it was asked for. The proof is in the
// page -- the process id changes on every request, and the clock is the guest's.
//
// It is CGI, which busybox httpd speaks and which needs nothing installed. The
// form uses GET on purpose: a form submission is a top-level navigation, and a
// top-level navigation is the one thing a service worker still controls when a
// machine has to share the app's origin behind a sandbox. So this stays dynamic
// even in the arrangement where a site's stylesheet would not load.
//
// Everything is one self-contained document for the same reason: inline styles,
// no scripts, no separate assets. What survives the narrower arrangement also
// works in the wider one.

import { rc } from "../src/guest/fs.js";

/** Written to the served directory. The CGI is the only one made executable. */
export const CGI = "cgi-bin/process.cgi";

const STYLE =
  "body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:64ch;" +
  "margin:6vh auto;padding:0 20px;background:#EFF2F1;color:#131C1A}" +
  "h1{font-size:20px;margin:0 0 4px}p.sub{color:#4A5754;margin:0 0 22px}" +
  "form{background:#FBFCFC;border:1px solid #D1D9D6;border-radius:5px;padding:18px}" +
  "label{display:block;font-size:12px;letter-spacing:.08em;text-transform:uppercase;" +
  "color:#6E7C78;margin:0 0 5px}input{font:inherit;width:100%;box-sizing:border-box;" +
  "padding:9px 11px;border:1px solid #D1D9D6;border-radius:4px;background:#EFF2F1;color:#131C1A}" +
  "input+label{margin-top:16px}button{font:inherit;margin-top:16px;background:#14685A;" +
  "color:#EFF2F1;border:0;border-radius:4px;padding:9px 18px;cursor:pointer}" +
  "table{border-collapse:collapse;width:100%;margin-top:8px}" +
  "td{padding:6px 0;border-bottom:1px solid #E1E7E5;vertical-align:top}" +
  "td.k{color:#6E7C78;width:15ch;padding-right:12px}" +
  "footer{margin-top:26px;color:#6E7C78;font-size:12px}" +
  "a{color:#14685A}" +
  "@media(prefers-color-scheme:dark){body{background:#0D1412;color:#E1E9E6}" +
  "p.sub,td.k,footer{color:#7E8C88}form{background:#141D1A;border-color:#263330}" +
  "input{background:#0D1412;color:#E1E9E6;border-color:#263330}td{border-color:#1E2A27}" +
  "button{background:#55C4A6;color:#0D1412}a{color:#55C4A6}}";

const FORM =
  '<form action="cgi-bin/process.cgi" method="get">' +
  '<label for="text">Some text</label>' +
  '<input id="text" name="text" value="Repo as Root Disk" autofocus>' +
  '<label for="calc">And a sum</label>' +
  '<input id="calc" name="calc" value="(2+3)*7">' +
  '<button type="submit">Send it to the machine</button>' +
  "</form>";

export const INDEX =
  "<!doctype html><meta charset=utf-8><title>A dynamic machine</title>" +
  // Inline, so the page is legible however it is being served -- and linked as
  // well, so it says which of the two arrangements it got. A machine on an
  // origin of its own loads both; one sharing the app's origin loads neither,
  // and the form below still works either way.
  "<style>" + STYLE + "</style>" +
  '<link rel=stylesheet href="style.css">' +
  "<h1>This page is a file. The next one will not be.</h1>" +
  '<p class="sub">Submitting runs a program inside the virtual machine and returns ' +
  "what it produced. Nothing between here and there is a server: the request crosses " +
  "a TCP stack written in JavaScript, in the tab next to this one.</p>" +
  FORM +
  '<footer id="probe">Served by busybox httpd from the machine&rsquo;s own disk. ' +
  "This machine&rsquo;s stylesheet and script have not loaded, so it is sharing the " +
  "app&rsquo;s origin behind a sandbox: the form still works, the assets do not.</footer>" +
  '<script src="app.js"></script>';

/**
 * The backend.
 *
 * Percent-decoding is done by busybox itself -- `httpd -d` exists for exactly
 * this and is right about the cases a sed pipeline gets wrong. The sum is
 * filtered down to arithmetic before anything evaluates it, because a query
 * string is input from outside and this is a shell.
 *
 * Reversing is done with awk rather than `rev`, which this busybox does not
 * have: an applet missing from a build is not an error, it is just a column
 * that comes back empty, which is the kind of thing only a real request shows.
 */
export const SCRIPT = `#!/bin/sh
BB=/disk/usr/local/bin/busybox
field() { echo "$QUERY_STRING" | tr '&' '\\n' | grep "^$1=" | head -n 1 | cut -d= -f2-; }
decode() { $BB httpd -d "$(printf '%s' "$1" | tr '+' ' ')"; }

text=$(decode "$(field text)")
calc=$(decode "$(field calc)")
safe=$(printf '%s' "$calc" | tr -cd '0-9+*/(). -')
sum=$(awk "BEGIN{printf \\"%.10g\\", $safe}" 2>/dev/null || echo "not a sum")

echo "Content-Type: text/html; charset=utf-8"
echo "Cache-Control: no-store"
echo
echo "<!doctype html><meta charset=utf-8><title>Processed in the machine</title>"
echo "<style>"
cat /disk/www/inline.css 2>/dev/null
echo "</style>"
echo "<h1>Processed inside the virtual machine</h1>"
echo "<p class=sub>This page did not exist until you asked for it.</p>"
echo "<table>"
echo "<tr><td class=k>you sent</td><td>$text</td></tr>"
echo "<tr><td class=k>upper case</td><td>$(printf '%s' "$text" | tr 'a-z' 'A-Z')</td></tr>"
echo "<tr><td class=k>reversed</td><td>$(printf '%s' "$text" | awk '{for(i=length($0);i>0;i--)printf "%s",substr($0,i,1)}')</td></tr>"
echo "<tr><td class=k>characters</td><td>$(printf '%s' "$text" | wc -c)</td></tr>"
echo "<tr><td class=k>words</td><td>$(printf '%s' "$text" | wc -w)</td></tr>"
echo "<tr><td class=k>sha256</td><td>$(printf '%s' "$text" | sha256sum | cut -c1-32)</td></tr>"
echo "<tr><td class=k>$calc</td><td>$sum</td></tr>"
echo "</table>"
echo "<table>"
echo "<tr><td class=k>ran as pid</td><td>$$ &mdash; a new one every request</td></tr>"
echo "<tr><td class=k>guest clock</td><td>$(date)</td></tr>"
echo "<tr><td class=k>uptime</td><td>$(uptime | sed 's/^ *//')</td></tr>"
echo "<tr><td class=k>kernel</td><td>$(uname -srm)</td></tr>"
echo "</table>"
echo "<footer><a href=\\"../index.html\\">Send something else</a> &middot; this ran in the guest, not in the browser</footer>"
`;

/**
 * Write the site onto the machine's disk.
 *
 * A few lines per command rather than one long one: the guest talks over the
 * same console these commands travel on, and a line it interrupts is a line that
 * never runs.
 */
export async function install(run, { directory, timeoutMs = 40000 } = {}) {
  if (!directory) throw new Error("a directory to write the site into is required");
  await rc(run, `mkdir -p ${directory}/cgi-bin`, timeoutMs);

  // The stylesheet as a file the backend can read. Inlining it in the script
  // instead would put a fifteen-hundred-character line in it, and a line is the
  // unit a command is cut into: no amount of splitting the script by lines makes
  // one long line short enough to survive the guest talking over it.
  const stylePath = `${directory}/inline.css`;
  for (let at = 0; at < STYLE.length; at += 180) {
    const piece = STYLE.slice(at, at + 180);
    const written = await rc(run,
      `printf '%s' '${quote(piece)}' ${at === 0 ? ">" : ">>"} ${stylePath}`, timeoutMs);
    if (!written.ok) throw new Error(`could not write ${stylePath}`);
  }

  // In pieces. One command carrying two kilobytes of markup is one command for
  // the guest's own console chatter to land in the middle of, and a line cut in
  // half never runs at all.
  const indexPath = `${directory}/index.html`;
  for (let at = 0; at < INDEX.length; at += 180) {
    const piece = INDEX.slice(at, at + 180);
    const redirect = at === 0 ? ">" : ">>";
    const written = await rc(run, `printf '%s' '${quote(piece)}' ${redirect} ${indexPath}`, timeoutMs);
    if (!written.ok) throw new Error(`could not write ${indexPath}: ${written.output.trim()}`);
  }

  const path = `${directory}/${CGI}`;
  const lines = SCRIPT.replace(/\n$/, "").split("\n");
  for (let at = 0; at < lines.length; at += 3) {
    const chunk = lines.slice(at, at + 3).map((line) => `'${quote(line)}'`).join(" ");
    const wrote = await rc(run, `printf '%s\\n' ${chunk} ${at === 0 ? ">" : ">>"} ${path}`, timeoutMs);
    if (!wrote.ok) throw new Error(`could not write ${path}: ${wrote.output.trim()}`);
  }
  const marked = await rc(run, `chmod +x ${path}`, timeoutMs);
  if (!marked.ok) throw new Error(`could not make ${path} executable`);

  return { index: indexPath, cgi: path, style: stylePath };
}

/** Escape for a single-quoted shell string: end the quoting, emit a quote, resume. */
function quote(text) {
  return String(text).replace(/'/g, "'\\''");
}
