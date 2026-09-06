// The command the user types inside the machine.
//
// A program in the guest cannot call a function in the page, but it can open a
// socket, and the tab is on the other end of the only network the guest has. So
// the tab answers HTTP on its own address and the guest gets a one-file client
// for it. The arrangement is the one a cloud already uses: an instance asks a
// service on a fixed local address about itself, and about what the platform
// should do next on its behalf.
//
// The script goes in over the 9p share and onto the machine's disk, like every
// other binary, which means it is part of the machine: restore that machine
// somewhere else and its commands come back with it.

export const NAME = "rrd";
export const HOST = "10.0.2.2";

/**
 * The web server, by path.
 *
 * Publishing reads the site over it, so it has to be up -- and the machine can
 * see that for itself and start it again without involving the tab, which is
 * better than asking the tab to run a command in the shell this script is
 * holding.
 */
export const SERVER = "/disk/usr/local/bin/busybox httpd";

/**
 * The client, as a shell script.
 *
 * Written against busybox wget and nothing else, because that is what the
 * images this project boots actually have. No curl, no jq, no bash.
 */
export const SCRIPT = `#!/bin/sh
# rrd -- talk to the browser tab this machine runs in.
h=\${RRD_HOST:-${HOST}}
ask() { wget -T 30 -qO- "http://$h$1" || { echo "rrd: no answer from the tab" >&2; exit 1; }; }
enc() { echo "$*" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/&/%26/g' -e 's/?/%3F/g' -e 's/#/%23/g'; }
c=$1
[ $# -gt 0 ] && shift
case "$c" in
"" | help) ask /help ;;
status) ask /status ;;
url) ask /url ;;
unserve) ask /unserve ;;
serve) ask "/serve?dir=$(enc "\${1:-/disk/www}")" ;;
sync) ask "/sync?message=$(enc "$*")" ;;
publish)
  d=$(ask /where | tr -d '\\r\\n')
  [ -n "$d" ] || exit 1
  wget -T 3 -q -O /dev/null http://127.0.0.1/ 2>/dev/null || ${SERVER} -p 80 -h "$d"
  find "$d" -type f | sed -e "s|^$d/||" | grep -v '^\\.rrd-manifest$' > "$d/.rrd-manifest"
  ask "/publish?message=$(enc "$*")"
  ;;
*) echo "rrd: no such command: $c" >&2; echo "try: rrd help" >&2; exit 1 ;;
esac
`;

/**
 * Put the script in the transfer share, ready to be installed.
 *
 * Separate from installing it because of when it has to happen. Handing v86 a
 * file makes the guest reattach the 9p share and announce it on the console, and
 * that announcement lands whenever it lands -- in the middle of a command being
 * echoed, if one is in flight, which cuts the command in half and leaves the
 * caller waiting for an exit status that never comes. So every file a machine
 * needs goes across at once, before any command is sent, and the console is
 * given a moment to fall quiet afterwards.
 */
export async function stage(emulator, name = NAME) {
  await emulator.create_file(name, new TextEncoder().encode(SCRIPT));
  return name;
}

/**
 * Copy the staged script onto the machine's disk and put it on PATH.
 *
 * @param {Object} options
 * @param {(command: string, options?: Object) => Promise<string>} options.run
 * @param {Object} options.fs the guest/fs module
 */
export async function install({ run, fs, name = NAME, profile = null }) {
  const installed = await fs.install(run, { name });
  // The profile goes on the disk, not in the guest's home. The root filesystem
  // is a read-only CD with everything writable held in memory, so a profile
  // written to /root is gone the moment the guest re-initialises -- and with it
  // the PATH that makes this command findable by name.
  await fs.ensureOnPath(run, { profile: profile || `${fs.MOUNTPOINT}/.profile` });
  return installed;
}
