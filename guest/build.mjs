// Build the guest's initramfs.
//
// A cpio archive and a gzip, which is all an initramfs is. No compiler, no
// buildroot, no toolchain: the kernel is v86's own and the userland is one
// static busybox with an init script beside it.
//
// The archive is written here rather than by the cpio tool because writing it is
// twelve lines and depending on a tool that is not on every machine is a
// reproducibility problem this repository already has opinions about.
//
//   node guest/build.mjs
//
// Produces guest/initramfs.cpio.gz.

import { readFileSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const BUSYBOX = join(here, "..", "vendor", "busybox", "busybox-1.35.0-i686");

const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;
const S_IFCHR = 0o020000;

/** One newc entry: a fixed header of hex fields, then the name, then the data. */
function entry({ name, mode, data = Buffer.alloc(0), rdev = [0, 0], ino }) {
  const hex = (n) => n.toString(16).padStart(8, "0");
  const header =
    "070701" +
    hex(ino) + hex(mode) + hex(0) + hex(0) + hex(1) + hex(0) +
    hex(data.length) + hex(0) + hex(0) + hex(rdev[0]) + hex(rdev[1]) +
    hex(name.length + 1) + hex(0);

  const parts = [Buffer.from(header, "ascii"), Buffer.from(name + "\0", "ascii")];
  parts.push(pad(header.length + name.length + 1));
  parts.push(data);
  parts.push(pad(data.length));
  return Buffer.concat(parts);
}

/** newc aligns the name and the data to four bytes each. */
function pad(length) {
  return Buffer.alloc((4 - (length % 4)) % 4);
}

const files = [];
let ino = 1;
const dir = (name) => files.push(entry({ name, mode: S_IFDIR | 0o755, ino: ino++ }));
const file = (name, data, mode = 0o644) =>
  files.push(entry({ name, mode: S_IFREG | mode, data, ino: ino++ }));
const device = (name, major, minor, mode = 0o600) =>
  files.push(entry({ name, mode: S_IFCHR | mode, rdev: [major, minor], ino: ino++ }));

dir(".");
dir("bin");
file("bin/busybox", readFileSync(BUSYBOX), 0o755);
file("init", readFileSync(join(here, "init")), 0o755);

// The kernel opens /dev/console for init's own output, before anything has had a
// chance to mount devtmpfs. These three have to be in the archive itself.
dir("dev");
device("dev/console", 5, 1);
device("dev/ttyS0", 4, 64);
device("dev/null", 1, 3, 0o666);

for (const name of ["proc", "sys", "tmp", "root", "mnt", "disk", "usr", "usr/bin", "sbin", "usr/sbin"]) {
  dir(name);
}

files.push(entry({ name: "TRAILER!!!", mode: 0, ino: 0 }));

const archive = Buffer.concat(files);
const gz = gzipSync(archive, { level: 9 });
const out = join(here, "initramfs.cpio.gz");
writeFileSync(out, gz);

console.log(`${out}`);
console.log(`  ${files.length - 1} entries, ${archive.length} bytes, ${gz.length} gzipped`);
