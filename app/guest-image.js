// How a machine boots.
//
// A kernel and an initramfs, rather than a CD with somebody else's userland on
// it. The kernel is the one the vendored ISO carried; the userland is ours, and
// it is one static busybox and an init script that mounts the share once and
// then leaves the machine alone.
//
// That last part is the whole reason this exists. The image this project used to
// boot retried its 9p mount for as long as it ran, and every attempt printed into
// the one channel commands travel over and took the disk, the guest's address and
// any running server down with it. The bounded runner, the state restorer and the
// self-healing serve path were all written to survive that. An image that does
// not do it needs none of them.
//
// What the new image brings, measured on a boot: a shell in about five seconds,
// 9p already mounted at /mnt, eth0 already addressed, loopback up, /dev/sda
// present, and busybox with 402 applets including httpd -- so a machine no longer
// has to be told its own address, and no longer has to have a web server smuggled
// onto it before it can serve anything.

export const KERNEL = "../guest/bzimage-linux4.bin";
export const INITRD = "../guest/initramfs.cpio.gz";

/**
 * `quiet` matters more than it looks. This kernel prints to the serial line, and
 * a message arriving after the shell's prompt leaves a caller watching for that
 * prompt looking at a line about a mouse.
 */
export const CMDLINE = "console=ttyS0 quiet loglevel=1 tsc=reliable";

/** The v86 options a machine boots with, minus the disk, which differs by caller. */
export function bootOptions({ root = "..", screen, bios = "../spike-c/bios" } = {}) {
  return {
    wasm_path: `${root}/vendor/v86/v86.wasm`,
    memory_size: 128 * 1024 * 1024,
    vga_memory_size: 2 * 1024 * 1024,
    screen_container: screen,
    bios: { url: `${bios}/seabios.bin` },
    vga_bios: { url: `${bios}/vgabios.bin` },
    bzimage: { url: KERNEL },
    initrd: { url: INITRD },
    cmdline: CMDLINE,
    // The card with nothing on the other end of it but the tab, and the share
    // that bytes get in through.
    net_device: { type: "ne2k" },
    filesystem: {},
    autostart: true, disable_keyboard: true, disable_mouse: true
  };
}
