// Making the terminal panel type into a demo's own machine.
//
// The panel's own key handling lives in app.js and sends to the emulator that
// app.js booted. A demo builds its own emulator and app.js knows nothing about
// it, so with no boot from the UI there is nothing behind the panel: keystrokes
// go to a handler that checks for an emulator, finds none, and returns. The
// terminal looks alive because output is being written to it, and typing does
// nothing at all.
//
// This attaches a second handler, bound to the demo's emulator. app.js's handler
// still runs and still returns early, so the two do not fight.

import { keyToBytes, pasteNeedsConfirming, textToBytes } from "../src/ui/keyboard.js";

/**
 * @param {Object} emulator the demo's V86
 * @param {Element} [element] the terminal, by default the panel in /app/
 * @returns {() => void} detach
 */
export function attachKeyboard(emulator, element = document.getElementById("term")) {
  if (!emulator) throw new Error("an emulator is required");
  if (!element) throw new Error("no terminal element to attach to");

  const send = (bytes) => {
    if (!bytes || !bytes.length) return;
    if (typeof emulator.serial_send_bytes === "function") {
      emulator.serial_send_bytes(0, new Uint8Array(bytes));
    } else {
      emulator.serial0_send(String.fromCharCode(...bytes));
    }
  };

  const onKey = (event) => {
    const bytes = keyToBytes(event);
    if (!bytes) return;              // let the browser keep its own shortcuts
    event.preventDefault();
    send(bytes);
  };

  const onPaste = (event) => {
    event.preventDefault();
    const text = event.clipboardData.getData("text");
    if (!text) return;
    // A paste carrying a newline runs a line the user has not read. Ask first,
    // the same as the app does.
    if (pasteNeedsConfirming(text) && !confirm(`Run ${text.trim().split("\n").length} lines in the guest?`)) return;
    send(textToBytes(text));
  };

  element.addEventListener("keydown", onKey);
  element.addEventListener("paste", onPaste);
  if (!element.hasAttribute("tabindex")) element.setAttribute("tabindex", "0");
  element.focus();

  return () => {
    element.removeEventListener("keydown", onKey);
    element.removeEventListener("paste", onPaste);
  };
}
