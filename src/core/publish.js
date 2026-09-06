// Publishing a site as a tree, next to the disk it was built on.
//
// The machine's disk is chunks: opaque blocks whose names are content hashes and
// whose contents mean nothing without the manifest that orders them. That is the
// right shape for a disk and the wrong shape for a website, because no static
// host will serve it. A site published from a machine goes to its own ref as
// ordinary blobs under ordinary paths, which is a shape every host already
// understands -- so a page anyone can open costs a commit, not a server.
//
// Two lanes, one repository. The disk lane records what a machine is; this one
// records what it published. They never share a ref: a host that serves a branch
// as a website would otherwise be serving the disk's chunks as one too.
//
// Nothing here talks to a guest. What arrives is bytes and paths, whoever
// collected them, which is what makes the whole of it testable without a virtual
// machine anywhere.

import { blobId } from "./objectid.js";

/** Files that make a directory listing into a website. */
const INDEX = "index.html";

/**
 * Commit a set of files to a ref of their own.
 *
 * @param {Object} options
 * @param {Object} options.host a Host, which need not be the machine's own
 * @param {string} options.branch the ref to publish to
 * @param {Array<{path: string, bytes: Uint8Array}>} options.files
 * @param {string} [options.message]
 * @param {boolean} [options.orphan] replace the ref's history rather than adding to it
 * @param {(event: Object) => void} [options.onEvent]
 * @returns {Promise<{commit: string, files: number, bytes: number, requests: number, branch: string}>}
 */
export async function publish({
  host, branch, files, message = null, orphan = false, onEvent = () => {}
} = {}) {
  if (!host) throw new Error("a host is required");
  if (!branch) throw new Error("a branch to publish to is required");
  const prepared = prepare(files);

  if (!prepared.length) {
    throw new Error(
      "there is nothing to publish. The directory held no files, or none that " +
      "could be read."
    );
  }

  // Name every blob before handing it over. Hosts differ in what they do with
  // an id -- one checks the id it computed against the one the server returned,
  // another stores by it -- and a file with no id is the kind of thing that
  // works on one host and quietly publishes the wrong bytes on the next.
  for (const file of prepared) file.id = await blobId(file.bytes);

  const existing = await host.resolveRef(branch);
  onEvent({ type: "publishing", branch, files: prepared.length, existing: !!existing });

  const bytes = prepared.reduce((total, file) => total + file.bytes.length, 0);
  const result = await host.commit({
    branch,
    message: message || `publish ${prepared.length} files`,
    files: prepared,
    parent: existing ? existing.commit : null,
    branchExists: !!existing,
    orphan
  });

  onEvent({ type: "published", branch, commit: result.commit, files: prepared.length, bytes });
  return {
    branch,
    commit: result.commit,
    files: prepared.length,
    bytes,
    requests: result.requests === undefined ? null : result.requests
  };
}

/**
 * Put a collected site in order, and refuse the shapes that would publish badly.
 *
 * A path is normalised rather than rejected wherever normalising is
 * unambiguous, because the difference between "www/index.html" and
 * "/www/index.html" is not something a person should have to think about. What
 * is refused is what would silently publish the wrong thing: a path that climbs
 * out of the site, a duplicate, an empty name.
 */
export function prepare(files) {
  if (!Array.isArray(files)) throw new Error("files must be an array");
  const seen = new Set();
  const prepared = [];

  for (const file of files) {
    if (!file || typeof file.path !== "string") throw new Error("every file needs a path");
    const path = normalise(file.path);
    if (!path) throw new Error(`not a usable path: ${JSON.stringify(file.path)}`);
    if (path.split("/").includes("..")) {
      throw new Error(`${file.path} climbs out of the site, which is never what was meant`);
    }
    if (seen.has(path)) throw new Error(`${path} was collected twice`);
    seen.add(path);

    const bytes = file.bytes instanceof Uint8Array ? file.bytes : new Uint8Array(file.bytes || []);
    prepared.push({ path, bytes });
  }

  // Sorted, so the same site publishes to the same tree whatever order it was
  // collected in, and a diff between two publishes is about the site.
  return prepared.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Strip leading slashes and dot segments; collapse doubled separators. */
function normalise(path) {
  return String(path)
    .replace(/\\/g, "/")
    .split("/")
    .filter((part) => part !== "" && part !== ".")
    .join("/");
}

/**
 * Whether a published site will actually appear when its root is opened.
 *
 * Not an error, because a site of one page named something else is a site, and
 * a host may be configured for it. It is worth saying, though: the commonest way
 * to publish something that looks broken is to publish it without an index.
 */
export function missingIndex(files) {
  const paths = prepare(files).map((file) => file.path);
  if (paths.includes(INDEX)) return null;
  const candidate = paths.find((path) => path.endsWith(`/${INDEX}`));
  return candidate
    ? `there is no ${INDEX} at the top level, though ${candidate} exists: ` +
      `publishing from one directory further down would put it at the root`
    : `there is no ${INDEX}, so opening the site's root will not show a page`;
}
