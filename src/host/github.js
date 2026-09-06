// GitHub: the only host of the three with low-level git object writes, and
// consequently the most expensive for this workload.
//
// A commit costs N+3 requests: one blob per new object, then a tree, a commit,
// and a reference update. The measured end-to-end loop was nine requests and
// 5.1 seconds. Compaction of a 94%-full 256 MB machine needs 945 requests, which
// at the enforced 180 writes per minute is 5.3 minutes against 2.8 minutes of
// bandwidth, so it is the one workload here that a rate limit actually bounds.
//
// What GitHub gives in return is the two capabilities the batch-commit hosts
// lack: parentless commits, which compaction needs, and fast-forward-only
// reference updates, which are a real compare-and-swap. A stale parent is
// rejected with 422 every time.

import { Host, toBase64 } from "./adapter.js";

export class GitHubHost extends Host {
  static get defaultEndpoint() { return "https://api.github.com"; }

  static get capabilities() {
    return {
      orphanCommit: true,
      casRef: true,
      batchCommit: false,
      maxBodyBytes: 100 * 1024 * 1024
    };
  }

  authHeaders() {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    };
  }

  base(suffix = "") {
    return `/repos/${this.owner}/${this.repo}${suffix}`;
  }

  async validate() {
    const user = await this.request("GET", "/user");
    const repo = await this.request("GET", this.base());
    return {
      login: user.login,
      private: !!repo.private,
      canWrite: !!(repo.permissions && repo.permissions.push)
    };
  }

  async resolveRef(branch) {
    try {
      const ref = await this.request("GET", this.base(`/git/ref/heads/${branch}`));
      const commit = await this.request("GET", this.base(`/git/commits/${ref.object.sha}`));
      return { commit: ref.object.sha, tree: commit.tree.sha };
    } catch (err) {
      // A branch that is not there is a 404. A repository with nothing in it at
      // all is a 409, "Git Repository is empty" -- which is the state every
      // repository starts in, and therefore the state the first publish to one
      // meets. Both mean the same thing to a caller: there is no previous commit
      // to build on.
      if (err.status === 404 || err.status === 409) return null;
      throw err;
    }
  }

  async readCommit(id) {
    const commit = await this.request("GET", this.base(`/git/commits/${id}`));
    return {
      commit: id,
      tree: commit.tree.sha,
      parents: (commit.parents || []).map((p) => p.sha),
      message: commit.message
    };
  }

  async history(branch, { limit = 100 } = {}) {
    const list = await this.request(
      "GET", this.base(`/commits?sha=${encodeURIComponent(branch)}&per_page=${limit}`)
    );
    return list.map((entry) => ({
      commit: entry.sha,
      message: (entry.commit && entry.commit.message) || "",
      when: entry.commit && entry.commit.committer && entry.commit.committer.date
    }));
  }

  async createRef(ref, commit) {
    const created = await this.request("POST", this.base("/git/refs"), {
      body: { ref, sha: commit }
    });
    return created.ref || ref;
  }

  async readTree(treeSha) {
    const tree = await this.request("GET", this.base(`/git/trees/${treeSha}?recursive=1`));
    return tree.tree
      .filter((entry) => entry.type === "blob")
      .map((entry) => ({ path: entry.path, id: entry.sha, size: entry.size || 0 }));
  }

  async readObject(id) {
    // The default media type returns base64 inside JSON and inflates a 65,536
    // byte blob to 90,615. Asking for raw is worth 17% on the read path, which
    // matters most on private repositories where the CDN is unavailable and
    // every read goes through here.
    return this.request("GET", this.base(`/git/blobs/${id}`), {
      headers: { Accept: "application/vnd.github.raw" },
      binary: true
    });
  }

  /**
   * Commit, seeding the repository first if it has never had one.
   *
   * A repository with no commits at all refuses every write to the git data
   * API -- blobs included -- with 409 "Git Repository is empty". That is the
   * state every new repository starts in, so it is the state the first publish
   * to one meets, and telling somebody to go and add a README by hand is a poor
   * answer. The contents API does work on an empty repository, so one file goes
   * in that way and the ordinary path takes it from there.
   */
  async commit(options) {
    try {
      return await this._commit(options);
    } catch (err) {
      if (err.status !== 409 || !/empty/i.test(err.message)) throw err;
      if (!options.files || !options.files.length) throw err;
      await this._seed(options.branch, options.files[0], options.message);
      const head = await this.resolveRef(options.branch);
      const result = await this._commit({
        ...options, parent: head ? head.commit : null, branchExists: !!head
      });
      // The seed is a commit too, and a caller counting requests should see it.
      return { ...result, requests: result.requests + 1, seeded: true };
    }
  }

  /** One file, through the API that works on a repository with no commits. */
  async _seed(branch, file, message) {
    await this.governed(() =>
      this.request("PUT", this.base(`/contents/${encodeURI(file.path)}`), {
        body: {
          message: `${message || "publish"} (first commit)`,
          content: toBase64(file.bytes),
          branch
        }
      })
    );
  }

  async _commit({ branch, message, files, parent = null, orphan = false, branchExists }) {
    const before = this.requestCount;
    const toUpload = files.filter((f) => !f.skipUpload);

    await this.governedAll(
      toUpload.map((file) => async () => {
        const result = await this.request("POST", this.base("/git/blobs"), {
          body: { content: toBase64(file.bytes), encoding: "base64" }
        });
        if (file.id && result.sha !== file.id) {
          throw new Error(
            `object id mismatch for ${file.path}: computed ${file.id}, server ${result.sha}`
          );
        }
        file.id = result.sha;
        return result.sha;
      })
    );

    const tree = await this.governed(() =>
      this.request("POST", this.base("/git/trees"), {
        body: {
          tree: files.map((f) => ({
            path: f.path, mode: "100644", type: "blob", sha: f.id
          }))
        }
      })
    );

    const commit = await this.governed(() =>
      this.request("POST", this.base("/git/commits"), {
        body: {
          message,
          tree: tree.sha,
          parents: orphan || !parent ? [] : [parent]
        }
      })
    );

    // Whether the branch exists is already known to the caller, which resolved
    // the ref to obtain `parent`. Probing for it here would cost an extra
    // request per commit and make the cost N+4 rather than the N+3 the
    // portability comparison reports.
    const existing = branchExists !== undefined ? branchExists : parent !== null;
    if (existing) {
      // force is correct only when deliberately discarding history. Otherwise
      // force:false gives fast-forward-only semantics, which is the
      // compare-and-swap P7 depends on: a rejection means someone moved first.
      await this.governed(() =>
        this.request("PATCH", this.base(`/git/refs/heads/${branch}`), {
          body: { sha: commit.sha, force: !!orphan }
        })
      );
    } else {
      await this.governed(() =>
        this.request("POST", this.base("/git/refs"), {
          body: { ref: `refs/heads/${branch}`, sha: commit.sha }
        })
      );
    }

    return { commit: commit.sha, requests: this.requestCount - before };
  }

}
