# Supply chain, secrets and licensing — design

**Date:** 2026-11-16
**Status:** ready to implement
**Covers:** B1–B5 of `2026-11-16-rebaseline-design.md`

---

## 1. The issues

| # | Issue | Severity |
|---|-------|----------|
| B1 | The `xray` worker image builds from a **69 MB binary committed to git**. | S2 |
| B2 | Development credentials are committed in `deploy/*.ini` and in the Compose file. | S2 |
| B3 | `admin` / `TailnetAdmin2026!` appear in the transcript. | S2 |
| B4 | `B-Hunters-Playground` is unmodified: a committed `.env` with credentials and a **public** artefact-bucket policy. | S2 |
| B5 | **No licence in any of the 19 repositories**, while shipping GPL-2 (`nmap`, `dirsearch`, `wapiti`) and AGPL-3 (`xray`) tools. | S2 |

---

## 2. B1 — the committed xray binary

**Today.** `B-Hunters-xray/Dockerfile` copies a 69 MB xray binary out of the
repository.

**Why it matters.** The binary's provenance cannot be checked, the build is
not reproducible, and the repository carries an executable that anyone can
run. It is also the largest object in the organisation by two orders of
magnitude.

**The fix.** Fetch the release at build time from a pinned version, and
verify it against a published checksum.

```dockerfile
ARG XRAY_VERSION=2.1.9
ARG XRAY_SHA256=<the checksum of the release asset>

RUN set -eux; \
    curl -fsSL -o /tmp/xray \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"; \
    echo "${XRAY_SHA256}  /tmp/xray" | sha256sum -c -; \
    unzip -p /tmp/xray xray > /usr/local/bin/xray; \
    chmod 0755 /usr/local/bin/xray; \
    rm -f /tmp/xray
```

The checksum is the point: without it the build is a download of unknown
content. It is recorded in the Dockerfile next to the version it belongs to,
and a test fails when the two disagree.

**Also.** The binary is removed from git history only if the organisation
decides to rewrite history — a separate, risky operation. The practical
mitigation is to stop shipping it forward and to rotate anything that
treated the repository as trusted.

---

## 3. B2 and B3 — the credentials

**B2.** `deploy/b-hunters.ini` and `deploy/platform.ini` carry
`bhunter_dev_pw` and `bhunter_dev_secret`. Both files are already labelled
*"This is the **example**. The real file is written from the environment by
`scripts/render_config.py` and is not in the repository"* — but the example
is committed with **working** values, so a deployment that copies it
unchanged runs with credentials that are in git.

**The fix.**

1. The committed examples carry placeholders that cannot work:
   `password = CHANGE_ME`, `secret_key = CHANGE_ME`.
2. `scripts/render_config.py` refuses to render a configuration whose
   password equals the example's placeholder.
3. The Compose file reads every secret from the environment and fails fast
   when one is missing, rather than falling back to a default.

**B3.** `admin` / `TailnetAdmin2026!` appear in a transcript, which is
committed. A credential in a transcript is a public credential.

**The fix.** Rotate the credential, and add the transcript to the ignore
list or to the redaction pass that writes it. If a transcript is evidence
that must be kept, the credential is rotated — it is not redacted in place,
because the same value works everywhere it was used.

---

## 4. B4 — the Playground repository

`B-Hunters-Playground` is the reference deployment that a new operator
copies. It is unmodified and it still carries:

* a committed `.env` with `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`,
  `REDIS_PASS`, `MONGO_USER`, `MONGO_PASS`;
* `mc policy set public myminio/recon` — a bucket readable by anyone who
  learns the address.

**The fix.**

* `.env` becomes `.env.example` with placeholders; the real `.env` is
  ignored.
* The bucket policy becomes `private`. The platform reads the bucket
  through the MinIO API with credentials; nothing reads it anonymously.
* The Redis and Mongo ports are not published to the host, or are published
  to loopback only.

This is a separate repository and a separate pull request from the rest of
this spec, because it has its own history and its own consumers.

---

## 5. B5 — the licences

**The facts.** None of the 19 repositories carries a licence file, and the
GitHub API reports `license: null` for every one. `setup.py` in the
framework repository advertises `License :: OSI Approved :: BSD License` in
its classifiers, and the README of the upstream organisation says BSD.

**What that means.** Without a licence, the default is *all rights
reserved*. Nobody may lawfully copy, modify or redistribute the wrappers —
including the project's own contributors, and including anyone who forks
one.

**The tools are a second question.** The wrappers ship binaries of tools
under their own terms:

| Tool | Licence | Consequence |
|------|---------|-------------|
| `nmap`, `dirsearch`, `wapiti` | GPL-2 | A distributed image must offer the corresponding source |
| `xray` | AGPL-3 | A **network** deployment triggers the copyleft — the strongest obligation in the set |
| `dalfox`, `katana`, `nuclei`, `subfinder`, `httpx`, `waybackurls`, `gau`, `gospider`, `sqlmap`, `getJS`, `secretfinder`, `nipejs` | MIT / permissive | Attribution only |
| `gf`, `qsreplace`, `uro`, `anew`, `findomain`, `sublist3r`, `assetfinder`, `chaos`, `vita`, `paramspider`, `ffuf` | MIT / GPL-2 / mixed | Per tool |

**The decision this needs.**

1. **The wrappers.** Add a licence to all 19 repositories. The
   recommendation is **BSD-3-Clause**, which is what the classifiers already
   claim and what permits the organisation to grant contributions and
   relicense nothing by accident.
2. **xray.** AGPL-3 inside a hosted service is the sharpest obligation here.
   The recommendation is to keep xray **opt-in and unhosted**: the image is
   built, it is not part of the platform's own distribution, and the
   documentation says why. The alternative — replacing it — costs a
   capability the platform currently has.
3. **The GPL-2 tools.** Offer the corresponding source for the images that
   ship them, and write down where that source lives.

**The decision needs an owner.** It is a legal question about how the
project is distributed, not a code question, and this document does not
pretend otherwise.

---

## 6. Acceptance criteria

| # | Criterion |
|---|-----------|
| 1 | No repository contains a binary over 1 MB, and `B-Hunters-xray` builds its binary from a pinned, checksummed release. |
| 2 | `git grep -E 'password|secret_key|access_key' -- '*.ini' '*.env'` finds no value that works. |
| 3 | `scripts/render_config.py` refuses to render a configuration with a placeholder password. |
| 4 | The Playground repository has no committed `.env`, and no bucket policy is public. |
| 5 | The credential in the transcript has been rotated and no longer authenticates. |
| 6 | All 19 repositories carry a licence, and the GitHub API reports it. |
| 7 | The licence of every tool that ships inside an image is recorded in a table next to that image. |

---

## 7. Risks

| Risk | Mitigation |
|------|-----------|
| Rotating a credential breaks a running deployment | The rotation is scripted and the old value is kept valid for one release |
| Replacing the committed binary changes the image | The checksum and the version are asserted in a test, so a wrong build fails rather than runs |
| Adding a licence is a decision that cannot be undone | The licence is chosen with the owner before it is committed, and the decision is recorded in `docs/` |
| The xray decision stalls the rest of the spec | xray is isolated in its own task; the other tasks do not wait for it |
