# Releasing Geneza

A release is a Git tag. Pushing `vX.Y.Z` to the repo is the only trigger; CI does
the rest. There is nothing to build or upload by hand.

## What a tag push produces

A single `v*` tag push fans out to four workflows that all converge on the same
GitHub Release for that tag:

| Workflow        | Produces                                                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| `release.yml`   | The Release object itself + auto-generated notes (changelog since the previous tag). Marks pre-releases.    |
| `binaries.yml`  | `geneza` CLI archives (6 os/arch), the Linux `geneza-node` agent package, `SHA256SUMS`, `SHA256SUMS.sig`, `root-keys.json`. |
| `docker.yml`    | Multi-arch `ghcr.io/geneza-ai/geneza-controller` and `ghcr.io/geneza-ai/geneza-relay` images, tagged with the semver + `latest`. |
| `desktop.yml`   | Wails desktop bundles (`.dmg`/`.app` for macOS, `.exe` for Windows, `.tar.gz` for Linux).                  |

The split is deliberate: `release.yml` owns only the release shell and notes;
the other three attach the artifacts. `softprops/action-gh-release` create-or-
updates the release for the tag, so whichever runs first creates the release and
the rest update it.

One caveat for pre-releases: only `release.yml` sets the `prerelease`/`make_latest`
flags. The artifact workflows call the same action without those inputs, so they
apply the action's defaults (`prerelease=false`, `make_latest=legacy`) whenever
they update the release. If an artifact attach lands after `release.yml` on an
`-rcN`/`-beta` tag, it can flip the release back to "Latest". If that happens,
re-run `release.yml` (Actions -> release -> Re-run) once the assets are attached
to re-stamp the flags.

The container images are GHCR packages, not Release assets, so they don't show
up in the Release's file list — pull them by tag from `ghcr.io/geneza-ai`.

## Cutting a release

Two equivalent ways. Both end in the same `v*` tag.

**A. The `cut-release` workflow (recommended).** In the GitHub **Actions** tab,
pick **cut-release**, click **Run workflow**, and enter:

- `version` — the bare semver, e.g. `1.4.0` (no leading `v`). Use a suffix like
  `1.4.0-rc1` for a pre-release.
- `prerelease` — optional checkbox. A hyphen in the version already forces a
  pre-release; the checkbox is just there for a clean (no-suffix) pre-release.

It validates the version, refuses to run off `main`, refuses to overwrite
an existing tag, then creates and pushes the annotated tag `v<version>` at the
current commit. That push starts the four workflows above.

> One-time setup: this path needs a **`RELEASE_PAT`** secret (a fine-grained PAT
> with **contents: write**). A tag pushed with the built-in `GITHUB_TOKEN` does
> not start other workflows (Actions' anti-recursion rule), so without the PAT
> the tag is created but the release/build workflows don't fire. The workflow
> warns if it's missing; just push the tag by hand (option B) in that case.

**B. Push a tag by hand.** From a clean checkout of `main`:

```sh
git tag -a v1.4.0 -m "Geneza v1.4.0"
git push origin v1.4.0
```

## Version scheme

SemVer 2.0.0. The tag is `vX.Y.Z`; the version stamped into binaries and images
is the tag with the leading `v` stripped (`vX.Y.Z` -> `X.Y.Z`). A pre-release
carries a hyphenated suffix (`v1.4.0-rc1`, `v1.4.0-beta.2`) and is published as a
GitHub pre-release, so it is never marked "Latest".

Builds off the `main` branch are stamped `0.0.0-dev+<sha>` and publish **early,
unsigned** artifacts and images (`main`/`sha`-tagged) for testing. They are not
releases: no Release object is created, and `SHA256SUMS` is left unsigned because
the signing key is absent. Only a `v*` tag yields a signed, published release.

## Signing keys and secrets

Signing is offline-keyed and gated on repository secrets being present; a fork or
an early run without them still builds (just unsigned).

- **`GENEZA_RELEASE_SIGNING_KEY`** — the release-signing private key (ed25519).
  `binaries.yml` uses it via `geneza-sign sign-file --tag <ref>` to produce
  `SHA256SUMS.sig`, bound to the tag so the signature can't be replayed onto a
  different release. Its public half is pinned in `deploy/release/root-keys.json`,
  published alongside the checksums. If the secret is unset, the checksums ship
  unsigned (integrity-only) and CI emits a warning.
- **macOS code-signing** (optional, `desktop.yml`) — `MACOS_CERT_P12`,
  `MACOS_CERT_PASSWORD`, `MACOS_SIGN_IDENTITY` for Developer ID signing, plus
  `AC_API_KEY_P8`, `AC_API_KEY_ID`, `AC_API_ISSUER` for notarization. Absent =
  an unsigned `.app`/`.dmg` still builds.
- **Windows code-signing** (optional, `desktop.yml`) — `WINDOWS_CERT_PFX`,
  `WINDOWS_CERT_PASSWORD` for Authenticode. Absent = an unsigned `.exe` still
  builds.
- **`RELEASE_PAT`** (optional, `cut-release.yml`) — a fine-grained PAT with
  `contents: write`, used only so the `cut-release` dispatch's tag push triggers
  the release workflows. Absent = cut the tag by hand instead (see above).

The container and tag-push workflows authenticate with the built-in
`GITHUB_TOKEN` (`contents: write` for Releases, `packages: write` for GHCR); no
extra secret is needed for those.

For how nodes verify the signed binaries before running them — the root key,
`root-keys.json`, and the signed manifest chain — see
[update-trust.md](update-trust.md).
