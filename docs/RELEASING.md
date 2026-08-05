# Releasing wiretally

## The one rule

**Nothing is published without a version tag.** Merging to `main` never releases and never
publishes. The release pipeline is triggered by a pushed git tag matching
`**[0-9]+.[0-9]+.[0-9]+*` (see `on.push.tags` in `.github/workflows/release.yml`), and by nothing
else.

If you remember only one thing, remember that. Everything below is detail.

## What runs when

| Event | `ci.yml` | `release.yml` | Publishes to crates.io |
| --- | --- | --- | --- |
| PR opened / updated | all 7 jobs | `plan` only (build jobs skip) | no |
| Merge to `main` | all 7 jobs | **does not run** | no |
| Push tag `v0.1.1` | does not run | full pipeline | yes, once wired up |

`release.yml` also has a bare `pull_request:` trigger. That exists so `dist plan` validates the
release config on every PR without building anything — it is a syntax check, not a release.

## Why an accidental publish is close to impossible

Three independent layers, in the order they would stop you:

1. **The trigger.** No tag, no release workflow run. A merge cannot publish because the workflow
   that publishes is never invoked.
2. **knope's `PrepareRelease`** (once adopted, see below). With no changesets and no conventional
   commits it exits with an error rather than producing an empty release. `allow_empty = true`
   disables that guard; leave it off unless you have a reason.
3. **crates.io itself.** The registry is append-only. A version can never be overwritten or
   deleted — only yanked, which leaves it visible and installable by exact version. A duplicate
   `cargo publish` is rejected by the server.

So the failure mode of a mistake is a red CI job, not a bad release.

### Known wart: re-running a release

Re-pushing a tag, or re-running a completed release workflow, will attempt `cargo publish` for a
version that already exists and fail with an "already uploaded" error. The binaries and GitHub
release are unaffected — only the publish job goes red.

`cargo publish` has no `--skip-if-published` flag, so `publish-crates.yml` guards the step by
querying the sparse index for the version in `Cargo.toml` first, and skipping with a notice if it
is already there. A failed index request falls through to attempting the publish, letting crates.io
be the authority — a genuine duplicate is rejected server-side.

## Releasing today (manual)

The current, working flow. No changesets, no automation beyond dist.

1. Decide the new version and edit `version` in `Cargo.toml`.
2. Run `cargo publish --dry-run` locally. If it fails on `sccache`, re-run with
   `RUSTC_WRAPPER="" cargo publish --dry-run` — that error is a local wrapper issue, not a
   packaging problem.
3. Commit, open a PR, let CI go green, merge.
4. Tag and push: `git tag v0.1.1 && git push origin v0.1.1`.
5. dist builds four binaries (macOS and Linux, arm64 and x86_64), attaches them to a new GitHub
   release along with checksums and a source tarball.

## Releasing with knope + changesets (planned)

Not yet set up. This is the intended end state.

The model is a **release PR**: you never hand-edit a version. Instead:

1. **While developing**, add a change file to `.changeset/` describing the change and its bump
   level (patch / minor / major). knope also reads conventional commits, so both sources work and
   are merged — write a change file when the intent is not obvious from commit messages.
2. **knope opens or updates a release PR** that bumps `Cargo.toml`, updates `CHANGELOG.md`, and
   consumes the change files. It keeps updating that same PR as more commits land, so the open PR
   is always a live preview of "what shipping right now would look like".
3. **You merge the release PR.** knope's `Release` step then creates the tag and GitHub release.
4. **The tag triggers dist**, which builds and attaches binaries, and runs the publish job.

Merging any *other* PR does none of this. It only updates the pending release PR's contents.

### The token trap — read this before wiring it up

**The default `GITHUB_TOKEN` cannot trigger other workflows.** GitHub blocks that deliberately to
prevent infinite loops. So if knope tags the release using `GITHUB_TOKEN`, `release.yml` will
**not** fire: you get a GitHub release with no binaries attached, no publish, and no error message
explaining why.

Fix: give knope a fine-grained PAT (Contents + Pull requests, read/write) or a GitHub App
installation token. A GitHub App is preferable — it is not tied to a personal account.

This applies to any tool that cuts the tag, including release-plz.

### Why knope and not release-plz

release-plz is the more Cargo-aware tool (it runs `cargo-semver-checks` against the published
version to catch breakage you mislabelled), but it has **no changesets support** — versions are
derived from commit messages only, with no manual override. wiretally is a binary whose public API
is incidental, so semver-checks is mostly noise, which removes release-plz's main advantage.

## crates.io publishing setup

Status:

- [x] Package metadata (`description`, `license`, `repository`, `keywords`, `categories`)
- [x] `rust-version = "1.88"` — appears in the published index metadata
- [x] v0.1.0 published manually. crates.io requires a manual first publish; there is no
      "pending publisher" flow like PyPI's, though it is on their roadmap.
- [x] Trusted Publishing configured at crates.io → wiretally → Settings
- [x] GitHub environment `crates-io` created, with required reviewers
- [x] `.github/workflows/publish-crates.yml` + `publish-jobs = ["./publish-crates"]` in
      `dist-workspace.toml`
- [ ] Proven end to end by a real tag — **not yet exercised**
- [ ] Bootstrap API token revoked (wait until an automated publish has succeeded)

### The `crates-io` environment

The trusted publisher config is scoped to a GitHub environment named `crates-io`. That one string
has to match in three places, exactly:

| Where | Value |
| --- | --- |
| crates.io trusted publisher config | `crates-io` |
| GitHub → Settings → Environments | `crates-io` |
| `environment:` on the publish job | `crates-io` |

Named after the registry it authorizes rather than after the release, so a second publish target
later (Homebrew, a container registry) gets its own boundary instead of overloading this one.

Set **required reviewers** on it. dist builds every binary first and then parks the publish job
awaiting approval, so you see a green build and can inspect the release before anything becomes
permanent on crates.io.

#### Deployment branches and tags

Restrict it to **one tag rule, pattern `v*`, and no branch rules.**

This puts "publishing only ever happens from a release tag" in a second place besides the
`on.push.tags` trigger in `release.yml`, so both would have to be wrong for a branch to publish.
The mistake it actually guards against is a future `workflow_dispatch` or push trigger added for
convenience, which would silently make the publish job reachable from a branch — the workflow
trigger cannot catch that, because it is the thing that changed.

**Do not choose "protected branches only."** It is the option that sounds safest and it blocks
every release: releases come from a tag, not a branch, and the failure reports as a generic
permissions error rather than as an excluded tag.

**This makes the `v` prefix mandatory.** dist's trigger pattern
(`**[0-9]+.[0-9]+.[0-9]+*`) accepts both `v0.1.1` and a bare `0.1.1`, but a `v*` deployment rule
only matches the former. Always tag `vMAJOR.MINOR.PATCH`. A bare `0.2.0` tag will build binaries
and then block the publish for a reason that is not obvious from the error.

### Trusted Publishing

Publishing uses OIDC, not a stored token: the workflow requests a short-lived credential from
crates.io that auto-revokes when the job ends. There is no `CARGO_REGISTRY_TOKEN` secret in this
repo, and there should never be one.

Requirements: `permissions: id-token: write` on the publishing job, and
`rust-lang/crates-io-auth-action@v1` to perform the exchange.

**Register `release.yml` as the workflow filename**, not `publish-crates.yml`. With reusable
workflows, GitHub's OIDC token describes the *calling* workflow in its standard claims and the
called one in a separate `job_workflow_ref` claim; crates.io matches the standard claim. If the
exchange is rejected, the error names the value it actually saw.

### Why publishing lives inside dist's pipeline

`publish-jobs` is dist's supported extension point for a reusable `workflow_call` workflow. Wiring
it there rather than as a separate tag-triggered workflow means publishing runs **after** the
binaries build, so a failed build stops the publish. A standalone workflow could push to crates.io
while the GitHub release ends up with nothing attached.

## Gotchas

- **A published version is permanent.** The README is rendered on the crate page and cannot be
  replaced for an already-published version. Proofread it before publishing, not after.
- **`rust-version` is published metadata.** Bumping the MSRV is a user-visible change; treat it as
  at least a minor bump.
- **Windows is deliberately not built.** `exit_code` in `src/main.rs` is `cfg(unix)`-gated so it
  would compile, but CI does not test Windows and shipping an untested binary is not a promise
  worth making. Add a Windows job to `ci.yml` before adding the target to `dist-workspace.toml`.
- **`.cargo/config.toml` is gitignored on purpose.** It carries local build-speed flags
  (`-fuse-ld=lld`, and cargo-wizard wants to add `-Ctarget-cpu=native`) that would break the macOS
  runner or, worse, produce binaries that crash on users' CPUs. Note that a `RUSTFLAGS` env var in
  a workflow *overrides* `[build] rustflags` rather than merging, so `ci.yml` would silently ignore
  those flags while `release.yml` would apply them — tests clean, shipped binary broken.
- **`profile.dist` omits `panic = "abort"`** even though cargo-wizard's fast-runtime template
  includes it. The proxy spawns a task per connection and is built to survive one failing; under
  abort, a single panicking connection kills the whole process.
