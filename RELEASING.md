# Releasing tailcat-rs

Pushing a `v*` tag starts two independent workflows in
[spullara/tailcat-rs](https://github.com/spullara/tailcat-rs):

- [Release](.github/workflows/release.yml) creates platform packages, a GitHub
  release, and container images.
- [Publish crate](.github/workflows/publish-crate.yml) validates and uploads the
  `tailcat` Cargo package to crates.io when the tag exactly matches
  `v` followed by the version in `Cargo.toml`.

Both use [rust-toolchain.toml](rust-toolchain.toml) and the checked-in lockfile.
The crate, executable, and operating-system package are named `tailcat`; this
repository starts at version `0.1.0`, independent of upstream Go releases.

## crates.io setup

GitHub Actions uses crates.io Trusted Publishing through OIDC, with no stored
registry secret or API-token fallback. crates.io currently requires an existing
crate and crate ownership before a trusted publisher can be registered. Bootstrap
the first `0.1.0` upload locally with an API token, then enable OIDC for CI.
[Trusted Publishing documentation](https://crates.io/docs/trusted-publishing).

### Publish 0.1.0 once locally

1. Sign in to [crates.io](https://crates.io/), verify your email in
   [account settings](https://crates.io/me), and create a short-lived
   [API token](https://crates.io/settings/tokens) with permission to publish a
   new crate. Keep it on your local machine; do not add it to GitHub.
2. From a clean checkout whose `Cargo.toml` version is `0.1.0`, validate and
   publish. `cargo login` prompts for the token:

   ```sh
   cargo publish --locked --package tailcat --registry crates-io --dry-run
   cargo login --registry crates-io
   cargo publish --locked --package tailcat --registry crates-io
   cargo logout --registry crates-io
   ```

3. Confirm that `tailcat` version `0.1.0` is available, then revoke that token
   in crates.io's token settings.

This publishes `0.1.0`; it cannot be overwritten. The first later CI release
must bump the package version, for example to `0.1.1`.

### Register the trusted publisher

As the crate owner, open `tailcat` on crates.io, then **Settings → Trusted
Publishing → Add → GitHub**. Save these fields:

| Field | Value |
|---|---|
| Repository owner | `spullara` |
| Repository name | `tailcat-rs` |
| Workflow filename | `publish-crate.yml` |
| Environment | `crates-io` |

The workflow field is a filename, without `.github/workflows/`. In
[GitHub environment settings](https://github.com/spullara/tailcat-rs/settings/environments),
`crates-io` is configured to allow only release tags matching `v*`.

The upload job requests a GitHub OIDC identity and exchanges it through
[rust-lang/crates-io-auth-action](https://github.com/rust-lang/crates-io-auth-action)
for a short-lived crates.io credential. Validation and dry runs do not request
credentials. A dry run does not test the OIDC exchange: that remains unverified
until the registry is configured and an authenticated publishing run succeeds.

### Check publication without uploading

Run the workflow on `main` with its default dry-run setting, using GitHub's
Actions interface or the GitHub CLI:

```sh
gh workflow run publish-crate.yml --ref main -f dry_run=true
```

The local equivalent, from a clean checkout, is:

```sh
cargo package --locked --list
cargo publish --locked --dry-run
```

Inspect the file list and packaged crate under `target/package/`. The registry
package contains native source and documentation; it excludes browser assets,
the nested WASM crate, and its vendored dependency tree. The optional
`web-tools` feature compiles the native web tools, but building WASM with them
requires a full source checkout. See [Browser build](README.md#browser-build).

### Manual publication from an existing tag

After setup and validation, an explicit non-dry manual run must select a tag
whose version matches the package:

```sh
gh workflow run publish-crate.yml --ref v0.1.1 -f dry_run=false
```

Replace `v0.1.1` with an unpublished release tag after the local bootstrap.
Uploads from branches or mismatched tags
are rejected. Do not reuse a version that is already published; bump the
manifest version and create a new tag instead.

The crate workflow listens to the tag push directly. It does not wait for the
GitHub release created by `release.yml`: events made with `GITHUB_TOKEN`
generally do not trigger another workflow. This avoids coupling registry
publication to that suppressed release event.
[GitHub documents the event behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

## Prepare and publish a release

1. Complete the local bootstrap and trusted-publisher registration above.
   Update `Cargo.toml` to a new version (`0.1.1` after the `0.1.0` bootstrap)
   before tagging, update `wasm/Cargo.toml` as appropriate, refresh the
   corresponding lockfile package records, and review the release changes.
   Check that the [Test workflow](.github/workflows/test.yml) is green
   on the intended commit. It runs native Rust checks on Linux, macOS, and
   Windows plus a Rust/WASM browser build.
2. Run the optional [External interoperability workflow](.github/workflows/interop.yml)
   or the equivalent local commands below. It fetches the pinned Go reference
   outside this checkout; no Go source belongs in the release repository.
3. Commit the version bump, then create an SSH-signed tag exactly matching
   `v{Cargo.toml package version}`. Git's `user.signingkey` must identify your SSH
   public key. The script creates a local tag and does not push it:

   ```sh
   ./tag.sh v0.1.1
   ```

4. Push the tag to start publication:

   ```sh
   git push origin v0.1.1
   ```

5. Inspect both workflows, the crates.io version, GitHub release assets,
   checksums, and container manifest. After registry publication, check
   `cargo install tailcat --locked --version 0.1.1` with the released version.
   Verify installation and execution on the supported platforms.

## Artifacts and toolchains

The configured release matrix builds:

| Platform | Architectures | Packages |
|---|---|---|
| Linux, musl | amd64, arm64, armv7 | `.tar.gz`, `.deb`, `.rpm` |
| Windows, MSVC | amd64, arm64 | `.zip` |
| macOS | amd64, arm64 | `.tar.gz` |

Archives contain `tailcat` (or `tailcat.exe`), the README, project license, and
third-party notices/licenses. `checksums.txt` covers the archives and packages.
The `tailcat-web` and `tailcat-webdist` tools require the `web-tools` Cargo
feature. The release packaging script packages the main CLI, and a default
`cargo install tailcat` installs only that CLI.

Linux cross-compilation uses `cross` 0.2.5. Windows builds use MSVC and macOS
builds use the hosted Apple SDK. [scripts/package-release.py](scripts/package-release.py)
generates archives and Linux package metadata with nFPM 2.47.0. The release
workflow installs Go to build the nFPM packaging tool; it does not build Tailcat
from Go or require a local Go module. Ordinary Rust builds and tests need no Go.

`TAILCAT_VERSION` embeds a release label in the executable. Ordinary Cargo
builds report the package version. A tag alone does not update either manifest.

## Containers

The workflow publishes images for `linux/amd64` and `linux/arm64` at
`ghcr.io/spullara/tailcat-rs`, with the release tag (for example `v0.1.1`) and
`latest`. [Dockerfile.release](Dockerfile.release) consumes the compiled static
Linux binaries and uses a distroless nonroot runtime. Mount a volume at
`/home/nonroot` to persist identity and cache state.

The distroless image includes certificates but no `ssh`, `scp`, or shell.
Native streams, forwarding, SOCKS, and SFTP file services work without those
programs. The `ssh`/`cp` client commands and shell sessions served by
`no-auth-ssh` require the source-built Debian image, which includes the system
OpenSSH clients and a shell:

```sh
docker build --build-arg TAILCAT_VERSION=dev -t tailcat-rs:dev .
```

## Verify locally without publishing

```sh
make build test check
make interop-full
make web-tools web-dist
make interop-web
TAILCAT_VERSION=dev cargo build --locked --release --bin tailcat
python3 scripts/package-release.py --target aarch64-apple-darwin --version dev
```

Use the host's Rust target triple when packaging a host build. To package a
cross-compiled binary, first build with the matching `--target`. The packaging
script also accepts `--binary` to select an explicit executable. Linux packages
require nFPM; `--archive-only` emits an archive without `.deb` or `.rpm` files.
The commands above do not create tags, push images, or publish releases.

`make interop-full` needs Python 3, Git, and Go 1.27. Browser interoperability
additionally needs Chrome/Chromium. The Rust/WASM build needs a compatible clang
and wasm-bindgen CLI 0.2.127. See the [README](README.md#browser-build) for setup.

Cross-platform execution, package installation, Docker builds, and Nix builds
must be checked in their respective environments. Historical macOS validation
of the earlier mixed checkout is recorded in the
[repository map](docs/repository-map.md#historical-validation-of-the-port);
it is separate from validation of a standalone release.

## Browser deployment

[webdemo-pages.yml](.github/workflows/webdemo-pages.yml) is manually dispatched.
Configure GitHub Pages to deploy from Actions, select the commit to deploy,
and run that workflow. It builds the Rust/WASM distribution and publishes the
static page with a gzip-compressed WASM asset that the browser decompresses.
A native release tag does not deploy Pages.

The upstream [tailscale.github.io/tailcat](https://tailscale.github.io/tailcat/)
site is managed separately. Its content is not evidence that this repository or
any specific Rust revision has been deployed.
