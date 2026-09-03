# Releasing tailcat-rs

The [Release workflow](.github/workflows/release.yml) builds the Rust
implementation using [rust-toolchain.toml](rust-toolchain.toml) and the
checked-in lockfile. Pushing a `v*` tag starts packaging and publication for
[spullara/tailcat-rs](https://github.com/spullara/tailcat-rs). The executable and
package remain named `tailcat`; this repository starts its own version sequence
at `0.1.0`, independent of upstream Go releases.

## Prepare and publish a release

1. Update package versions in `Cargo.toml` and `wasm/Cargo.toml` as appropriate,
   refresh the corresponding lockfile package records, and review the release
   changes. Check that the [Test workflow](.github/workflows/test.yml) is green
   on the intended commit. It runs native Rust checks on Linux, macOS, and
   Windows plus a Rust/WASM browser build.
2. Run the optional [External interoperability workflow](.github/workflows/interop.yml)
   or the equivalent local commands below. It fetches the pinned Go reference
   outside this checkout; no Go source belongs in the release repository.
3. Create an SSH-signed tag. Git's `user.signingkey` must identify your SSH
   public key. The script creates a local tag and does not push it:

   ```sh
   ./tag.sh v0.1.0
   ```

4. Push the tag to start publication:

   ```sh
   git push origin v0.1.0
   ```

5. Inspect the workflow results, GitHub release assets, checksums, and container
   manifest. Verify installation and execution on the supported platforms.

## Artifacts and toolchains

The configured release matrix builds:

| Platform | Architectures | Packages |
|---|---|---|
| Linux, musl | amd64, arm64, armv7 | `.tar.gz`, `.deb`, `.rpm` |
| Windows, MSVC | amd64, arm64 | `.zip` |
| macOS | amd64, arm64 | `.tar.gz` |

Archives contain `tailcat` (or `tailcat.exe`), the README, project license, and
third-party notices/licenses. `checksums.txt` covers the archives and packages.
The `tailcat-web` and `tailcat-webdist` tools can be built from source; the
release packaging script packages the main CLI.

Linux cross-compilation uses `cross` 0.2.5. Windows builds use MSVC and macOS
builds use the hosted Apple SDK. [scripts/package-release.py](scripts/package-release.py)
generates archives and Linux package metadata with nFPM 2.47.0. The release
workflow installs Go to build the nFPM packaging tool; it does not build Tailcat
from Go or require a local Go module. Ordinary Rust builds and tests need no Go.

`TAILCAT_VERSION` embeds a release label in the executable. Ordinary Cargo
builds report the package version. A tag alone does not update either manifest.

## Containers

The workflow publishes images for `linux/amd64` and `linux/arm64` at
`ghcr.io/spullara/tailcat-rs`, with the release tag (for example `v0.1.0`) and
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
