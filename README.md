<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

# tailcat-rs

A standalone Rust implementation of [Tailcat](https://github.com/tailscale/tailcat):
netcat-style streams through WireGuard-encrypted tunnels, without a Tailscale
account, daemon, or control plane. Peers exchange compact addresses, meet through
a DERP relay, and discover a direct UDP path when possible. Everything runs in
userspace; no root access, TUN device, or host route changes are required.

This repository contains the Rust library and CLI, native SSH/SFTP services,
a WebAssembly implementation, and browser JavaScript assets. The executable
and Rust crate are both named **`tailcat`**; the repository is **`tailcat-rs`**.
The initial package version is `0.1.0`.

This is an independent port, not a Tailscale-maintained release. It was extracted
from the Rust port in
[spullara/tailcat at `689b74e`](https://github.com/spullara/tailcat/tree/689b74e2405c18fbdf4b21a0610d8c1abae8f334),
which used the original Go implementation as a compatibility reference.
This checkout includes no Go source or Go repository history. See the
[repository map](docs/repository-map.md) for architecture, protocol details,
and validation provenance.

## Build and install

Install Rust through rustup and a native C build toolchain: Xcode Command Line
Tools on macOS, a C compiler and linker on Linux, or Visual Studio C++ Build
Tools on Windows. [rust-toolchain.toml](rust-toolchain.toml) pins Rust 1.97.1;
rustup installs it automatically. The manifests declare Rust 1.91 as the minimum
supported version.

```sh
git clone https://github.com/spullara/tailcat-rs.git
cd tailcat-rs
cargo build --release --locked --bins
./target/release/tailcat --help
# Optional: install this checkout's CLI into Cargo's bin directory.
cargo install --path . --locked --bin tailcat
```

On Windows the executable is `target\release\tailcat.exe`. The other native
binaries are `tailcat-web` and `tailcat-webdist`. These builds do not require Go.
The `ssh` and `cp` client commands invoke system OpenSSH `ssh` and `scp`;
`ls` and the built-in SSH/SFTP server are native Rust.

## Verify

```sh
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

These checks use Rust and local fixtures. Optional cross-implementation tests
fetch the pinned external Go reference into a temporary checkout and require
Python 3, Git, and Go 1.27:

```sh
make interop       # Rust/Go wire and executable interoperability
make interop-full  # Also run the reference CLI behavior suite against Rust
```

The equivalent runner accepts a prebuilt executable:

```sh
python3 scripts/check-interop.py --binary target/release/tailcat --full-cli
```

The tests use a local DERP relay. Go is an optional test dependency, not part
of the Rust build or deployed application. See
[verification details](docs/repository-map.md#verification).

## Usage

In the examples, replace `tcADDRESS` with the complete address printed by your
server. Addresses are case-sensitive. Share them only with intended clients:
without an allowlist, knowledge of the address grants access to the service.

### Pipe stdin and stdout between machines

Start a one-connection receiver. It prints its address to stderr, then waits:

```sh
tailcat > received.txt
```

On the other machine:

```sh
printf 'hello\n' | tailcat tcADDRESS
```

Streams are bidirectional and preserve half-close: a sender can finish writing
while continuing to read the response.

### Serve and forward TCP ports

Expose local ports through the tunnel:

```sh
tailcat serve 8080,8443
# Or serve every local TCP port:
tailcat serve all
```

Connect a client stream to one served port:

```sh
tailcat tcADDRESS 8080
```

Or make the served ports available to ordinary local applications:

```sh
tailcat forward tcADDRESS 18080:8080 3306
```

This binds `127.0.0.1:18080` to the server's port 8080 and
`127.0.0.1:3306` to its port 3306. Local port `0` requests a free port; the
listener prints the selected address. Use `--bind=0.0.0.0` before `tcADDRESS`
to expose a listener to other machines. Ctrl-C stops forwarding.

### Send and receive files

Create a directory, then receive uploads in a write-only drop box:

```sh
mkdir -p inbox
tailcat recv inbox
```

The sender uses:

```sh
tailcat cp report.pdf tcADDRESS:
```

The default drop box assigns each upload a unique filename. Senders cannot
list or read files, overwrite existing files, or inspect guessed names.
Use `tailcat recv --accept-dirs inbox` to allow directory trees, then
`tailcat cp -r directory tcADDRESS:` to upload one.

To offer a directory for reading or ordinary read/write access:

```sh
tailcat serve --files=.:ro files
tailcat serve --files=/pub:rw files
```

Clients can list and download files:

```sh
tailcat ls -l tcADDRESS
tailcat cp tcADDRESS:report.pdf .
```

`tailcat ls` implements SFTP directly and needs no OpenSSH installation.
`tailcat cp` runs the system `scp` and preserves its progress display.
Rooted shares use capability-based filesystem access, confining both normal
paths and symlinks to the served directory. Supported modes are `ro`, `rw`,
`wo`, and `wo+`; see the [file policy table](docs/repository-map.md#services).
Transfers do not enable SSH compression.

### SSH

The built-in SSH server runs as the current OS user and accepts no separate
SSH password or user key:

```sh
tailcat serve no-auth-ssh
```

Connect interactively or run a command:

```sh
tailcat ssh tcADDRESS
tailcat ssh tcADDRESS ls -la
```

Use `serve --allow=... no-auth-ssh` to restrict access to client identities.
A shell server also provides SFTP with the current user's filesystem access
unless an explicit rooted file share is configured. To use your system SSH
server and its authentication policies, run `tailcat serve 22` instead.

### Ping, SOCKS, and exit nodes

Test connectivity and wait up to ten seconds for a direct UDP path:

```sh
tailcat ping --until-direct tcADDRESS
```

Run a command through a SOCKS5 proxy to the server:

```sh
tailcat socks tcADDRESS curl http://server.tailcat:8080/
```

Tailcat addresses also work as URL hostnames with compatible clients:

```sh
tailcat socks curl http://tcADDRESS:8080/
```

Browsers lowercase hostnames, so use a local `forward` listener with them.

An exit-node server allows TCP access to destinations reachable from its host:

```sh
tailcat serve exit-node
```

For example, forward a local port to a private-network destination through it:

```sh
tailcat forward tcADDRESS 3001:172.23.52.30:3001
```

### Saved keys and access control

A server normally creates an ephemeral key. `genkey` saves an identity so the
server address can remain stable across restarts:

```sh
tailcat genkey --key=default --fixed-region
tailcat serve 8080
```

Saved keys live under the operating system's user configuration directory in
`tailcat/keys`. A saved key named `default` is selected automatically for
servers; `client-default` is selected automatically for clients. Startup output
identifies whether the server is using a saved or new identity.

```sh
tailcat serve --key=new 8080             # Force an ephemeral server key
tailcat serve --key=work 8080            # Use another saved identity
tailcat genkey --list
tailcat genkey --delete --key=default
```

Anyone who received a saved server address can reuse it while that identity is
serving. Restrict access by generating a client key on the client machine:

```sh
tailcat genkey --client --key=client-default
# Prints a nodekey:... public key.
```

On the server, use the complete printed public key:

```sh
tailcat serve --allow=nodekey:CLIENT_PUBLIC_KEY 22
```

An allowlist checks the client's WireGuard identity before exposing the service.
The saved client private key stays on the client machine.

### DNS and relay selection

A DNS TXT record can publish a server address:

```text
my-server.example.com. 300 IN TXT "tailcat=tcADDRESS"
```

Clients can then use the DNS name:

```sh
tailcat ssh my-server.example.com
tailcat ping my-server.example.com
```

For a published address, use `genkey --fixed-region` or an explicit
`--region=<id-or-code>` so server restarts use the same relay region.
`genkey --region=list` lists available regions.

The default relay map is [tailcat.dev/derpmap.json](https://tailcat.dev/derpmap.json),
operated by the upstream project. This repository does not operate those relays.
You can [run your own DERP server](https://github.com/tailscale/tailscale/tree/main/cmd/derper)
and embed its hostname in a saved address:

```sh
tailcat genkey --key=default --region=derp.example.com
tailcat serve 22
```

A custom DERP server needs a hostname and valid TLS certificate. For a relay
fleet, point both peers at your own map with `--derpmap-url`.

Inspect an address without connecting, or expand a region ID into embedded
relay metadata:

```sh
tailcat parse tcADDRESS
tailcat resolve tcADDRESS
```

`resolve` may fetch the relay map. `serve --full-address` prints the embedded
form directly. Addresses include separate WireGuard and path-discovery keys;
legacy addresses without a discovery key must be regenerated for connections.

## Rust library

`Server::start(ServerConfig)` creates a listener. Port callbacks receive Tokio
`DuplexStream`s and run asynchronously. `Client::connect` resolves an address
and registers with the server; `dial_tcp_port` connects to a served port, while
`dial_tcp` targets an exit-node destination.

```sh
cargo run --example echo
cargo run --example client -- tcADDRESS
```

[examples/echo.rs](examples/echo.rs) and [examples/client.rs](examples/client.rs)
are complete, compilable examples. After sending a request, call `shutdown()`
on the stream's write side, continue reading the response, and call
`drain_tcp()` before closing the client. This lets the userspace TCP stack
finish FIN/ACK delivery.

`Client::status()` and `Server::status()` return peer keys and addresses,
WireGuard handshake age and byte counters, fresh direct endpoints, and active
TCP connection counts. Generate API documentation with `cargo doc --no-deps`.

## Browser build

The browser implementation uses Rust/WebAssembly for networking and JavaScript
for the DOM, file picker, and streams. Browsers use DERP over WebSockets;
there is no direct UDP path in the browser.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.127 --locked
cargo run --locked --bin tailcat-webdist -- -o dist
cargo run --locked --bin tailcat-web -- --dist dist --listen localhost:8080
```

The WASM build also needs clang with WebAssembly support. On macOS,
`brew install llvm` supplies it and the builder finds Homebrew clang
automatically. Set `CC_wasm32_unknown_unknown` to select a compiler explicitly.
The distribution builder emits bindings plus raw, gzip, and zstd WASM variants.

Run `make interop-web` for optional browser compatibility tests against the
external Go reference; these additionally need a supported Chrome/Chromium
installation. The repository's Pages workflow is manually dispatched after
Pages is configured. The [upstream demo](https://tailscale.github.io/tailcat/)
is a separate deployment and does not identify the version of this Rust port.

## Architecture and releases

The native runtime combines BoringTun for WireGuard, smoltcp for TCP,
Tokio for I/O, and a Rust DERP/discovery implementation. SSH/SFTP use
russh and russh-sftp; rooted shares use cap-std and terminals use portable-pty.
See [docs/repository-map.md](docs/repository-map.md) for module boundaries,
wire invariants, resource limits, and the verification strategy.

Cargo, the Makefile, and the Nix flake build Rust. Tagged releases package the
`tailcat` executable for Linux, macOS, and Windows and publish containers to
`ghcr.io/spullara/tailcat-rs`. See [RELEASING.md](RELEASING.md) for the configured
release process; no release or deployment is implied by a successful local build.

## Security and provenance

This is experimental software. Its Rust API, CLI, and wire compatibility may
change. See [SECURITY.md](SECURITY.md) for the threat model and private reporting
instructions. Upstream relay availability and policies are controlled by their
operators.

Tailcat's protocol, behavior, and browser UI originate in
[tailscale/tailcat](https://github.com/tailscale/tailcat). The standalone Rust
source was extracted from
[spullara/tailcat at `689b74e2405c18fbdf4b21a0610d8c1abae8f334`](https://github.com/spullara/tailcat/tree/689b74e2405c18fbdf4b21a0610d8c1abae8f334).
The original BSD-3-Clause copyright and license remain in [LICENSE](LICENSE).
Dependency and browser adaptation notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
