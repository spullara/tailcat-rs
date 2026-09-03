# Third-party notices

## Tailcat provenance

`tailcat-rs` is an independent Rust implementation of
[Tailcat](https://github.com/tailscale/tailcat). Its protocol behavior,
documentation, artwork, and browser UI derive from that project. The standalone
Rust source was extracted from the port in
[spullara/tailcat at `689b74e2405c18fbdf4b21a0610d8c1abae8f334`](https://github.com/spullara/tailcat/tree/689b74e2405c18fbdf4b21a0610d8c1abae8f334).

The original BSD-3-Clause license and copyright are preserved in
[LICENSE](LICENSE):

Copyright (c) 2020 Tailscale Inc & contributors.

This port's repository name and independent maintenance do not change the
attribution or redistribution requirements. The upstream project does not
endorse or maintain this port.

## Rust dependencies and browser adaptation

Native open-source dependencies are recorded in [Cargo.lock](Cargo.lock).
The full source checkout additionally records browser dependencies in
[wasm/Cargo.lock](https://github.com/spullara/tailcat-rs/blob/main/wasm/Cargo.lock),
which is outside the published Cargo package. Their individual licenses and
notices continue to apply; lockfiles are an inventory, not replacement license
texts.

BoringTun 0.7.1 is provided by Cloudflare, Inc. under BSD-3-Clause. Native builds
use the [registry crate](https://crates.io/crates/boringtun/0.7.1), with the upstream
[versioned license text](https://github.com/cloudflare/boringtun/blob/051c9d47dc9c5cb36e461b7d36dcd673820dc98b/LICENSE.md)
at the source commit recorded by that crate.

In a full repository checkout, browser builds use
[third_party/boringtun](third_party/boringtun/) with a small clock and entropy
adaptation documented in [TAILCAT-PATCH.md](third_party/boringtun/TAILCAT-PATCH.md).
Those source links are available in the checkout; the vendored tree is excluded
from the native Cargo archive. The repository also provides the
[browser adaptation](https://github.com/spullara/tailcat-rs/blob/main/third_party/boringtun/TAILCAT-PATCH.md)
for readers of the published crate.

Copyright (c) 2019 Cloudflare, Inc. All rights reserved.

The [BoringTun license](https://github.com/cloudflare/boringtun/blob/051c9d47dc9c5cb36e461b7d36dcd673820dc98b/LICENSE.md)
also accompanies the full checkout at
[third_party/boringtun/LICENSE](third_party/boringtun/LICENSE) and must accompany
redistributed browser artifacts and binaries using BoringTun. Platform release
archives include that license, the project license, and these notices. The
Cargo package resolves native dependencies separately from the registry. Other dependencies retain their applicable terms.
