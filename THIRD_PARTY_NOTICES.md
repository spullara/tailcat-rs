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

Open-source dependencies are recorded in [Cargo.lock](Cargo.lock) and
[wasm/Cargo.lock](wasm/Cargo.lock). Their individual licenses and notices continue
to apply; these lockfiles are an inventory, not replacement license texts.

BoringTun 0.7.1 is provided by Cloudflare, Inc. under BSD-3-Clause. Native builds
use the upstream crate. Browser builds use its source in
[third_party/boringtun](third_party/boringtun/) with a small clock and entropy
adaptation documented in
[TAILCAT-PATCH.md](third_party/boringtun/TAILCAT-PATCH.md).

Copyright (c) 2019 Cloudflare, Inc. All rights reserved.

The [full BoringTun license](third_party/boringtun/LICENSE) accompanies the
vendored source and must accompany redistributed browser artifacts and binaries
using BoringTun. Release packaging includes this license, the project license,
and these notices. Other dependencies retain their own applicable terms.
