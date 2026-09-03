# Security

## Reporting a vulnerability

Report vulnerabilities in this Rust implementation to the maintainer of
[spullara/tailcat-rs](https://github.com/spullara/tailcat-rs), not to the upstream
project. Use [private vulnerability reporting](https://github.com/spullara/tailcat-rs/security/advisories/new)
when enabled. If it is unavailable, arrange private contact with
[@spullara](https://github.com/spullara) before sharing exploit details.
Do not open a public issue containing an undisclosed vulnerability.

For vulnerabilities in the original [Tailscale Tailcat](https://github.com/tailscale/tailcat)
implementation or Tailscale-operated infrastructure, use the Tailscale security
contact published at [security.txt](https://tailscale.com/.well-known/security.txt).
This independent Rust port is not a Tailscale-maintained product; upstream
contacts do not replace reporting port-specific defects here.

## Threat model

A Tailcat address contains the information needed to contact a service. Unless
the server configures a client allowlist, possession of that address grants
access. Treat addresses as secrets when offering private services. Publishing
an address in DNS makes it public. Saved server identities preserve access
across restarts, so previously shared addresses remain relevant.

`no-auth-ssh` grants the current OS user's shell and, by default, filesystem
access. It has no separate SSH user authentication. An exit node grants TCP
access through the server's network. Writable shares grant the specified file
operations. Limit these capabilities to intended clients; use `--allow` with
client identity keys or forward to an existing authenticated service where
appropriate.

The native implementation uses BoringTun, smoltcp, a Rust DERP/discovery
runtime, russh/russh-sftp, and capability-relative filesystem access. WireGuard
encrypts traffic end to end, including when DERP relays carry it. Relays still
observe connection and traffic metadata. Discovery uses a separate key so
cleartext direct-path discovery frames do not reveal the node public key
embedded in an unlisted service address.

Rooted file shares confine operations to an open directory capability, including
symlink traversal. Read-only and write-only modes enforce separate policies.
The default write-only receiver assigns unique server-chosen filenames and
rejects reads, listings, and access to unrelated files. `--accept-dirs` opts
into directory creation and directory metadata access. Shell mode without an
explicit rooted share intentionally has the current user's ambient filesystem
access.

The runtime validates incoming packet structure before allocating TCP buffers,
authenticates peer identities and direct-path responses, bounds connections and
discovery state, and preserves directional TCP shutdown. These measures and
compatibility tests do not constitute an independent security audit. The port
is experimental and has no stable security-support release policy yet.

## Provenance and earlier reports

The port was developed against the Tailcat behavior represented by
[spullara/tailcat at `689b74e2405c18fbdf4b21a0610d8c1abae8f334`](https://github.com/spullara/tailcat/tree/689b74e2405c18fbdf4b21a0610d8c1abae8f334).
The [upstream security policy](https://github.com/tailscale/tailcat/blob/main/SECURITY.md)
credits reports that shaped drop-box privacy, subprocess quoting, DNS address
handling, zero-key rejection, and separation of node and discovery keys.
Those reports concern upstream history, not newly disclosed vulnerabilities or
release fixes in `tailcat-rs`. Rust tests preserve the relevant behavior and
exercise this implementation's own boundaries.
