This directory contains BoringTun 0.7.1 from crates.io, under its original
BSD-3-Clause license. The only functional modifications select `web-time`
for monotonic and wall clocks on wasm32 and enable browser entropy through
getrandom's JavaScript backend. Native implementations and cryptography are
unchanged. The browser crate uses this copy; the native crate uses crates.io.
