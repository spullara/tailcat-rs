//! Control-plane-free TCP streams using tailcat's address and discovery protocol,
//! DERP relays, WireGuard encryption, and a userspace TCP stack.
pub mod cli;
pub mod derp;
pub mod protocol;
pub mod runtime;
pub mod services;
pub mod webdemo;

pub use protocol::{ConnInfo, PrivateKey, Region, parse_addr};
pub use runtime::{
    Client, PeerStatus, PingResult, RuntimeStatus, Server, ServerConfig, TcpHandler,
};
