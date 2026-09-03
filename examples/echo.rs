//! Run with `cargo run --example echo`, then connect using the printed address.
use std::sync::Arc;
use tailcat::{Server, ServerConfig, TcpHandler};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = Server::start(ServerConfig {
        on_tcp: Some(Arc::new(|port| {
            let handler: TcpHandler = Arc::new(move |mut stream| {
                Box::pin(async move {
                    let _ = stream
                        .write_all(format!("hello from port {port}\n").as_bytes())
                        .await;
                    let _ = stream.shutdown().await;
                })
            });
            Some(handler)
        })),
        ..Default::default()
    })
    .await?;
    println!("{}", server.tailcat_addr());
    tokio::signal::ctrl_c().await?;
    server.close().await;
    Ok(())
}
