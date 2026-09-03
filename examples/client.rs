//! Run with `cargo run --example client -- tcADDRESS`.
use std::time::Duration;
use tailcat::Client;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: client tcADDRESS"))?;
    let client = Client::connect(&addr, None, None).await?;
    let mut stream = client.dial_tcp_port(80).await?;
    stream.shutdown().await?;
    tokio::io::copy(&mut stream, &mut tokio::io::stdout()).await?;
    client.drain_tcp(Duration::from_secs(5)).await?;
    client.close().await;
    Ok(())
}
