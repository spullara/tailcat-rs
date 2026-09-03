#[tokio::main]
async fn main() {
    std::process::exit(tailcat::cli::main().await);
}
