use std::path::{Path, PathBuf};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = tailcat::webdemo::parse_options(std::env::args().skip(1))?;
    if options.contains_key("help") {
        println!(
            "tailcat-web [--listen localhost:8080] [--dist directory] [--web-dir web] [--derpmap-url URL]"
        );
        return Ok(());
    }
    let dist = options.get("dist").map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("tailcat-web-{}", std::process::id()))
    });
    let generated = !options.contains_key("dist");
    if generated {
        tailcat::webdemo::build_dist(
            Path::new(options.get("web-dir").map(String::as_str).unwrap_or("web")),
            &dist,
        )?;
    }
    let result = tailcat::webdemo::serve(
        &dist,
        options
            .get("listen")
            .map(String::as_str)
            .unwrap_or("localhost:8080"),
        options
            .get("derpmap-url")
            .map(String::as_str)
            .unwrap_or(tailcat::protocol::DEFAULT_DERP_MAP_URL),
    )
    .await;
    if generated {
        let _ = std::fs::remove_dir_all(dist);
    }
    result
}
