use std::path::Path;
fn main() -> anyhow::Result<()> {
    let options = tailcat::webdemo::parse_options(std::env::args().skip(1))?;
    if options.contains_key("help") {
        println!("tailcat-webdist -o <output directory> [--web-dir web]");
        return Ok(());
    }
    let out = options
        .get("o")
        .ok_or_else(|| anyhow::anyhow!("-o output directory is required"))?;
    tailcat::webdemo::build_dist(
        Path::new(options.get("web-dir").map(String::as_str).unwrap_or("web")),
        Path::new(out),
    )?;
    eprintln!("built Rust web distribution in {out}");
    Ok(())
}
