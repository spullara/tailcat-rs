//! Distribution builder and HTTP handler for the browser's Rust WebAssembly app.
use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
struct Assets {
    files: Arc<HashMap<String, Vec<u8>>>,
}

/// Validate the complete distribution before accepting requests.
pub fn handler(dist: &Path) -> Result<Router> {
    let mut files = HashMap::new();
    for name in ["index.html", "app.js", "tailcat.js", "main.wasm"] {
        files.insert(
            name.to_string(),
            std::fs::read(dist.join(name))
                .with_context(|| format!("webdemo: incomplete dist: {name}"))?,
        );
    }
    for name in ["main.wasm.gz", "main.wasm.zst"] {
        if let Ok(bytes) = std::fs::read(dist.join(name)) {
            files.insert(name.into(), bytes);
        }
    }
    Ok(Router::new()
        .route("/", get(asset))
        .route("/app.js", get(asset))
        .route("/tailcat.js", get(asset))
        .route("/main.wasm", get(asset))
        .with_state(Assets {
            files: Arc::new(files),
        }))
}
async fn asset(State(assets): State<Assets>, request: Request) -> Response {
    let name = match request.uri().path() {
        "/" => "index.html",
        path => path.trim_start_matches('/'),
    };
    let mut headers = HeaderMap::new();
    let mut actual = name;
    if name == "main.wasm" {
        headers.insert(header::CONTENT_TYPE, "application/wasm".parse().unwrap());
        headers.insert(header::VARY, "Accept-Encoding".parse().unwrap());
        headers.insert(
            "X-Uncompressed-Size",
            assets.files[name].len().to_string().parse().unwrap(),
        );
        let enc = request
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        for (encoding, file) in [("zstd", "main.wasm.zst"), ("gzip", "main.wasm.gz")] {
            if accepts(enc, encoding) && assets.files.contains_key(file) {
                actual = file;
                headers.insert(header::CONTENT_ENCODING, encoding.parse().unwrap());
                break;
            }
        }
        headers.insert(
            "X-Compressed-Size",
            assets.files[actual].len().to_string().parse().unwrap(),
        );
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            if name.ends_with(".js") {
                "text/javascript; charset=utf-8"
            } else {
                "text/html; charset=utf-8"
            }
            .parse()
            .unwrap(),
        );
    }
    let bytes = assets.files[actual].clone();
    headers.insert(
        header::CONTENT_LENGTH,
        bytes.len().to_string().parse().unwrap(),
    );
    (StatusCode::OK, headers, Body::from(bytes)).into_response()
}
fn accepts(header: &str, encoding: &str) -> bool {
    header.split(',').any(|part| {
        let mut parts = part.trim().split(';');
        if parts.next() != Some(encoding) {
            return false;
        }
        !parts.any(|p| {
            p.trim()
                .strip_prefix("q=")
                .and_then(|q| q.parse::<f32>().ok())
                .is_some_and(|q| q <= 0.0)
        })
    })
}

pub async fn serve(dist: &Path, listen: &str, derp_map_url: &str) -> Result<()> {
    let upstream = derp_map_url.to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let app = handler(dist)?.route(
        "/derpmap.json",
        get(move |headers: HeaderMap| {
            let client = client.clone();
            let url = upstream.clone();
            async move {
                let mode = headers
                    .get("Tailcat-Mode")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("client");
                match client.get(url).header("Tailcat-Mode", mode).send().await {
                    Ok(response) => {
                        let status = response.status();
                        match response.bytes().await {
                            Ok(bytes) => {
                                (status, [(header::CONTENT_TYPE, "application/json")], bytes)
                                    .into_response()
                            }
                            Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
                        }
                    }
                    Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!(
        "serving tailcat web app at http://{}/",
        listener.local_addr()?
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Compile the Rust browser module, generate JavaScript bindings, and precompress.
/// Tool execution uses argv directly, with no shell interpolation.
pub fn build_dist(web_dir: &Path, out: &Path) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = root.join("wasm/Cargo.toml");
    let mut build = std::process::Command::new("cargo");
    build
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
        ])
        .arg(&manifest);
    build.arg("--target-dir").arg(root.join("wasm/target"));
    // Apple's system clang does not include the WebAssembly backend required
    // by ring. Respect an explicit compiler, otherwise locate Homebrew LLVM.
    #[cfg(target_os = "macos")]
    if std::env::var_os("CC_wasm32_unknown_unknown").is_none() {
        for clang in [
            "/opt/homebrew/opt/llvm/bin/clang",
            "/usr/local/opt/llvm/bin/clang",
        ] {
            if Path::new(clang).is_file() {
                build.env("CC_wasm32_unknown_unknown", clang);
                break;
            }
        }
    }
    run(&mut build)?;
    std::fs::create_dir_all(out)?;
    let wasm = root.join("wasm/target/wasm32-unknown-unknown/release/tailcat_web.wasm");
    run(std::process::Command::new("wasm-bindgen")
        .arg(&wasm)
        .args(["--target", "web", "--out-name", "tailcat", "--out-dir"])
        .arg(out))?;
    std::fs::rename(out.join("tailcat_bg.wasm"), out.join("main.wasm"))?;
    for name in ["index.html", "app.js"] {
        std::fs::copy(web_dir.join(name), out.join(name))
            .with_context(|| format!("copying browser asset {name}"))?;
    }
    compress_wasm(&out.join("main.wasm"))?;
    Ok(())
}
fn run(command: &mut std::process::Command) -> Result<()> {
    let status = command.status().with_context(|| {
        format!(
            "could not run {:?}; install the Rust wasm target and wasm-bindgen-cli",
            command.get_program()
        )
    })?;
    if !status.success() {
        bail!("{:?} failed with {status}", command.get_program());
    }
    Ok(())
}
pub fn compress_wasm(path: &Path) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gzip.write_all(&bytes)?;
    std::fs::write(
        PathBuf::from(format!("{}.gz", path.display())),
        gzip.finish()?,
    )?;
    std::fs::write(
        PathBuf::from(format!("{}.zst", path.display())),
        zstd::encode_all(bytes.as_slice(), 9)?,
    )?;
    Ok(())
}

pub fn parse_options(args: impl Iterator<Item = String>) -> Result<HashMap<String, String>> {
    let mut options = HashMap::new();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if matches!(arg.as_str(), "-h" | "--help") {
            options.insert("help".into(), String::new());
            continue;
        }
        let (key, value) = if let Some((key, value)) = arg.split_once('=') {
            (key.trim_start_matches('-').to_string(), value.to_string())
        } else {
            (
                arg.trim_start_matches('-').to_string(),
                args.next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?,
            )
        };
        if !matches!(
            key.as_str(),
            "o" | "web-dir" | "listen" | "derpmap-url" | "dist"
        ) {
            bail!("unknown option {arg}");
        }
        options.insert(key, value);
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn serves_compressed_wasm_and_rejects_unknown_paths() {
        let dir = tempfile::tempdir().unwrap();
        for (name, data) in [
            ("index.html", "<html>demo</html>"),
            ("app.js", "// app"),
            ("tailcat.js", "// bindings"),
            ("main.wasm", "wasm-uncompressed"),
            ("main.wasm.zst", "wasm-zst"),
            ("main.wasm.gz", "wasm-gzip!"),
        ] {
            std::fs::write(dir.path().join(name), data).unwrap();
        }
        let app = handler(dir.path()).unwrap();
        for (encoding, body) in [
            ("zstd, gzip", "wasm-zst"),
            ("gzip", "wasm-gzip!"),
            ("zstd;q=0, gzip;q=0", "wasm-uncompressed"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/main.wasm")
                        .header("Accept-Encoding", encoding)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["X-Uncompressed-Size"], "17");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap(),
                body
            );
        }
        for path in ["/nope", "/main.wasm.zst", "/../Cargo.toml"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        std::fs::remove_file(dir.path().join("main.wasm")).unwrap();
        assert!(handler(dir.path()).is_err());
    }
}
