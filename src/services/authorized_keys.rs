// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
use anyhow::{Context, Result, bail};
use russh::keys::PublicKey;
use std::io::Read;

const MAX_SIZE: usize = 1 << 20;

/// Parse plain OpenSSH public keys, rejecting restrictions this server cannot enforce.
pub fn parse_authorized_keys(text: &str) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let kind = line.split_whitespace().next().unwrap();
        if !kind.starts_with("ssh-") && !kind.starts_with("ecdsa-") && !kind.starts_with("sk-") {
            bail!("authorized-key options are not supported");
        }
        keys.push(PublicKey::from_openssh(line).context("invalid SSH public key")?);
    }
    if keys.is_empty() {
        bail!("no SSH public keys found");
    }
    Ok(keys)
}

pub async fn load_authorized_keys(sources: &str) -> Result<Vec<PublicKey>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut keys = Vec::new();
    for source in sources.split(',').map(str::trim) {
        if source.is_empty() {
            bail!("authorized-key source is empty");
        }
        let text = if let Some(user) = source.strip_suffix("@github") {
            if user.is_empty()
                || user.len() > 39
                || !user.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                || user.starts_with('-')
                || user.ends_with('-')
            {
                bail!("invalid GitHub username");
            }
            let mut response = client
                .get(format!("https://github.com/{user}.keys"))
                .header("User-Agent", "tailcat")
                .send()
                .await?
                .error_for_status()?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if bytes.len() + chunk.len() > MAX_SIZE {
                    bail!("GitHub key list is too large");
                }
                bytes.extend_from_slice(&chunk);
            }
            String::from_utf8(bytes)?
        } else if let Ok(file) = std::fs::File::open(source) {
            let mut text = String::new();
            file.take(MAX_SIZE as u64 + 1).read_to_string(&mut text)?;
            if text.len() > MAX_SIZE {
                bail!("authorized-key file is too large");
            }
            text
        } else {
            source.to_owned()
        };
        keys.extend(parse_authorized_keys(&text)?);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_keys_and_unsupported_restrictions() {
        let private =
            russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let key = private.public_key().to_openssh().unwrap();
        assert_eq!(
            parse_authorized_keys(&format!("# comment\n{key}\n"))
                .unwrap()
                .len(),
            1
        );
        assert!(parse_authorized_keys("# empty").is_err());
        assert!(parse_authorized_keys(&format!("no-pty {key}")).is_err());
        assert!(parse_authorized_keys("ssh-ed25519 broken").is_err());
    }
}
