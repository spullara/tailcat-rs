//! Tailcat's stable wire vocabulary: keys, compact addresses, meow and disco.
//!
//! These encodings are intentionally independent of the networking backend.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore},
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng, seq::SliceRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const DEFAULT_DERP_MAP_URL: &str = "https://tailcat.dev/derpmap.json";
pub const DISCO_MAGIC: &[u8] = b"TS\xf0\x9f\x92\xac";
const MAX_ADDRESS_BYTES: usize = 1 << 20;

/// A Curve25519 node identity. Debug output deliberately excludes secret bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn new() -> Self {
        let mut raw = [0; 32];
        OsRng.fill_bytes(&mut raw);
        clamp(&mut raw);
        Self(raw)
    }

    pub fn public(&self) -> [u8; 32] {
        x25519_dalek::x25519(self.0, x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    pub fn disco_private(&self) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC accepts any key");
        mac.update(b"github.com/tailscale/tailcat disco key v1");
        let mut raw: [u8; 32] = mac.finalize().into_bytes().into();
        clamp(&mut raw);
        raw
    }

    pub fn disco_public(&self) -> [u8; 32] {
        x25519_dalek::x25519(self.disco_private(), x25519_dalek::X25519_BASEPOINT_BYTES)
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "privkey:{}", hex::encode(self.0))
    }
}
impl FromStr for PrivateKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(parse_hex_key(s, "privkey:")?))
    }
}
impl Serialize for PrivateKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

fn clamp(raw: &mut [u8; 32]) {
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
}

pub fn parse_hex_key(s: &str, prefix: &str) -> Result<[u8; 32]> {
    let hex = s
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("key must start with {prefix}"))?;
    let mut raw = [0; 32];
    hex::decode_to_slice(hex, &mut raw).context("key must contain exactly 32 hex-encoded bytes")?;
    Ok(raw)
}

fn serialize_node_key<S: Serializer>(key: &[u8; 32], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&format!("nodekey:{}", hex::encode(key)))
}
fn deserialize_node_key<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<[u8; 32], D::Error> {
    parse_hex_key(&String::deserialize(d)?, "nodekey:").map_err(serde::de::Error::custom)
}
fn serialize_disco_key<S: Serializer>(
    key: &Option<[u8; 32]>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match key {
        Some(k) => s.serialize_str(&format!("discokey:{}", hex::encode(k))),
        None => s.serialize_none(),
    }
}
fn deserialize_disco_key<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<[u8; 32]>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|s| parse_hex_key(&s, "discokey:").map_err(serde::de::Error::custom))
        .transpose()
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConnInfo {
    #[serde(
        serialize_with = "serialize_node_key",
        deserialize_with = "deserialize_node_key"
    )]
    pub server_public: [u8; 32],
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_disco_key",
        deserialize_with = "deserialize_disco_key"
    )]
    pub server_disco_public: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub region: Vec<Region>,
    #[serde(rename = "RegionID", skip_serializing_if = "is_zero")]
    pub region_id: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Region {
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Node {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub host_name: String,
    pub cert_name: String,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    pub ipv6: String,
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpMap {
    pub regions: BTreeMap<i64, Region>,
}

impl ConnInfo {
    pub fn addr(&self) -> Result<String> {
        encode_addr(self)
    }
    pub fn for_key(key: &PrivateKey) -> Self {
        Self {
            server_public: key.public(),
            server_disco_public: Some(key.disco_public()),
            ..Self::default()
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn expand(&mut self, url: Option<&str>, is_server: bool) -> Result<()> {
        expand(self, url, is_server).await
    }
}

fn field(name: &str, value: Value) -> (Value, Value) {
    (Value::Text(name.into()), value)
}
fn push_string(fields: &mut Vec<(Value, Value)>, name: &str, text: &str) {
    if !text.is_empty() {
        fields.push(field(name, Value::Text(text.into())));
    }
}
fn push_int(fields: &mut Vec<(Value, Value)>, name: &str, number: i64) {
    if number != 0 {
        fields.push(field(name, Value::Integer(number.into())));
    }
}

pub fn encode_addr(ci: &ConnInfo) -> Result<String> {
    let mut fields = vec![field("p", Value::Bytes(ci.server_public.to_vec()))];
    if let Some(key) = ci.server_disco_public.filter(|k| *k != [0; 32]) {
        fields.push(field("k", Value::Bytes(key.to_vec())));
    }
    if !ci.region.is_empty() {
        let regions = ci
            .region
            .iter()
            .map(|r| {
                let nodes: Vec<Value> = r
                    .nodes
                    .iter()
                    .filter(|n| !n.stun_only)
                    .map(|n| {
                        let mut fields = Vec::new();
                        if n.host_name.is_empty() {
                            push_string(&mut fields, "n", &n.name);
                        }
                        push_string(&mut fields, "h", &n.host_name);
                        push_string(&mut fields, "t", &n.cert_name);
                        push_string(&mut fields, "4", &n.ipv4);
                        push_string(&mut fields, "6", &n.ipv6);
                        push_int(&mut fields, "s", i64::from(n.stun_port));
                        push_int(&mut fields, "d", i64::from(n.derp_port));
                        if n.insecure_for_tests {
                            fields.push(field("x", Value::Bool(true)));
                        }
                        Value::Map(fields)
                    })
                    .collect();
                Value::Map(if nodes.is_empty() {
                    vec![]
                } else {
                    vec![field("N", Value::Array(nodes))]
                })
            })
            .collect();
        fields.push(field("r", Value::Array(regions)));
    }
    push_int(&mut fields, "i", ci.region_id);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(fields), &mut bytes)?;
    Ok(format!("tc{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn decode_addr(addr: &str) -> Result<Value> {
    let rest = addr
        .strip_prefix("tc")
        .ok_or_else(|| anyhow!("tailcat address doesn't start with \"tc\""))?;
    if rest.len() > MAX_ADDRESS_BYTES * 4 / 3 + 4 {
        bail!("tailcat address is too large");
    }
    let bytes = URL_SAFE_NO_PAD.decode(rest).context("base64 decode")?;
    let mut reader = bytes.as_slice();
    let value = ciborium::de::from_reader(&mut reader).context("CBOR unmarshal")?;
    if !reader.is_empty() {
        bail!("trailing data after CBOR address");
    }
    Ok(value)
}

fn as_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(m) => Ok(m),
        _ => bail!("expected CBOR map"),
    }
}
fn lookup<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    fields.iter().rev().find_map(|(k, v)| {
        if k.as_text() == Some(name) {
            Some(v)
        } else {
            None
        }
    })
}
fn read_int(fields: &[(Value, Value)], name: &str) -> Result<i64> {
    match lookup(fields, name) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Integer(i)) => i64::try_from(*i).context("integer out of range"),
        _ => bail!("{name} must be an integer"),
    }
}
fn read_string(fields: &[(Value, Value)], name: &str) -> Result<String> {
    match lookup(fields, name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => bail!("{name} must be text"),
    }
}
fn read_bool(fields: &[(Value, Value)], name: &str) -> Result<bool> {
    match lookup(fields, name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        _ => bail!("{name} must be a boolean"),
    }
}
fn read_array<'a>(fields: &'a [(Value, Value)], name: &str) -> Result<&'a [Value]> {
    match lookup(fields, name) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        _ => bail!("{name} must be an array"),
    }
}
fn read_key(fields: &[(Value, Value)], name: &str) -> Result<Option<[u8; 32]>> {
    match lookup(fields, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bytes(b)) => {
            Ok(Some(b.as_slice().try_into().map_err(|_| {
                anyhow!("invalid public key length {}, want 32", b.len())
            })?))
        }
        _ => bail!("{name} must be a 32-byte CBOR byte string"),
    }
}

pub fn parse_addr(addr: &str) -> Result<ConnInfo> {
    let value = decode_addr(addr)?;
    let fields = as_map(&value)?;
    let mut ci = ConnInfo {
        server_public: read_key(fields, "p")?.unwrap_or_default(),
        server_disco_public: read_key(fields, "k")?,
        region_id: read_int(fields, "i")?,
        region: Vec::new(),
    };
    for (ri, value) in read_array(fields, "r")?.iter().enumerate() {
        if matches!(value, Value::Null) {
            bail!("invalid tailcat address: region {ri} is null");
        }
        let fields = as_map(value)?;
        let id = read_int(fields, "i")?;
        let mut r = Region {
            region_id: if id == 0 { ri as i64 + 1 } else { id },
            region_code: read_string(fields, "c")?,
            region_name: read_string(fields, "m")?,
            nodes: Vec::new(),
        };
        if r.region_code.is_empty() {
            r.region_code = r.region_id.to_string();
        }
        for (ni, value) in read_array(fields, "N")?.iter().enumerate() {
            if matches!(value, Value::Null) {
                bail!("invalid tailcat address: region {ri} node {ni} is null");
            }
            let fields = as_map(value)?;
            let mut n = Node {
                name: read_string(fields, "n")?,
                region_id: read_int(fields, "i")?,
                host_name: read_string(fields, "h")?,
                cert_name: read_string(fields, "t")?,
                ipv4: read_string(fields, "4")?,
                ipv6: read_string(fields, "6")?,
                stun_port: read_int(fields, "s")?
                    .try_into()
                    .context("invalid STUN port")?,
                derp_port: read_int(fields, "d")?
                    .try_into()
                    .context("invalid DERP port")?,
                insecure_for_tests: read_bool(fields, "x")?,
                stun_only: false,
            };
            if n.region_id == 0 {
                n.region_id = r.region_id;
            }
            if n.name.is_empty() {
                n.name.clone_from(&n.host_name);
            }
            r.nodes.push(n);
        }
        ci.region.push(r);
    }
    Ok(ci)
}

/// A diagnostic decode preserving null entries and implicit-field omissions.
pub fn parse_addr_raw(addr: &str) -> Result<serde_json::Value> {
    fn convert(value: &Value, level: usize) -> Result<serde_json::Value> {
        if matches!(value, Value::Null) {
            return Ok(serde_json::Value::Null);
        }
        let fields = as_map(value)?;
        let mut out = serde_json::Map::new();
        if level == 0 {
            out.insert(
                "ServerPublic".into(),
                format!(
                    "nodekey:{}",
                    hex::encode(read_key(fields, "p")?.unwrap_or_default())
                )
                .into(),
            );
            if let Some(k) = read_key(fields, "k")? {
                out.insert(
                    "ServerDiscoPublic".into(),
                    format!("discokey:{}", hex::encode(k)).into(),
                );
            }
        }
        for (short, long) in [("i", "RegionID"), ("s", "STUNPort"), ("d", "DERPPort")] {
            let v = read_int(fields, short)?;
            if v != 0 {
                out.insert(long.into(), v.into());
            }
        }
        for (short, long) in [
            ("c", "RegionCode"),
            ("m", "RegionName"),
            ("n", "Name"),
            ("h", "HostName"),
            ("t", "CertName"),
            ("4", "IPv4"),
            ("6", "IPv6"),
        ] {
            let v = read_string(fields, short)?;
            if !v.is_empty() {
                out.insert(long.into(), v.into());
            }
        }
        if read_bool(fields, "x")? {
            out.insert("InsecureForTests".into(), true.into());
        }
        let (short, long) = if level == 0 {
            ("r", "Region")
        } else {
            ("N", "Nodes")
        };
        let a = read_array(fields, short)?;
        if !a.is_empty() {
            out.insert(
                long.into(),
                serde_json::Value::Array(
                    a.iter()
                        .map(|v| convert(v, level + 1))
                        .collect::<Result<_>>()?,
                ),
            );
        }
        Ok(out.into())
    }
    convert(&decode_addr(addr)?, 0)
}

pub fn tc_addr_for_key(key: &[u8; 32]) -> Ipv6Addr {
    let mut raw = [
        0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    raw[6..].copy_from_slice(&key[..10]);
    Ipv6Addr::from(raw)
}

pub fn nat64_addr(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V6(a) => a,
        IpAddr::V4(a) => {
            let mut raw = [0; 16];
            raw[..4].copy_from_slice(&[0, 0x64, 0xff, 0x9b]);
            raw[12..].copy_from_slice(&a.octets());
            Ipv6Addr::from(raw)
        }
    }
}

pub fn unmap_nat64(addr: Ipv6Addr) -> IpAddr {
    let raw = addr.octets();
    if raw[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        IpAddr::from([raw[12], raw[13], raw[14], raw[15]])
    } else {
        IpAddr::V6(addr)
    }
}

pub fn encode_meow_ping(node: &[u8; 32], disco: &[u8; 32]) -> Vec<u8> {
    let mut b = b"meow\x01".to_vec();
    b.extend_from_slice(node);
    b.extend_from_slice(disco);
    b
}
pub fn encode_meowed() -> Vec<u8> {
    b"meow\x02".to_vec()
}
pub fn is_meow_packet(b: &[u8]) -> bool {
    b.starts_with(b"meow")
}
pub fn is_meowed_packet(b: &[u8]) -> bool {
    b.starts_with(b"meow\x02")
}
pub fn parse_meow_ping(b: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if b.len() < 69 || !b.starts_with(b"meow\x01") {
        return None;
    }
    let disco: [u8; 32] = b[37..69].try_into().ok()?;
    if disco == [0; 32] {
        return None;
    }
    Some((b[5..37].try_into().ok()?, disco))
}

/// NaCl's Curve25519/XSalsa20/Poly1305 box, including the 24-byte nonce.
pub fn seal_box(private: &[u8; 32], public: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    if *private == [0; 32] || *public == [0; 32] {
        bail!("cannot seal with zero key");
    }
    let cipher = SalsaBox::new(&PublicKey::from(*public), &SecretKey::from(*private));
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(&nonce, payload)
            .map_err(|_| anyhow!("NaCl box encryption failed"))?,
    );
    Ok(out)
}

pub fn open_box(private: &[u8; 32], public: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    if *private == [0; 32] || *public == [0; 32] || payload.len() < 40 {
        bail!("invalid NaCl box");
    }
    let cipher = SalsaBox::new(&PublicKey::from(*public), &SecretKey::from(*private));
    cipher
        .decrypt(payload[..24].into(), &payload[24..])
        .map_err(|_| anyhow!("NaCl box authentication failed"))
}

pub fn seal_disco(key: &PrivateKey, peer_disco: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    let mut b = DISCO_MAGIC.to_vec();
    b.extend_from_slice(&key.disco_public());
    b.extend(seal_box(&key.disco_private(), peer_disco, payload)?);
    Ok(b)
}

pub fn open_disco(key: &PrivateKey, packet: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if packet.len() < 78 || !packet.starts_with(DISCO_MAGIC) {
        bail!("invalid disco wrapper");
    }
    let public = packet[6..38].try_into()?;
    Ok((
        public,
        open_box(&key.disco_private(), &public, &packet[38..])?,
    ))
}

pub fn encode_call_me_maybe(endpoints: &[SocketAddr]) -> Vec<u8> {
    let mut b = vec![3, 0];
    for endpoint in endpoints {
        b.extend_from_slice(
            &match endpoint.ip() {
                IpAddr::V4(a) => a.to_ipv6_mapped(),
                IpAddr::V6(a) => a,
            }
            .octets(),
        );
        b.extend_from_slice(&endpoint.port().to_be_bytes());
    }
    b
}

pub fn parse_call_me_maybe(payload: &[u8]) -> Vec<SocketAddr> {
    if payload.len() < 2 || payload[..2] != [3, 0] || !(payload.len() - 2).is_multiple_of(18) {
        return vec![];
    }
    payload[2..]
        .chunks_exact(18)
        .map(|p| {
            let a = Ipv6Addr::from(<[u8; 16]>::try_from(&p[..16]).expect("chunk size"));
            SocketAddr::new(
                a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
                u16::from_be_bytes([p[16], p[17]]),
            )
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct CachedMap {
    data: Vec<u8>,
    etag: String,
    stored_at: std::time::SystemTime,
}
#[cfg(not(target_arch = "wasm32"))]
static MAP_CACHE: OnceLock<Mutex<HashMap<String, CachedMap>>> = OnceLock::new();
#[cfg(not(target_arch = "wasm32"))]
static DISK_CACHE: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Opt into the CLI's persistent DERP-map cache. Libraries otherwise cache only
/// in memory. The on-disk format is compatible with the Go CLI.
#[cfg(not(target_arch = "wasm32"))]
pub fn enable_disk_derp_cache() {
    if let Some(dir) = dirs::cache_dir() {
        let _ = DISK_CACHE.set(dir.join("tailcat"));
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn cache_paths(dir: &std::path::Path, url: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut escaped = String::new();
    for byte in url.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(byte as char)
            }
            b' ' => escaped.push('+'),
            _ => {
                use std::fmt::Write;
                let _ = write!(escaped, "%{byte:02X}");
            }
        }
    }
    (
        dir.join(format!("derpmap-{escaped}.json")),
        dir.join(format!("derpmap-{escaped}.etag")),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn read_disk_cache(dir: &std::path::Path, url: &str) -> Option<CachedMap> {
    use std::io::Read;
    let (path, etag_path) = cache_paths(dir, url);
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > 8 << 20 {
        return None;
    }
    let mut data = Vec::new();
    file.take((8 << 20) + 1).read_to_end(&mut data).ok()?;
    if data.len() > 8 << 20 {
        return None;
    }
    serde_json::from_slice::<DerpMap>(&data).ok()?;
    let etag = std::fs::read_to_string(etag_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    Some(CachedMap {
        data,
        etag,
        stored_at: metadata.modified().ok()?,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn write_disk_cache(dir: &std::path::Path, url: &str, entry: &CachedMap) -> Result<()> {
    use std::io::Write;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let (path, etag_path) = cache_paths(dir, url);
    // Publish complete JSON atomically. Failures only discard the optional
    // cache; they must never turn a successful network response into an error.
    let temporary = dir.join(format!(
        ".derpmap-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&entry.data)?;
        file.sync_all()?;
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(&path);
        }
        std::fs::rename(&temporary, &path)?;
        if entry.etag.is_empty() {
            let _ = std::fs::remove_file(etag_path);
        } else {
            std::fs::write(etag_path, &entry.etag)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn fetch_derp_map(url: Option<&str>, is_server: bool) -> Result<DerpMap> {
    fetch_derp_map_cached(
        url.unwrap_or(DEFAULT_DERP_MAP_URL),
        is_server,
        DISK_CACHE.get().map(std::path::PathBuf::as_path),
    )
    .await
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_derp_map_cached(
    url: &str,
    is_server: bool,
    disk: Option<&std::path::Path>,
) -> Result<DerpMap> {
    let cache = MAP_CACHE.get_or_init(Mutex::default);
    let cached = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(url)
        .cloned()
        .or_else(|| disk.and_then(|dir| read_disk_cache(dir, url)));
    if let Some(c) = &cached
        && c.stored_at.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(3600)
        && let Ok(map) = serde_json::from_slice(&c.data)
    {
        return Ok(map);
    }
    let store = |entry: CachedMap| {
        if let Some(dir) = disk {
            let _ = write_disk_cache(dir, url, &entry);
        }
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(url.into(), entry);
    };
    let fetch = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let mut request = client
            .get(url)
            .header("Tailcat-Mode", if is_server { "server" } else { "client" });
        if let Some(c) = &cached
            && !c.etag.is_empty()
        {
            request = request.header("If-None-Match", &c.etag);
        }
        let mut res = request.send().await?;
        if res.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(mut c) = cached.clone() {
                let map: DerpMap = serde_json::from_slice(&c.data)?;
                c.stored_at = std::time::SystemTime::now();
                store(c);
                return Ok(map);
            }
            bail!("DERP map returned 304 without a cached representation");
        }
        res.error_for_status_ref()?;
        let etag = res
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut data = Vec::new();
        while let Some(chunk) = res.chunk().await? {
            if data.len() + chunk.len() > 8 << 20 {
                bail!("DERP map exceeds 8 MiB");
            }
            data.extend_from_slice(&chunk);
        }
        let map: DerpMap = serde_json::from_slice(&data).context("invalid DERP map JSON")?;
        store(CachedMap {
            data,
            etag,
            stored_at: std::time::SystemTime::now(),
        });
        Ok::<_, anyhow::Error>(map)
    }
    .await;
    match fetch {
        Ok(map) => Ok(map),
        Err(error) => match cached {
            Some(c) => serde_json::from_slice(&c.data).context(error),
            None => Err(error),
        },
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn expand(ci: &mut ConnInfo, url: Option<&str>, is_server: bool) -> Result<()> {
    for r in &mut ci.region {
        if r.region_id == 0 {
            r.region_id = 1;
        }
        for n in &mut r.nodes {
            if n.region_id == 0 {
                n.region_id = r.region_id;
            }
        }
    }
    if !ci.region.is_empty() || ci.region_id == 0 {
        return Ok(());
    }
    let mut dm = fetch_derp_map(url, is_server).await?;
    if ci.region_id == -1 {
        if dm.regions.is_empty() {
            bail!("failed to auto-detect any regions");
        }
        for r in dm.regions.values_mut() {
            r.nodes.shuffle(&mut rand::thread_rng());
        }
        let best = pick_best_region(&dm).await;
        let id = best.unwrap_or_else(|| {
            **dm.regions
                .keys()
                .collect::<Vec<_>>()
                .choose(&mut rand::thread_rng())
                .expect("nonempty regions")
        });
        ci.region = vec![dm.regions.remove(&id).expect("known region")];
        ci.region_id = 0;
    } else {
        ci.region
            .push(dm.regions.remove(&ci.region_id).ok_or_else(|| {
                anyhow!(
                    "tailcat address specified DERP RegionID {} but no such region exists in {}",
                    ci.region_id,
                    url.unwrap_or(DEFAULT_DERP_MAP_URL)
                )
            })?);
    }
    Ok(())
}

/// Probe relay STUN servers concurrently; no privileged/raw sockets are required.
#[cfg(not(target_arch = "wasm32"))]
pub async fn pick_best_region(dm: &DerpMap) -> Option<i64> {
    let mut tasks = tokio::task::JoinSet::new();
    for (id, region) in &dm.regions {
        for node in region.nodes.iter().filter(|n| n.stun_port >= 0).take(2) {
            let id = *id;
            let node = node.clone();
            tasks.spawn(async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    let host = if !node.ipv4.is_empty() && node.ipv4 != "none" {
                        node.ipv4.as_str()
                    } else {
                        node.host_name.as_str()
                    };
                    let target = tokio::net::lookup_host((
                        host,
                        if node.stun_port == 0 {
                            3478
                        } else {
                            node.stun_port as u16
                        },
                    ))
                    .await?
                    .find(SocketAddr::is_ipv4)
                    .ok_or_else(|| anyhow!("no IPv4 STUN address"))?;
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                    let mut request = [0u8; 20];
                    request[1] = 1;
                    request[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
                    OsRng.fill_bytes(&mut request[8..]);
                    let now = Instant::now();
                    socket.send_to(&request, target).await?;
                    let mut response = [0u8; 2048];
                    let (len, source) = socket.recv_from(&mut response).await?;
                    if source != target
                        || len < 20
                        || response[..2] != [1, 1]
                        || response[4..20] != request[4..20]
                    {
                        bail!("invalid STUN response");
                    }
                    Ok::<_, anyhow::Error>((id, now.elapsed()))
                })
                .await
                .ok()
                .and_then(Result::ok)
            });
        }
    }
    let mut best = None;
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some((id, latency))) = result
            && best.is_none_or(|(_, b)| latency < b)
        {
            best = Some((id, latency));
        }
    }
    best.map(|(id, _)| id)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn resolve_addr(addr: &str, url: Option<&str>) -> Result<String> {
    let mut ci = parse_addr(addr)?;
    if !ci.region.is_empty() {
        return Ok(addr.into());
    }
    expand(&mut ci, url, false).await?;
    for region in &mut ci.region {
        region.nodes.truncate(2);
    }
    ci.region_id = 0;
    encode_addr(&ci)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn persistent_map_cache_freshness_revalidation_and_stale_fallback() {
        use axum::{
            Router,
            http::{HeaderMap, StatusCode},
            response::IntoResponse,
            routing::get,
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let data = r#"{"Regions":{"1":{"RegionID":1,"RegionCode":"test","Nodes":[]}}}"#;
        let app = Router::new().route(
            "/",
            get(move |headers: HeaderMap| {
                let seen = seen.clone();
                async move {
                    match seen.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            assert_eq!(headers["Tailcat-Mode"], "server");
                            (StatusCode::OK, [("ETag", "\"map-v1\"")], data).into_response()
                        }
                        1 => {
                            assert_eq!(headers["If-None-Match"], "\"map-v1\"");
                            StatusCode::NOT_MODIFIED.into_response()
                        }
                        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let first = fetch_derp_map_cached(&url, true, Some(dir.path()))
            .await
            .unwrap();
        assert_eq!(first.regions[&1].region_code, "test");
        let cached = read_disk_cache(dir.path(), &url).unwrap();
        assert_eq!(cached.etag, "\"map-v1\"");
        assert!(
            cache_paths(dir.path(), &url)
                .0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("http%3A%2F%2F")
        );
        // Simulate a fresh process: the Go-compatible disk cache avoids HTTP.
        MAP_CACHE.get().unwrap().lock().unwrap().remove(&url);
        fetch_derp_map_cached(&url, false, Some(dir.path()))
            .await
            .unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        // Expire the disk entry, then revalidate its opaque ETag.
        let stale = std::time::SystemTime::now() - Duration::from_secs(7200);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(cache_paths(dir.path(), &url).0)
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(stale))
            .unwrap();
        fetch_derp_map_cached(&url, false, Some(dir.path()))
            .await
            .unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        MAP_CACHE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .get_mut(&url)
            .unwrap()
            .stored_at = stale;
        let fallback = fetch_derp_map_cached(&url, false, Some(dir.path()))
            .await
            .unwrap();
        assert_eq!(fallback.regions, first.regions);
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        task.abort();
    }

    #[test]
    fn go_address_vectors() {
        let mut key = [0; 32];
        key[1] = 1;
        key[2] = 2;
        key[31] = 31;
        for (region_id, addr) in [
            (0, "tcoWFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHw"),
            (
                10,
                "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg",
            ),
        ] {
            let ci = ConnInfo {
                server_public: key,
                region_id,
                ..Default::default()
            };
            assert_eq!(encode_addr(&ci).unwrap(), addr);
            assert_eq!(parse_addr(addr).unwrap(), ci);
        }
    }

    #[test]
    fn embeds_only_required_fields() {
        let key = PrivateKey([7; 32]);
        let mut ci = ConnInfo::for_key(&key);
        ci.region.push(Region {
            region_id: 123,
            region_code: "sea".into(),
            region_name: "Seattle".into(),
            nodes: vec![
                Node {
                    name: "10a".into(),
                    region_id: 123,
                    host_name: "relay.test".into(),
                    cert_name: "cert.test".into(),
                    ipv6: "none".into(),
                    stun_port: -1,
                    derp_port: 8443,
                    insecure_for_tests: true,
                    ..Default::default()
                },
                Node {
                    stun_only: true,
                    ..Default::default()
                },
            ],
        });
        let encoded = encode_addr(&ci).unwrap();
        let got = parse_addr(&encoded).unwrap();
        assert_eq!(got.region[0].region_id, 1);
        assert_eq!(got.region[0].region_code, "1");
        assert_eq!(got.region[0].nodes.len(), 1);
        assert_eq!(got.region[0].nodes[0].name, "relay.test");
        assert_eq!(got.region[0].nodes[0].cert_name, "cert.test");
        assert_eq!(encode_addr(&got).unwrap(), encoded);
    }

    fn raw_addr(v: Value) -> String {
        let mut raw = vec![];
        ciborium::ser::into_writer(&v, &mut raw).unwrap();
        format!("tc{}", URL_SAFE_NO_PAD.encode(raw))
    }

    #[test]
    fn malformed_addresses_are_errors() {
        for n in [0, 31, 33] {
            let addr = raw_addr(Value::Map(vec![field("p", Value::Bytes(vec![0; n]))]));
            assert!(parse_addr(&addr).is_err());
            assert!(parse_addr_raw(&addr).is_err());
        }
        for value in [
            Value::Null,
            Value::Map(vec![field("N", Value::Array(vec![Value::Null]))]),
        ] {
            let addr = raw_addr(Value::Map(vec![field("r", Value::Array(vec![value]))]));
            assert!(parse_addr(&addr).is_err());
            assert!(parse_addr_raw(&addr).is_ok());
        }
    }

    #[test]
    fn meow_fixed_offsets_and_trailers() {
        let ping = encode_meow_ping(&[1; 32], &[2; 32]);
        assert_eq!(ping.len(), 69);
        for n in 0..69 {
            assert!(parse_meow_ping(&ping[..n]).is_none());
        }
        assert_eq!(
            parse_meow_ping(&[ping, vec![3]].concat()),
            Some(([1; 32], [2; 32]))
        );
        assert!(parse_meow_ping(&encode_meow_ping(&[1; 32], &[0; 32])).is_none());
        assert!(is_meowed_packet(b"meow\x02extra"));
        assert!(!is_meow_packet(DISCO_MAGIC));
    }

    #[test]
    fn keys_and_disco_authenticate() {
        let a = PrivateKey([7; 32]);
        let b = PrivateKey([8; 32]);
        assert_ne!(a.public(), a.disco_public());
        assert_eq!(a.disco_public(), a.clone().disco_public());
        assert_eq!(a.to_string().parse::<PrivateKey>().unwrap(), a);
        let packet = seal_disco(&a, &b.disco_public(), b"test").unwrap();
        assert_eq!(
            open_disco(&b, &packet).unwrap(),
            (a.disco_public(), b"test".to_vec())
        );
        let mut corrupted = packet;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(open_disco(&b, &corrupted).is_err());
    }

    #[test]
    fn endpoint_and_nat64_roundtrips() {
        let endpoints = [
            "192.0.2.1:1234".parse().unwrap(),
            "[2001:db8::1]:2345".parse().unwrap(),
        ];
        assert_eq!(
            parse_call_me_maybe(&encode_call_me_maybe(&endpoints)),
            endpoints
        );
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(nat64_addr(ip).to_string(), "64:ff9b::c000:201");
        assert_eq!(unmap_nat64(nat64_addr(ip)), ip);
        assert_eq!(tc_addr_for_key(&[0; 32]).to_string(), "fd7a:115c:a1e0::");
    }

    #[test]
    fn json_uses_go_key_and_field_names() {
        let ci = ConnInfo::for_key(&PrivateKey([7; 32]));
        let json = serde_json::to_value(&ci).unwrap();
        assert!(
            json["ServerPublic"]
                .as_str()
                .unwrap()
                .starts_with("nodekey:")
        );
        assert!(
            json["ServerDiscoPublic"]
                .as_str()
                .unwrap()
                .starts_with("discokey:")
        );
        assert_eq!(serde_json::from_value::<ConnInfo>(json).unwrap(), ci);
        let dm: DerpMap = serde_json::from_str(r#"{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"localhost","IPv4":"127.0.0.1","DERPPort":443}]}}}"#).unwrap();
        assert_eq!(dm.regions[&1].nodes[0].ipv4, "127.0.0.1");
    }
}
