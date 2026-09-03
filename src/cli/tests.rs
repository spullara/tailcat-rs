use super::{args::*, keys::*, util::*};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const ADDRESS: &str = "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg";
fn parse(args: &[&str]) -> Args {
    Args::parse(args.iter().map(|s| s.to_string())).unwrap()
}

#[test]
fn command_tree_and_flag_placement() {
    for command in COMMANDS {
        assert!(help("").contains(command));
    }
    assert!(help("serve").contains("--allow"));
    assert!(!help("").contains("--allow"));
    for input in [
        vec![
            "--key=new",
            "--derpmap-url=http://d/",
            "ping",
            "--timeout=5s",
            "tcaddr",
        ],
        vec![
            "ping",
            "--key=new",
            "--derpmap-url=http://d/",
            "--timeout=5s",
            "tcaddr",
        ],
    ] {
        let args = parse(&input);
        assert_eq!(args.command, "ping");
        assert_eq!(args.key, "new");
        assert_eq!(args.derp_map_url, "http://d/");
        assert_eq!(args.timeout, Duration::from_secs(5));
    }
    assert_eq!(parse(&["tcSOMEBLOB", "80"]).command, "");
    assert!(Args::parse(["--allow=none".into()]).is_err());
}

#[test]
fn parsing_stops_at_first_positional() {
    let ssh = parse(&["ssh", "-p", "2222", "user@tcaddr", "ls", "-la"]);
    assert_eq!(ssh.port, "2222");
    assert_eq!(ssh.positional, ["user@tcaddr", "ls", "-la"]);
    let socks = parse(&[
        "socks",
        "--listen=1080",
        "tcaddr",
        "curl",
        "--fail",
        "http://x/",
    ]);
    assert_eq!(socks.listen, "1080");
    assert_eq!(socks.positional, ["tcaddr", "curl", "--fail", "http://x/"]);
    let serve = parse(&["serve", "--key=new", "80,no-auth-ssh", "8000-8999"]);
    assert_eq!(serve.key, "new");
    assert_eq!(serve.positional, ["80,no-auth-ssh", "8000-8999"]);
    assert_eq!(parse(&["genkey", "--key=example"]).genkey_key, "example");
    assert_eq!(parse(&["--key=example", "genkey"]).key, "example");
}

#[test]
fn explicit_help_and_version() {
    for input in [
        vec!["-h"],
        vec!["--help"],
        vec!["help"],
        vec!["genkey", "--help"],
        vec!["ssh", "-h"],
        vec!["--serve"],
    ] {
        assert!(parse(&input).help);
    }
    assert_eq!(parse(&["--serve"]).command, "serve");
    assert_eq!(parse(&["--version"]).command, "version");
    assert_eq!(
        parse_duration("1m2.5s").unwrap(),
        Duration::from_millis(62500)
    );
    assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    for value in ["-1s", "123", "NaNs", "1year"] {
        assert!(parse_duration(value).is_err(), "{value}");
    }
}

#[test]
fn dns_classification_protects_address_secrets() {
    assert_eq!(
        classify_address(ADDRESS).unwrap(),
        AddressArg::Address(ADDRESS.into())
    );
    for name in [
        "server.example.com",
        "server.example.com.",
        "tc-server.example.com",
    ] {
        assert_eq!(
            classify_address(name).unwrap(),
            AddressArg::DnsName(name.into())
        );
    }
    for name in [format!("{ADDRESS}."), format!("prefix.{ADDRESS}.example")] {
        assert!(
            classify_address(&name)
                .unwrap_err()
                .to_string()
                .contains("refusing DNS lookup")
        );
    }
    for name in [
        "server_name.example",
        "server..example",
        "not-an-address",
        "-bad.example",
        "bad-.example",
        "bad.éxample",
    ] {
        assert!(classify_address(name).is_err(), "{name}");
    }
    assert!(classify_address(&format!("{}.example", "a".repeat(64))).is_err());
}

#[test]
fn remote_paths_keep_local_colons_and_windows_drives() {
    for (arg, expected) in [
        ("tcBLOB:foo.txt", Some(("tcBLOB", "foo.txt"))),
        ("tcBLOB:", Some(("tcBLOB", ""))),
        ("example.com:dir/foo", Some(("example.com", "dir/foo"))),
        ("foo.txt", None),
        ("./dir:with:colons", None),
        (r"C:\Users\foo", None),
        ("C:/Users/foo", None),
        (":leading-colon", None),
    ] {
        assert_eq!(split_remote_arg(arg), expected);
    }
}

#[test]
fn ssh_port_validation_and_host_labels() {
    for (input, expected) in [
        ("22", "22"),
        ("0022", "22"),
        ("192.0.2.1", "192.0.2.1:22"),
        ("192.0.2.1:2222", "192.0.2.1:2222"),
        ("2001:db8::1", "[2001:db8::1]:22"),
        ("[2001:db8::1]:2222", "[2001:db8::1]:2222"),
    ] {
        assert_eq!(validated_ssh_port(input).unwrap(), expected);
    }
    for input in [
        "",
        "0",
        "65536",
        "22; touch /tmp/injected",
        "example.com:22",
        "+22",
    ] {
        assert!(validated_ssh_port(input).is_err(), "{input}");
    }
    let name = ssh_dest_host(ADDRESS);
    assert_eq!(name.len(), 24);
    assert!(name.starts_with("tailcat-"));
    assert_eq!(name, ssh_dest_host(ADDRESS));
    assert_ne!(name, ssh_dest_host("other"));
}

#[test]
fn ssh_proxy_inherits_identity_and_map() {
    let actual = ssh_proxy_command(
        "/path/to/tailcat",
        "client-default",
        "https://example.com/map",
        ADDRESS,
        "22",
    )
    .unwrap();
    assert!(actual.contains("--key=client-default"));
    assert!(actual.contains("--derpmap-url=https://example.com/map"));
    let actual =
        ssh_proxy_command("/path/to/tailcat", "", DEFAULT_DERP_MAP_URL, ADDRESS, "22").unwrap();
    assert!(!actual.contains("--key"));
    assert!(!actual.contains("--derpmap-url"));
}

#[cfg(unix)]
#[test]
fn proxy_command_quotes_shell_metacharacters() {
    let dir = tempfile::tempdir().unwrap();
    let injected = dir.path().join("injected");
    let key = format!("key $(touch {}) ' \" $HOME", injected.display());
    let url = format!(
        "https://example.invalid/`touch {}`?x=%h&y=two words",
        injected.display()
    );
    let command = proxy_command_join_unix(&[
        "printf".into(),
        "<%s>\\n".into(),
        key.clone(),
        url.clone(),
        "tc-safe".into(),
        "22".into(),
    ])
    .unwrap()
    .replace("%%", "%");
    let out = std::process::Command::new("sh")
        .args(["-c", &command])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("<{key}>\n<{url}>\n<tc-safe>\n<22>\n")
    );
    assert!(!injected.exists());
    for arg in ["line\nbreak", "nul\0", "carriage\r"] {
        assert!(proxy_command_join_unix(&[arg.into()]).is_err());
    }
}

#[test]
fn windows_proxy_quoting() {
    assert_eq!(
        proxy_command_join_windows(&[
            r"C:\Program Files\tailcat.exe".into(),
            "--key=a&b".into(),
            "tc-safe".into(),
            "22".into()
        ])
        .unwrap(),
        r#""C:\Program Files\tailcat.exe" "--key=a&b" "tc-safe" "22""#
    );
    assert_eq!(
        proxy_command_join_windows(&["C:\\tailcat\\".into()]).unwrap(),
        "\"C:\\tailcat\\\\\""
    );
    for arg in [
        "has\"quote",
        "has%percent",
        "has!bang",
        "has\nnewline",
        "has\0nul",
    ] {
        assert!(proxy_command_join_windows(&[arg.into()]).is_err());
    }
}

#[test]
fn forward_mappings() {
    for (value, listen, port, target) in [
        ("8080", "127.0.0.1:8080", 8080, None),
        ("18080:8080", "127.0.0.1:18080", 8080, None),
        ("1:65535", "127.0.0.1:1", 65535, None),
        ("0:8080", "127.0.0.1:0", 8080, None),
        (
            "13306:192.168.1.10:3306",
            "127.0.0.1:13306",
            0,
            Some("192.168.1.10:3306"),
        ),
        (
            "13306:[2001:db8::10]:3306",
            "127.0.0.1:13306",
            0,
            Some("[2001:db8::10]:3306"),
        ),
    ] {
        let mapping = parse_forward_spec("127.0.0.1", value).unwrap();
        assert_eq!(mapping.listen_addr, listen);
        assert_eq!(mapping.port, port);
        assert_eq!(mapping.target.map(|ap| ap.to_string()).as_deref(), target);
    }
    for value in ["0", "8080:0", "8080:bad", "8080:192.168.1.10:bad"] {
        assert!(parse_forward_spec("127.0.0.1", value).is_err(), "{value}");
    }
}

#[test]
fn listen_address_defaults() {
    for (input, expected) in [
        ("1234", "127.0.0.1:1234"),
        (":1234", ":1234"),
        ("127.0.0.1", "127.0.0.1:0"),
        ("[2001:db8::1]", "[2001:db8::1]:0"),
        ("foo", "foo:0"),
        ("localhost:", "localhost:0"),
    ] {
        assert_eq!(normalize_listen(input), expected);
    }
}

#[test]
fn service_sets_and_packet_filter_ranges() {
    let spec = parse_serve_spec("80,443,8002-8000,files,exit-node,0").unwrap();
    assert_eq!(spec.ports, BTreeSet::from([0, 80, 443, 8000, 8001, 8002]));
    assert_eq!(
        spec.services,
        BTreeSet::from(["files".into(), "exit-node".into()])
    );
    assert_eq!(
        port_ranges(&spec.ports),
        [(0, 0), (80, 80), (443, 443), (8000, 8002)]
    );
    assert_eq!(parse_serve_spec("all").unwrap().ports.len(), 65535);
    for value in ["http", "65536", "80,", "80-90-100"] {
        assert!(parse_serve_spec(value).is_err());
    }
}

#[test]
fn socks_destinations_and_ipv4_preference() {
    assert_eq!(
        classify_socks_target("server.tailcat", 8081, &[]).unwrap(),
        SocksTarget::Server(8081)
    );
    assert_eq!(
        classify_socks_target("", 80, &[]).unwrap(),
        SocksTarget::Server(80)
    );
    assert_eq!(
        classify_socks_target(ADDRESS, 8081, &[]).unwrap(),
        SocksTarget::Address(ADDRESS.into(), 8081)
    );
    assert_eq!(
        classify_socks_target("::ffff:1.2.3.4", 80, &[]).unwrap(),
        SocksTarget::Exit("1.2.3.4:80".parse::<SocketAddr>().unwrap())
    );
    let ips = [
        "2001:db8::1".parse::<IpAddr>().unwrap(),
        "192.0.2.1".parse::<IpAddr>().unwrap(),
    ];
    assert_eq!(
        classify_socks_target("example.com", 80, &ips).unwrap(),
        SocksTarget::Exit("192.0.2.1:80".parse().unwrap())
    );
    assert!(classify_socks_target("example.com", 80, &[]).is_err());
}

#[test]
fn secure_key_write_does_not_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    secure_write(&path, b"first", false).unwrap();
    assert!(secure_write(&path, b"second", false).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    secure_write(&path, b"second", true).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn key_validation_precedes_creation() {
    for args in [
        parse(&["genkey"]),
        parse(&["genkey", "--client"]),
        parse(&["genkey", "--client", "--key=default"]),
        parse(&["genkey", "--key=unused", "--client", "--region=auto"]),
        parse(&["genkey", "--key=unused", "--fixed-region", "--region=auto"]),
    ] {
        assert!(genkey(&args).await.is_err());
    }
}
