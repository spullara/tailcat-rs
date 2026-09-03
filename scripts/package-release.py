#!/usr/bin/env python3
"""Package an already-built native Rust binary without publishing anything."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


TARGETS = {
    "x86_64-unknown-linux-musl": ("linux", "amd64", "amd64"),
    "aarch64-unknown-linux-musl": ("linux", "arm64", "arm64"),
    "armv7-unknown-linux-musleabihf": ("linux", "armv7", "arm7"),
    "x86_64-pc-windows-msvc": ("windows", "amd64", None),
    "aarch64-pc-windows-msvc": ("windows", "arm64", None),
    "x86_64-apple-darwin": ("darwin", "amd64", None),
    "aarch64-apple-darwin": ("darwin", "arm64", None),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--version", required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--archive-only", action="store_true")
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if not version or any(c in version for c in "/\\\r\n\0"):
        parser.error("version must be a nonempty file-name component")
    os_name, archive_arch, package_arch = TARGETS[args.target]
    binary_name = "tailcat.exe" if os_name == "windows" else "tailcat"
    binary = args.binary or Path("target") / args.target / "release" / binary_name
    if args.binary is None and not binary.is_file():
        # Cargo omits the target triple directory when building for the host.
        host = subprocess.check_output(["rustc", "-vV"], text=True)
        if f"host: {args.target}\n" in host:
            binary = Path("target/release") / binary_name
    if not binary.is_file():
        parser.error(f"missing native binary: {binary}; build with --target {args.target}")
    args.output.mkdir(parents=True, exist_ok=True)
    files = [(binary, binary_name)]
    for path in ["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "third_party/boringtun/LICENSE"]:
        source = Path(path)
        if not source.is_file():
            parser.error(f"missing required release notice: {source}")
        files.append((source, path))
    stem = f"tailcat_{version}_{os_name}_{archive_arch}"
    archive = args.output / (stem + (".zip" if os_name == "windows" else ".tar.gz"))
    if os_name == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for source, name in files:
                output.write(source, name)
    else:
        with tarfile.open(archive, "w:gz") as output:
            for source, name in files:
                output.add(source, arcname=name, recursive=False)
    print(archive)
    if os_name != "linux" or args.archive_only:
        return
    if not shutil.which("nfpm"):
        parser.error("Linux packages require nfpm 2.47.0; use --archive-only to omit packages")
    config = {
        "name": "tailcat",
        "arch": package_arch,
        "platform": "linux",
        "version": version,
        "maintainer": "spullara",
        "description": "Control-plane-free TCP over WireGuard and DERP, implemented in Rust.",
        "homepage": "https://github.com/spullara/tailcat-rs",
        "license": "BSD-3-Clause",
        "contents": [
            {"src": str(binary.resolve()), "dst": "/usr/bin/tailcat", "file_info": {"mode": 0o755}},
            *[
                {"src": str(source.resolve()), "dst": "/usr/share/doc/tailcat/" + name}
                for source, name in files[1:]
            ],
        ],
    }
    with tempfile.TemporaryDirectory(prefix="tailcat-package-") as temporary:
        config_file = Path(temporary) / "nfpm.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        for kind in ["deb", "rpm"]:
            package = args.output / f"{stem}.{kind}"
            subprocess.run(["nfpm", "package", "--config", str(config_file), "--packager", kind, "--target", str(package)], check=True)


if __name__ == "__main__":
    main()
