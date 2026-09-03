#!/usr/bin/env python3
"""Validate the crate identity and a release tag before publishing."""

import argparse
from pathlib import Path
import sys
import tomllib


def validate(package, ref_type, ref_name, publish):
    if package.get("name") != "tailcat":
        raise ValueError("the publishing workflow expects the tailcat package")
    if package.get("publish") != ["crates-io"]:
        raise ValueError("Cargo.toml must restrict publishing to crates-io")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("Cargo.toml must specify an explicit package version")
    expected = f"v{version}"
    if publish and ref_type != "tag":
        raise ValueError(f"publishing requires tag {expected}; use dry_run on branches")
    if ref_type == "tag" and ref_name != expected:
        raise ValueError(f"tag {ref_name!r} must match package version {expected!r}")
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref-type", choices=("branch", "tag"), required=True)
    parser.add_argument("--ref-name", required=True)
    parser.add_argument("--publish", choices=("true", "false"), required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    package = tomllib.loads((root / "Cargo.toml").read_text())["package"]
    try:
        version = validate(package, args.ref_type, args.ref_name, args.publish == "true")
    except ValueError as error:
        parser.error(str(error))
    mode = "publish" if args.publish == "true" else "dry-run"
    print(f"Validated tailcat {version} for {mode} from {args.ref_type} {args.ref_name}")


if __name__ == "__main__":
    sys.exit(main())
