#!/usr/bin/env python3
"""Test a Rust tailcat binary against an ephemeral, pinned Go reference checkout.

The default runs both Go-library/Rust-CLI and Go-CLI/Rust-CLI pairings.
Use --full-cli for the entire reference CLI suite, and --web-dist to also test
the Rust browser distribution against Go peers. No Go source is retained in
this repository. Git and Go are required; browser tests also require Chrome
or Chromium (CHROME_BIN selects its executable).
"""

import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile


REFERENCE_URL = "https://github.com/spullara/tailcat.git"
REFERENCE_COMMIT = "689b74e2405c18fbdf4b21a0610d8c1abae8f334"


def stop_process_tree(process):
    """Terminate a command and its test/build children, then reap the command."""
    if os.name == "nt":
        # CREATE_NEW_PROCESS_GROUP alone does not make Process.kill recursive.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    finally:
        if os.name != "nt":
            # The group may still contain children after its leader has exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()


def run(argv, *, cwd, env, timeout, capture=False):
    argv = [str(arg) for arg in argv]
    display = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    print("+ " + display, flush=True)
    options = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE if capture else None,
        text=True,
        **options,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except BaseException:
        stop_process_tree(process)
        raise
    if process.returncode:
        stop_process_tree(process)
        raise subprocess.CalledProcessError(process.returncode, argv)
    return output


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, required=True,
        help="already-built native Rust tailcat executable",
    )
    parser.add_argument(
        "--full-cli", action="store_true",
        help="run all reference CLI tests instead of only mixed Go/Rust tests",
    )
    parser.add_argument(
        "--web-dist", type=Path,
        help="also test an already-built Rust browser distribution",
    )
    args = parser.parse_args()
    args.binary = args.binary.expanduser().resolve()
    if not args.binary.is_file():
        parser.error(f"native binary does not exist: {args.binary}")
    if os.name != "nt" and not os.access(args.binary, os.X_OK):
        parser.error(f"native binary is not executable: {args.binary}")
    if args.web_dist is not None:
        args.web_dist = args.web_dist.expanduser().resolve()
        for name in ("index.html", "app.js", "tailcat.js", "main.wasm"):
            if not (args.web_dist / name).is_file():
                parser.error(
                    f"browser distribution is missing {args.web_dist / name}; "
                    "build it with tailcat-webdist"
                )
    for tool in ("git", "go"):
        if shutil.which(tool) is None:
            parser.error(f"{tool} is required for external Go interoperability tests")
    if not re.fullmatch(r"[0-9a-f]{40}", REFERENCE_COMMIT):
        parser.error("the reference revision must be a complete Git commit ID")
    return args


def main():
    args = parse_args()
    env = os.environ.copy()
    # Avoid an inherited Git repository context redirecting commands outside
    # the disposable checkout; retain proxy/certificate/credential settings.
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX",
        "GIT_INTERNAL_SUPER_PREFIX", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE",
        "GIT_QUARANTINE_PATH", "GIT_REPLACE_REF_BASE",
    ):
        env.pop(name, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GOWORK"] = "off"
    env["TAILCAT_TEST_BINARY"] = str(args.binary)
    if args.web_dist is not None:
        env["TAILCAT_WEB_DIST"] = str(args.web_dist)

    # A fixed HTTPS URL and full commit ID keep the oracle reproducible. Fetch
    # into a fresh directory each time; no shared checkout can be edited or
    # accidentally substituted for the pinned source.
    with tempfile.TemporaryDirectory(prefix="tailcat-go-reference-") as temp:
        root = Path(temp)
        reference = root / "reference"
        hooks = root / "empty-hooks"
        hooks.mkdir()
        git = ["git", "-c", "core.bare=false", "-c", f"core.hooksPath={hooks}"]
        run([*git, "init", "--quiet", str(reference)], cwd=root, env=env, timeout=60)
        git += [f"--git-dir={reference / '.git'}", f"--work-tree={reference}"]
        run(
            [*git, "fetch", "--depth=1", "--no-tags", REFERENCE_URL, REFERENCE_COMMIT],
            cwd=reference, env=env, timeout=180,
        )
        run(
            [*git, "checkout", "--quiet", "--detach", "FETCH_HEAD"],
            cwd=reference, env=env, timeout=60,
        )
        actual = run(
            [*git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=reference, env=env, timeout=30, capture=True,
        ).strip()
        if actual != REFERENCE_COMMIT:
            raise RuntimeError(f"reference checkout is {actual}, expected {REFERENCE_COMMIT}")
        print(f"Testing against {REFERENCE_URL} at {actual}", flush=True)

        native = ["go", "test", "-count=1", "-timeout=600s", "-v"]
        if not args.full_cli:
            native += ["-run", "^TestRustInterop"]
        native.append("./cmd/tailcat")
        # The subprocess budget also covers downloading Go's pinned toolchain
        # and compiling dependencies, which go test's -timeout does not cover.
        run(native, cwd=reference, env=env, timeout=1800)
        if args.web_dist is not None:
            run(
                [
                    "go", "test", "-count=1", "-timeout=180s", "-v", "-run",
                    "^TestBrowser", "./web", "-run-headless-browser-tests",
                ],
                cwd=reference,
                env=env,
                timeout=1200,
            )
    print("External Go interoperability checks passed; reference checkout removed.", flush=True)


if __name__ == "__main__":
    # Give timeout/cancellation paths the same cleanup as a terminal interrupt.
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    try:
        main()
    except KeyboardInterrupt:
        print("Interoperability checks interrupted.", file=sys.stderr)
        sys.exit(130)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Interoperability checks failed: {error}", file=sys.stderr)
        sys.exit(1)
