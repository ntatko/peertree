"""Run PeerTree's repository checks in a local checkout."""

import argparse
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = os.pathsep.join((
    os.environ.get("PATH", os.defpath),
    str(Path.home() / ".cargo" / "bin"),
    str(Path.home() / ".local" / "homebrew" / "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
))


def run(*argv):
    if not shutil.which(argv[0], path=TOOL_PATH):
        raise SystemExit(f"Install {argv[0]} on this Mac to run this check.")
    print("$ " + shlex.join(argv), flush=True)
    subprocess.run(argv, cwd=ROOT, env={**os.environ, "PATH": TOOL_PATH}, check=True)


def lint():
    run("cargo", "fmt", "--all", "--", "--check")
    run("cargo", "fmt", "--manifest-path", "desktop/Cargo.toml", "--", "--check")
    run("cargo", "clippy", "--locked", "--offline", "--all-targets", "--", "-D", "warnings")
    for path in ("app.js", "desktop/frontend/launcher.js"):
        run("node", "--check", path)
    sources = [*ROOT.glob("*.py"), *ROOT.glob("ci/*.py"), *ROOT.glob("tests/*.py")]
    for source in sorted(sources):
        compile(source.read_bytes(), str(source.relative_to(ROOT)), "exec")
    print("Python syntax passed.", flush=True)
    with tempfile.TemporaryDirectory(prefix="peertree-swift-lint-") as cache:
        target = f"{platform.machine()}-apple-macosx15.0"
        for path in ("Launcher.swift", "Peer.swift"):
            run("xcrun", "swiftc", "-swift-version", "5", "-typecheck",
                "-module-cache-path", cache, "-target", target, path)


def test():
    run("cargo", "test", "--locked", "--offline")
    run("cargo", "build", "--locked", "--offline")
    run(sys.executable, "-B", "tests/headless.py")
    run(sys.executable, "-B", "tests/peer_majority.py")
    run(sys.executable, "-B", "tests/desktop_backend.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("lint", "test"))
    try:
        {"lint": lint, "test": test}[parser.parse_args().check]()
    except (subprocess.CalledProcessError, SyntaxError) as error:
        raise SystemExit(str(error))
