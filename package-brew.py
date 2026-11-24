#!/usr/bin/env python3
"""Build a universal PeerTree macOS app and generate its Homebrew cask."""

import argparse
import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile


VERSION = "0.5.0"
SOURCE = Path(__file__).resolve().parent
ICON = "desktop/frontend/peertree-icon.png"
RESOURCES = (
    "app.py", "agent.py", "lan.py", "peer.py", "quorum.py", "app.js", "index.html", "style.css", ICON,
    "assets/seti/theme.json", "assets/seti/seti.woff", "assets/seti/LICENSE.txt",
    "assets/marked/marked.umd.js", "assets/marked/LICENSE.md",
)
SERVICE = "_peertree-v2._tcp"
RUST_TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def swift(build, source, output, embedded_plist=None):
    compiled = []
    for architecture in ("arm64", "x86_64"):
        target = build / f"{output.name}-{architecture}"
        command = [
            "/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-O",
            "-module-cache-path", build / f"cache-{architecture}",
            "-target", f"{architecture}-apple-macosx15.0", SOURCE / source,
        ]
        if embedded_plist:
            command += ["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT",
                        "-Xlinker", "__info_plist", "-Xlinker", embedded_plist]
        run(*command, "-o", target)
        compiled.append(target)
    run("/usr/bin/lipo", "-create", *compiled, "-output", output)


def rust_core(build, output, targets=RUST_TARGETS):
    compiled = []
    for target in targets:
        libdir = subprocess.check_output(["rustc", "--print", "target-libdir", "--target", target],
                                         text=True).strip()
        if not Path(libdir).is_dir():
            raise SystemExit(f"Install the Rust standard library for {target} before building PeerTree.")
    directory = build / "cargo"
    for target in targets:
        run("cargo", "build", "--release", "--locked", "--offline", "--manifest-path", SOURCE / "Cargo.toml",
            "--target", target, "--target-dir", directory)
        compiled.append(directory / target / "release" / "peertree-core")
    run("/usr/bin/lipo", "-create", *compiled, "-output", output)


def rust_desktop(build, output):
    directory = build / "cargo"
    manifest = SOURCE / "desktop" / "Cargo.toml"
    if not manifest.with_name("Cargo.lock").is_file():
        raise SystemExit("Commit desktop/Cargo.lock before building a desktop release.")
    run("cargo", "fetch", "--locked", "--manifest-path", manifest)
    compiled = []
    for target in RUST_TARGETS:
        run("cargo", "build", "--release", "--locked", "--offline", "--manifest-path", manifest,
            "--features", "custom-protocol", "--target", target, "--target-dir", directory)
        compiled.append(directory / target / "release" / "peertree-desktop")
    run("/usr/bin/lipo", "-create", *compiled, "-output", output)


def app_icon(build, output):
    # Modern ICNS entries contain PNG images, with separate types for Retina sizes.
    entries = {
        16: (b"icp4",), 32: (b"icp5", b"ic11"), 64: (b"ic12",), 128: (b"ic07",),
        256: (b"ic08", b"ic13"), 512: (b"ic09", b"ic14"), 1024: (b"ic10",),
    }
    chunks = []
    for size, kinds in entries.items():
        target = build / f"icon-{size}.png"
        run("/usr/bin/sips", "-z", size, size, SOURCE / ICON, "--out", target)
        png = target.read_bytes()
        chunks.extend(kind + struct.pack(">I", len(png) + 8) + png for kind in kinds)
    body = b"".join(chunks)
    output.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)


def assemble(build, owner, signing_identity, desktop=False):
    app = build / "PeerTree.app"
    contents = app / "Contents"
    launcher = contents / "MacOS" / "peertree"
    windowed = launcher.with_name("peertree-desktop")
    helper = contents / "Helpers" / "peertree-peer"
    core = contents / "Helpers" / "peertree-core"
    resources = contents / "Resources"
    for path in (launcher.parent, helper.parent, resources):
        path.mkdir(parents=True)
    for name in RESOURCES:
        target = resources / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, target)
    app_icon(build, resources / "PeerTree.icns")
    info = {
        "CFBundleDisplayName": "PeerTree",
        "CFBundleExecutable": windowed.name if desktop else launcher.name,
        "CFBundleIconFile": "PeerTree.icns",
        "CFBundleIdentifier": f"io.github.{owner.lower()}.peertree",
        "CFBundleName": "PeerTree",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSMinimumSystemVersion": "15.0",
        "NSLocalNetworkUsageDescription": "Find paired teammates and exchange Git reviews over nearby Wi-Fi.",
        "NSBonjourServices": [SERVICE],
        "NSHighResolutionCapable": True,
    }
    if desktop:
        info.update(plistlib.loads((SOURCE / "desktop" / "Info.plist").read_bytes()))
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    swift(build, "Launcher.swift", launcher)
    swift(build, "Peer.swift", helper, SOURCE / "PeerInfo.plist")
    rust_core(build, core)
    if desktop:
        rust_desktop(build, windowed)
    signing = ["--options", "runtime", "--timestamp"] if signing_identity else []
    nested = (helper, core, launcher) if desktop else (helper, core)
    for item in (*nested, app):
        run("/usr/bin/codesign", "--force", "--sign", signing_identity or "-", *signing, item)
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)
    return app


def write_cask(path, archive, owner, repository):
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'''cask "peertree" do
  version "{VERSION}"
  sha256 "{checksum}"

  url "https://github.com/{owner}/{repository}/releases/download/v#{{version}}/PeerTree-#{{version}}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/{owner}/{repository}"

  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{{appdir}}/PeerTree.app/Contents/MacOS/peertree"
end
''', encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True, help="GitHub owner of the release")
    parser.add_argument("--repository", default="peertree", help="GitHub repository name")
    parser.add_argument("--sign-identity", help="Developer ID Application identity for the macOS bundle")
    parser.add_argument("--notary-profile", help="notarytool keychain profile for a release build")
    parser.add_argument("--desktop", action="store_true", help="bundle the Tauri desktop app")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", args.owner):
        parser.error("Enter a GitHub username or organization.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", args.repository):
        parser.error("Enter a valid GitHub repository name.")
    if args.notary_profile and not args.sign_identity:
        parser.error("Notarization requires --sign-identity.")
    output = SOURCE / "dist"
    output.mkdir(exist_ok=True)
    archive = output / f"PeerTree-{VERSION}-macOS.zip"
    with tempfile.TemporaryDirectory(prefix="peertree-build-") as temporary:
        app = assemble(Path(temporary), args.owner, args.sign_identity, args.desktop)
        staged = Path(temporary) / archive.name
        run("/usr/bin/ditto", "-c", "-k", "--keepParent", app, staged)
        if args.notary_profile:
            run("/usr/bin/xcrun", "notarytool", "submit", staged, "--wait",
                "--keychain-profile", args.notary_profile)
            run("/usr/bin/xcrun", "stapler", "staple", app)
            run("/usr/bin/xcrun", "stapler", "validate", app)
            run("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", app)
            staged.unlink()
            run("/usr/bin/ditto", "-c", "-k", "--keepParent", app, staged)
        shutil.copy2(staged, archive)
    cask = SOURCE / "Casks" / "peertree.rb"
    write_cask(cask, archive, args.owner, args.repository)
    print(f"Release archive: {archive}")
    print(f"Homebrew cask: {cask}")


if __name__ == "__main__":
    main()
