#!/usr/bin/env python3
"""Build a universal PeerTree macOS app and generate its Homebrew cask."""

import argparse
import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile


VERSION = "0.4.1"
SOURCE = Path(__file__).resolve().parent
RESOURCES = ("app.py", "lan.py", "peer.py", "app.js", "index.html", "style.css")
SERVICE = "_neighbor-review._tcp"


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


def assemble(build, owner, signing_identity):
    app = build / "PeerTree.app"
    contents = app / "Contents"
    launcher = contents / "MacOS" / "peertree"
    helper = contents / "Helpers" / "peertree-peer"
    resources = contents / "Resources"
    for path in (launcher.parent, helper.parent, resources):
        path.mkdir(parents=True)
    for name in RESOURCES:
        shutil.copy2(SOURCE / name, resources / name)
    info = {
        "CFBundleDisplayName": "PeerTree",
        "CFBundleExecutable": "peertree",
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
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    swift(build, "Launcher.swift", launcher)
    swift(build, "Peer.swift", helper, SOURCE / "PeerInfo.plist")
    signing = ["--options", "runtime", "--timestamp"] if signing_identity else []
    for item in (helper, app):
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

  depends_on macos: ">= :sequoia"

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
        app = assemble(Path(temporary), args.owner, args.sign_identity)
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
