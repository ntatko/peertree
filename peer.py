"""Manage the native peer-to-peer Wi-Fi process and its private exchange files."""

import base64
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile


PEER_CODE = "NR1."
ASSETS = Path(__file__).resolve().parent


def identity(directory, public, execute):
    directory.mkdir(mode=0o700, exist_ok=True)
    bundle = directory / "identity.json"
    if not bundle.exists():
        with tempfile.TemporaryDirectory(dir=directory) as temp:
            tmp = Path(temp)
            key, cert = tmp / "key.pem", tmp / "cert.pem"
            execute(["/usr/bin/openssl", "ecparam", "-name", "prime256v1",
                     "-param_enc", "named_curve", "-genkey", "-noout", "-out", str(key)])
            execute(["/usr/bin/openssl", "req", "-new", "-x509", "-key", str(key),
                     "-days", "3650", "-subj", "/CN=PeerTree", "-out", str(cert)])
            der = execute(["/usr/bin/openssl", "x509", "-in", str(cert), "-outform", "DER"])
            material = {"key": key.read_text(), "certificate": base64.b64encode(der).decode()}
            staged = tmp / "identity.json"
            staged.touch(mode=0o600)
            staged.write_text(json.dumps(material))
            staged.replace(bundle)
    material = json.loads(bundle.read_text())
    certificate = material.get("certificate") if isinstance(material, dict) else None
    if not isinstance(certificate, str):
        raise ValueError("The nearby certificate is missing.")
    pin = hashlib.sha256(base64.b64decode(certificate, validate=True)).hexdigest()
    payload = json.dumps({"key": public, "pin": pin}, separators=(",", ":")).encode()
    return bundle, PEER_CODE + base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_code(code):
    value = code.strip()
    if not value.startswith(PEER_CODE) or len(value) > 600:
        raise ValueError("Enter a nearby pairing code beginning with NR1.")
    value = value[len(PEER_CODE):]
    payload = json.loads(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True))
    if (not isinstance(payload, dict) or set(payload) != {"key", "pin"}
            or not isinstance(payload["key"], str) or not isinstance(payload["pin"], str)
            or not re.fullmatch("[0-9a-f]{64}", payload["pin"])):
        raise ValueError("Invalid nearby pairing code.")
    return payload["key"], payload["pin"]


def write_atomic(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("wb") as stream:
        stream.write(value)
    temporary.replace(path)


class PeerSession:
    def __init__(self, workspace, execute):
        self.workspace = workspace
        self.execute = execute
        self.error = ""
        self.received = ""
        self.received_count = 0
        self.received_activity = []
        self.initializing = True
        self.code = ""
        self.directory = None
        self.helper = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, name="nearby-wifi", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        if self.helper is not None and self.helper.poll() is None:
            self.helper.terminate()

    def executable(self):
        bundled = ASSETS.parent / "Helpers" / "peertree-peer"
        if bundled.is_file():
            return bundled
        installed = ASSETS / "neighbor-peer"
        if installed.is_file():
            return installed
        source = ASSETS / "Peer.swift"
        try:
            self.execute(["/usr/bin/xcrun", "--find", "swiftc"])
        except RuntimeError as error:
            raise RuntimeError("Nearby Wi-Fi from source needs the Apple Swift compiler.") from error
        plist = ASSETS / "PeerInfo.plist"
        digest = hashlib.sha256(source.read_bytes() + plist.read_bytes()).hexdigest()[:16]
        executable = self.workspace.data / f"neighbor-peer-{digest}"
        if not executable.exists():
            with tempfile.TemporaryDirectory(prefix="neighbor-build-") as build:
                binary = Path(build) / "peer"
                cache = str(Path(build) / "module-cache")
                args = ["/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-O", "-module-cache-path", cache,
                        "-target", f"{platform.machine()}-apple-macosx15.0", str(source)]
                self.execute([*args, "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT",
                              "-Xlinker", "__info_plist", "-Xlinker", str(plist), "-o", str(binary)])
                if not self.stopped.is_set():
                    staged = self.workspace.data / "neighbor-peer.new"
                    shutil.copy2(binary, staged)
                    staged.replace(executable)
        return executable

    def run(self):
        try:
            self.run_session()
        except (OSError, ValueError, RuntimeError) as error:
            self.error = str(error)
        finally:
            self.initializing = False

    def run_session(self):
        cert, self.code = identity(self.workspace.data / "peer-identity", self.workspace.public, self.execute)
        executable = self.executable()
        if self.stopped.is_set():
            return
        with tempfile.TemporaryDirectory(prefix="neighbor-peer-") as temp:
            directory = Path(temp)
            self.directory = directory
            (directory / "incoming").mkdir()
            (directory / "outgoing").mkdir()
            bootstrap = {"identity": str(cert), "name": self.workspace.me[:32],
                         "directory": str(directory)}
            (directory / "bootstrap.json").write_text(json.dumps(bootstrap))
            with (directory / "native.log").open("wb") as log:
                child = subprocess.Popen([str(executable), str(directory / "bootstrap.json")],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                self.helper = child
                try:
                    self.initializing = False
                    self.exchange_loop(directory, child)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                    self.directory = None

    def exchange_loop(self, directory, child):
        previous_peers = None
        previous_generation = None
        retry_export_at = 0.0
        while not self.stopped.is_set():
            if child.poll() is not None:
                log = (directory / "native.log").read_text(errors="replace").strip()
                raise RuntimeError(log[-1000:] or "The nearby Wi-Fi helper stopped.")
            with self.workspace.lock:
                peers = self.workspace.data_state["peers"]
                allowed = {ident[:32]: record["pin"] for ident, record in peers.items()
                           if record.get("pin")}
                serialized = json.dumps(allowed, sort_keys=True).encode()
                if serialized != previous_peers:
                    write_atomic(directory / "peers.json", serialized)
                    previous_peers = serialized
                for path in sorted((directory / "incoming").glob("*.zip")):
                    try:
                        result = self.workspace.import_exchange(path.read_bytes())
                        if result["imported"]:
                            self.received = result["message"]
                            self.received_count += 1
                            self.received_activity = result["activity"]
                        self.error = ""
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
                        self.error = f"Could not import a nearby exchange. {error}"
                    finally:
                        path.unlink(missing_ok=True)
                ids = sorted(self.workspace.records)
                generation = hashlib.sha256("".join(ids).encode()).hexdigest()
                if allowed and ids and generation != previous_generation and time.monotonic() >= retry_export_at:
                    try:
                        archive = directory / "outgoing" / f"{generation}.zip"
                        write_atomic(archive, self.workspace.export())
                        write_atomic(directory / "current.json", json.dumps(archive.name).encode())
                    except (OSError, RuntimeError) as error:
                        self.error = f"Could not prepare the nearby exchange. {error}"
                        retry_export_at = time.monotonic() + 5
                    else:
                        for old in archive.parent.glob("*.zip"):
                            if old != archive:
                                old.unlink(missing_ok=True)
                        previous_generation = generation
            self.stopped.wait(1)

    def status(self):
        native = {}
        if self.directory is not None:
            try:
                native = json.loads((self.directory / "status.json").read_bytes())
            except (OSError, ValueError):
                pass
        names = {ident[:32]: peer["name"] for ident, peer in self.workspace.data_state["peers"].items()}
        return {
            "enabled": True, "starting": self.initializing, "code": self.code,
            "online": [names.get(ident, ident) for ident in native.get("online", [])],
            "error": self.error or native.get("error", ""),
            "received": self.received, "received_count": self.received_count,
            "activity": self.received_activity,
        }
