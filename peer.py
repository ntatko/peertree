"""Manage the native peer-to-peer Wi-Fi process and its private exchange files."""

import base64
import hashlib
import hmac
import json
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
import zipfile


PEER_CODE = "NR1."
# The helper sends inventories in 512 KB packets; 64 MB holds about 1M record IDs.
MAX_INVENTORY = 64 * 1024 * 1024
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
        self.received_at = None
        self.received_activity = []
        self.initializing = True
        self.code = ""
        self.directory = None
        self.helper = None
        self.hosting_until = 0
        self.code_attempts = 0
        self.pairing_result = None
        self.display = None
        self.imported = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, name="nearby-wifi", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        if self.helper is not None and self.helper.poll() is None:
            self.helper.terminate()

    def request_sync(self):
        if self.directory is None or self.helper is None or self.helper.poll() is not None:
            return False
        write_atomic(self.directory / "sync.json", json.dumps(str(time.monotonic_ns())).encode())
        return True

    def read_json(self, name):
        try:
            return json.loads((self.directory / name).read_bytes())
        except (OSError, ValueError, TypeError):
            return None

    def host_open(self):
        """Keep listing Macs that are waiting to join while the host's pairing window stays open."""
        self.hosting_until = time.monotonic() + 15
        write_atomic(self.directory / "host.json", b'{"active":true}')
        return {"message": "Looking for Macs waiting to join."}

    def pair_start(self, ident):
        if not isinstance(ident, str) or not re.fullmatch("[0-9a-f]{32}", ident):
            raise ValueError("Choose a Mac that is waiting to join.")
        self.code_attempts = 0
        self.pairing_result = None
        write_atomic(self.directory / "pair-start.json",
                     json.dumps({"id": ident, "nonce": secrets.token_hex(8)}).encode())
        return {"message": "Connecting to the other Mac."}

    def pair_confirm(self, code):
        status = self.read_json("pairing.json") or {}
        if status.get("state") != "verify":
            raise ValueError("There is no pairing code to confirm right now.")
        if status.get("role") == "join":
            entered = "".join(str(code or "").split())
            if not hmac.compare_digest(entered, status.get("code", "")):
                self.code_attempts += 1
                if self.code_attempts >= 3:
                    self.pair_cancel()
                    raise ValueError("The code didn't match three times, so pairing stopped. Start again on the host.")
                raise ValueError("That code doesn't match. Check the host's screen and try again.")
        with self.workspace.lock:
            offer = self.workspace.pairing_offer(status["role"])
        write_atomic(self.directory / "pair-confirm.json",
                     json.dumps({"session": status["session"], "offer": offer}).encode())
        return {"message": "Confirmed on this Mac."}

    def pair_cancel(self):
        status = self.read_json("pairing.json") or {}
        if status.get("session"):
            write_atomic(self.directory / "pair-cancel.json", json.dumps({"session": status["session"]}).encode())
        return {"message": "Pairing cancelled."}

    def pairing_status(self):
        if self.directory is None:
            return {"available": False}
        hosting = time.monotonic() < self.hosting_until
        session = self.read_json("pairing.json") or {}
        if session.get("role") == "join":
            # The person joining types the host's code, so this Mac never displays it.
            session = {key: value for key, value in session.items() if key != "code"}
        return {"available": True, "hosting": hosting, "session": session, "result": self.pairing_result,
                "display": self.display_name(),
                "requests": (self.read_json("requests.json") or []) if hosting else []}

    def update_pairing(self, directory):
        join_file = directory / "join.json"
        if self.workspace.data_state.get("joining"):
            if not join_file.exists():
                write_atomic(join_file, json.dumps({"name": self.display_name()}).encode())
        else:
            join_file.unlink(missing_ok=True)
        if time.monotonic() >= self.hosting_until:
            (directory / "host.json").unlink(missing_ok=True)
        result_file = directory / "pair-result.json"
        if result_file.exists():
            try:
                result = json.loads(result_file.read_bytes())
                result_file.unlink()
                with self.workspace.lock:
                    self.pairing_result = self.workspace.apply_pairing(result)
            except (OSError, ValueError, RuntimeError) as error:
                self.pairing_result = {"error": f"Pairing did not finish. {error}"}

    def display_name(self):
        if self.display:
            return self.display
        name = self.workspace.data_state["name"]
        try:
            computer = self.execute(["/usr/sbin/scutil", "--get", "ComputerName"]).decode().strip()
        except (OSError, RuntimeError):
            computer = ""
        self.display = f"{name} · {computer}"[:80] if computer and computer != name else name
        return self.display

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
        except Exception as error:  # Show unexpected failures instead of stopping sync silently.
            traceback.print_exc()
            self.error = f"Nearby Wi-Fi stopped unexpectedly. {type(error).__name__}: {error}"
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
            (directory / "inventories").mkdir()
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
        previous_inventory = None
        previous_exports = None
        plans = {}
        while not self.stopped.is_set():
            if child.poll() is not None:
                log = (directory / "native.log").read_text(errors="replace").strip()
                raise RuntimeError(log[-1000:] or "The nearby Wi-Fi helper stopped.")
            self.update_pairing(directory)
            with self.workspace.lock:
                peers = self.workspace.data_state["peers"]
                allowed = {ident[:32]: record["pin"] for ident, record in peers.items()
                           if record.get("pin")}
                serialized = json.dumps(allowed, sort_keys=True).encode()
                if serialized != previous_peers:
                    write_atomic(directory / "peers.json", serialized)
                    previous_peers = serialized
            # Imports verify signatures without the lock and take it only to store records.
            for path in sorted((directory / "incoming").glob("*.zip")):
                try:
                    payload = path.read_bytes()
                    digest = hashlib.sha256(payload).digest()
                    if digest in self.imported:
                        continue  # A teammate repeats a batch until it hears that it arrived.
                    result = self.workspace.import_exchange(payload)
                    self.imported = [*self.imported[-63:], digest]
                    if result["imported"]:
                        self.received = result["message"]
                        self.received_count += 1
                        self.received_at = time.time()
                        self.received_activity = result["activity"]
                    self.error = ""
                except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
                    self.error = f"Could not import a nearby exchange. {error}"
                finally:
                    path.unlink(missing_ok=True)
            with self.workspace.lock:
                local = sorted(self.workspace.records)
            inventory = json.dumps(local, separators=(",", ":")).encode()
            if len(inventory) > MAX_INVENTORY:
                self.error = "The nearby signed record inventory exceeds 64 MB."
            elif inventory != previous_inventory:
                write_atomic(directory / "inventory.json", inventory)
                previous_inventory = inventory
            # Building Git bundles can take a while, so it runs without the workspace lock.
            exports = self.prepare_exports(directory, allowed, inventory, local, plans)
            if exports != previous_exports:
                write_atomic(directory / "exports.json", json.dumps(exports, sort_keys=True).encode())
                active = set(exports.values())
                for old in (directory / "outgoing").glob("*.zip"):
                    if old.name not in active:
                        old.unlink(missing_ok=True)
                previous_exports = exports
            self.stopped.wait(1)

    def prepare_exports(self, directory, peers, inventory, records, plans):
        exports = {}
        digest = hashlib.sha256(inventory).digest()
        for peer in tuple(plans):
            if peer not in peers:
                del plans[peer]
        for peer, pin in peers.items():
            path = directory / "inventories" / f"{peer}.json"
            try:
                with path.open("rb") as source:
                    remote = source.read(MAX_INVENTORY + 1)
            except FileNotFoundError:
                plans.pop(peer, None)
                continue
            if len(remote) > MAX_INVENTORY:
                continue
            generation = hashlib.sha256(digest + pin.encode() + remote).hexdigest()
            cached = plans.get(peer)
            if cached and cached[0] == generation and (not cached[2] or time.monotonic() < cached[2]):
                if cached[1]:
                    exports[peer] = cached[1]
                continue
            try:
                plan = self.workspace.inventory_plan(json.loads(remote), records)
                if not plan["missing"]:
                    plans[peer] = (generation, None, 0)
                    continue
                with self.workspace.lock:
                    parts = self.workspace.export_records(plan)
                archive = f"{peer}-{generation}.zip"
                write_atomic(directory / "outgoing" / archive, self.workspace.export_archive(*parts))
                exports[peer] = archive
                plans[peer] = (generation, archive, 0)
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                self.error = f"Could not prepare the nearby exchange. {error}"
                plans[peer] = (generation, None, time.monotonic() + 5)
        return exports

    def status(self):
        native = {}
        if self.directory is not None:
            try:
                native = json.loads((self.directory / "status.json").read_bytes())
            except (OSError, ValueError):
                pass
        online = set(native.get("online", []))
        peers = self.workspace.data_state["peers"]
        reachable = [ident for ident, peer in peers.items() if peer.get("pin") and ident[:32] in online]
        return {
            "enabled": True, "starting": self.initializing, "code": self.code,
            "online": [peers[ident]["name"] for ident in reachable], "reachable": reachable,
            "error": self.error or native.get("error", ""),
            "received": self.received, "received_count": self.received_count,
            "received_at": self.received_at,
            "activity": self.received_activity,
        }
