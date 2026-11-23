#!/usr/bin/env python3
import argparse
import base64
import fcntl
import getpass
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from lan import Announcements
from peer import PEER_CODE, PeerSession, decode_code


BRANCHES = ("dev", "main")
NAMESPACE = "neighbor-review-v1"
MAX_EXCHANGE = 512 * 1024 * 1024
ASSETS = Path(__file__).resolve().parent
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
GIT_ENV = {
    **os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


class Problem(RuntimeError):
    pass


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def run(argv, *, cwd=None, data=None):
    result = subprocess.run(argv, cwd=cwd, input=data, capture_output=True, env=GIT_ENV)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors="replace").strip()
        raise Problem(detail[:4000] or f"{argv[0]} exited with status {result.returncode}.")
    return result.stdout


def clean_key(value):
    parts = value.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise Problem("Enter a PeerTree Ed25519 public key.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError as error:
        raise Problem("The public key is invalid.") from error
    if len(raw) != 51 or not raw.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 "):
        raise Problem("The public key is invalid.")
    return " ".join(parts[:2])


def key_id(key):
    return hashlib.sha256(base64.b64decode(key.split()[1])).hexdigest()


def is_hash(value, pattern=OID):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def short_text(value, limit):
    return isinstance(value, str) and 0 < len(value.strip()) <= limit and len(value) <= limit


def validate(record):
    if not isinstance(record, dict) or type(record.get("at")) is not int or record["at"] < 0:
        raise Problem("Invalid record timestamp.")
    if not is_hash(record.get("who"), FINGERPRINT):
        raise Problem("Invalid record identity.")
    kind = record.get("kind")
    if kind == "proposal":
        valid = (record.get("target") in BRANCHES and is_hash(record.get("head"))
                 and is_hash(record.get("base")) and short_text(record.get("title"), 120)
                 and short_text(record.get("source"), 255))
    elif kind == "review":
        valid = (is_hash(record.get("proposal"), FINGERPRINT)
                 and record.get("vote") in ("approve", "changes")
                 and isinstance(record.get("note"), str) and len(record["note"]) <= 1000)
    elif kind == "shared":
        valid = record.get("branch") in BRANCHES and is_hash(record.get("head"))
    else:
        valid = False
    if not valid:
        raise Problem("Invalid branch submission, review, or branch record.")


class Workspace:
    def __init__(self, repo, project, name, check, lan=None, peer=None):
        self.root = Path(repo).resolve()
        self.root = Path(self.git("rev-parse", "--show-toplevel").strip())
        self.data = Path(self.git("rev-parse", "--path-format=absolute", "--git-common-dir").strip())
        self.data = self.data / "neighbor-review"
        self.data.mkdir(mode=0o700, exist_ok=True)
        self.instance = (self.data / "instance.lock").open("a")
        try:
            fcntl.flock(self.instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Problem("PeerTree is already open for this repository.") from error
        self.key = self.data / "identity"
        self.file = self.data / "state.json"
        if not self.key.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "neighbor-review",
                 "-f", str(self.key)])
        self.public = clean_key(run(["ssh-keygen", "-y", "-f", str(self.key)]).decode())
        self.me = key_id(self.public)
        self.lock = threading.RLock()
        self.check_lock = threading.Lock()
        self.announcements = None
        self.peer_session = None
        self.notices = {}
        self.notice_packets = {}
        self.share_folder = None
        if self.file.exists():
            self.data_state = json.loads(self.file.read_text())
            if project is not None and project != self.data_state["project"]:
                raise Problem(f"This clone already uses project {self.data_state['project']}.")
        else:
            project = project or self.default_project()
            name = name or self.config("user.name") or getpass.getuser()
            self.data_state = {
                "project": project[:80], "name": name[:80], "peers": {}, "integrator": "",
                "records": {}, "runs": {}, "check": "",
            }
        if check is not None:
            self.data_state["check"] = check
        if lan is not None:
            self.data_state["lan"] = lan
            if lan:
                self.data_state["peer"] = False
        if peer is not None:
            self.data_state["peer"] = peer
            if peer:
                self.data_state["lan"] = False
        self.save(self.data_state)

    def config(self, name):
        try:
            return self.git("config", "--get", name).strip()
        except Problem:
            return ""

    def default_project(self):
        origin = self.config("remote.origin.url").rstrip("/")
        if origin:
            return re.split(r"[/:]", origin)[-1].removesuffix(".git") or self.root.name
        return self.data.parent.parent.name or self.root.name

    def git_bytes(self, *args, cwd=None, data=None):
        return run(["git", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=cwd or self.root, data=data)

    def git(self, *args, **kwargs):
        return self.git_bytes(*args, **kwargs).decode(errors="replace")

    def save(self, state):
        with tempfile.NamedTemporaryFile(dir=self.data, mode="w", delete=False) as out:
            os.chmod(out.name, 0o600)
            json.dump(state, out, ensure_ascii=True)
        os.replace(out.name, self.file)
        self.data_state = state

    @property
    def records(self):
        return self.data_state["records"]

    def record_id(self, record):
        return hashlib.sha256(encoded(record)).hexdigest()

    def signature(self, record, namespace=NAMESPACE):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "record"
            payload.write_bytes(encoded(record))
            run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(self.key),
                 "-n", namespace, str(payload)])
            return payload.with_suffix(".sig").read_text()

    def sign(self, kind, **fields):
        record = {"kind": kind, "project": self.data_state["project"], "who": self.me,
                  "at": time.time_ns(), **fields}
        validate(record)
        return self.record_id(record), {"record": record, "signature": self.signature(record)}

    def verify_signature(self, record, signature, key, directory, namespace=NAMESPACE):
        signature_file = directory / "signature"
        signers_file = directory / "allowed_signers"
        signature_file.write_text(signature)
        signers_file.write_text(f"neighbor {key}\n")
        run(["ssh-keygen", "-Y", "verify", "-q", "-f", str(signers_file),
             "-I", "neighbor", "-n", namespace, "-s", str(signature_file)], data=encoded(record))

    def verified(self, envelope, directory):
        if not isinstance(envelope, dict):
            raise Problem("Invalid exchange record.")
        record, signature = envelope.get("record"), envelope.get("signature")
        validate(record)
        if record.get("project") != self.data_state["project"] or not short_text(signature, 2048):
            raise Problem("This record does not belong to the current project or lacks a signature.")
        keys = {peer: value["key"] for peer, value in self.data_state["peers"].items()}
        keys[self.me] = self.public
        key = keys.get(record["who"])
        if not key:
            raise Problem(f"Add the teammate with key ID {record['who'][:12]} before importing.")
        self.verify_signature(record, signature, key, directory)
        return self.record_id(record)

    def lan_scope(self):
        return hashlib.sha256(encoded(self.data_state["project"])).hexdigest()

    def outgoing_notices(self):
        with self.lock:
            ready = []
            branches, shared = self.branches(), self.shared()
            for ident in self.revisions():
                record = self.proposal(ident)
                if record["who"] != self.me:
                    continue
                tip = shared.get(record["target"]) or branches.get(record["target"])
                if tip and self.ancestor(record["head"], tip):
                    continue
                ready.append((record["at"], ident))
            packets = {}
            for at, ident in sorted(ready, reverse=True)[:20]:
                packet = self.notice_packets.get(ident)
                if packet is None:
                    notice = {"scope": self.lan_scope(), "who": self.me, "id": ident, "at": at}
                    packet = encoded({"notice": notice,
                                      "signature": self.signature(notice, Announcements.NAMESPACE)})
                packets[ident] = packet
            self.notice_packets = packets
            return list(packets.values())

    def receive_notice(self, packet):
        try:
            envelope = json.loads(packet)
            notice, signature = envelope["notice"], envelope["signature"]
            if (set(notice) != {"scope", "who", "id", "at"}
                    or not is_hash(notice["who"], FINGERPRINT)
                    or not is_hash(notice["id"], FINGERPRINT)
                    or type(notice["at"]) is not int or not 0 < notice["at"] <= 2**63 - 1
                    or not short_text(signature, 700)):
                return
            with self.lock:
                peer = self.data_state["peers"].get(notice["who"])
                ident = notice["id"]
                if (not peer or notice["scope"] != self.lan_scope()
                        or ident in self.records or ident in self.notices):
                    return
                with tempfile.TemporaryDirectory() as tmp:
                    self.verify_signature(notice, signature, peer["key"], Path(tmp),
                                          Announcements.NAMESPACE)
                self.notices[ident] = {
                    "id": ident, "name": peer["name"], "at": notice["at"],
                }
                if len(self.notices) > 80:
                    oldest = min(self.notices.values(), key=lambda item: item["at"])
                    del self.notices[oldest["id"]]
        except (Problem, ValueError, TypeError, KeyError, RecursionError):
            return

    def nearby(self):
        return {
            "enabled": self.data_state.get("lan", False),
            "error": self.announcements.error if self.announcements else "",
            "notices": sorted((item for ident, item in self.notices.items()
                               if ident not in self.records), key=lambda item: -item["at"]),
            "peer": self.peer_session.status() if self.peer_session else {"enabled": False},
        }

    def commit(self, ref):
        return self.git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()

    def ancestor(self, earlier, later):
        return self.git("merge-base", earlier, later).strip() == earlier

    def pin(self, records):
        commits = {record[field] for record in records
                   for field in ("head", "base") if field in record}
        if not commits:
            return
        for commit in commits:
            if self.commit(commit) != commit:
                raise Problem("An exchange references a non-commit Git object.")
        updates = "".join(f"update refs/neighbor-review/objects/{oid} {oid}\n"
                          for oid in sorted(commits))
        self.git("update-ref", "--stdin", data=updates.encode())

    def store(self, additions):
        self.pin([envelope["record"] for envelope in additions.values()])
        self.save({**self.data_state, "records": {**self.records, **additions}})

    def proposal(self, proposal_id):
        record = self.records.get(proposal_id, {}).get("record", {})
        if record.get("kind") != "proposal":
            raise Problem("This branch review is unavailable.")
        return record

    def revisions(self):
        latest = {}
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["kind"] == "proposal":
                branch = (record["who"], record["source"], record["target"])
                latest[branch] = max(latest.get(branch, (0, "")), (record["at"], ident))
        return {ident for _, ident in latest.values()}

    def branches(self):
        output = self.git("for-each-ref", "--format=%(refname:short)%09%(objectname)", "refs/heads/")
        return dict(line.split("\t", 1) for line in output.splitlines())

    def worktrees(self):
        result = []
        for entry in self.git("worktree", "list", "--porcelain", "-z").strip("\0").split("\0\0"):
            fields = dict((line.split(" ", 1) + [""])[:2] for line in entry.split("\0"))
            path = fields.get("worktree")
            if path and "bare" not in fields and "prunable" not in fields and Path(path).is_dir():
                result.append({"path": path, "branch": fields.get("branch", "").removeprefix("refs/heads/")})
        return result

    def select_worktree(self, path):
        if not any(path == entry["path"] for entry in self.worktrees()):
            raise Problem("This path is not an available worktree for the repository.")
        self.root = Path(path)
        return {"message": f"Using worktree {path}."}

    def create(self, data):
        source, target, title = (data.get(field, "").strip() for field in ("source", "target", "title"))
        branches = self.branches()
        if source not in branches or target not in BRANCHES or target not in branches:
            raise Problem("Select an existing source branch and shared target branch.")
        head = branches[source]
        base = self.git("merge-base", branches[target], head).strip()
        if base == head:
            raise Problem("The source branch has no commits ahead of the target.")
        for envelope in self.records.values():
            record = envelope["record"]
            if (record.get("kind") == "proposal" and record["who"] == self.me
                    and record["head"] == head and record["target"] == target):
                raise Problem("You already submitted this commit for that branch.")
        ident, envelope = self.sign("proposal", title=title, source=source,
                                    target=target, head=head, base=base)
        self.store({ident: envelope})
        if self.announcements:
            self.announcements.wake()
        return {"selected": ident}

    def reviews(self, proposal_id):
        people = self.data_state["peers"] | {self.me: {}}
        latest = {}
        for ident, envelope in self.records.items():
            record = envelope["record"]
            who = record["who"]
            if record.get("proposal") != proposal_id or who not in people:
                continue
            if who not in latest or (record["at"], ident) > latest[who][0]:
                latest[who] = ((record["at"], ident), record)
        return [item[1] for item in latest.values()]

    def review(self, data):
        ident = data.get("id")
        proposal = self.proposal(ident)
        vote, note = data.get("vote"), data.get("note", "").strip()
        if proposal["who"] == self.me:
            raise Problem("A teammate needs to review your branch.")
        if ident not in self.revisions():
            raise Problem("A newer revision is available. Open it to leave a review.")
        if vote == "approve":
            check = self.data_state["check"]
            result = self.data_state["runs"].get(ident, {})
            if not check or not result.get("passed") or result.get("command") != check:
                raise Problem("Run a successful local pipeline before approving this revision.")
        review_id, envelope = self.sign("review", proposal=ident, vote=vote, note=note)
        self.store({review_id: envelope})
        message = ("Review saved. Paired teammates receive it when nearby."
                   if self.data_state.get("peer") else "Review saved. Export an exchange to share it.")
        return {"message": message}

    def inspect(self, ident):
        proposal = self.proposal(ident)
        stats = self.git("diff", "--stat", "--no-ext-diff", "--no-textconv",
                         proposal["base"], proposal["head"], "--")
        with subprocess.Popen(
            ["git", "-c", "core.hooksPath=/dev/null", "diff", "--no-color", "--no-ext-diff",
             "--no-textconv", proposal["base"], proposal["head"], "--"],
            cwd=self.root, env=GIT_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ) as process:
            patch = process.stdout.read(300001)
            if len(patch) > 300000 and process.poll() is None:
                process.terminate()
            process.wait()
        return {"stats": stats[:16000], "patch": patch[:300000].decode(errors="replace"),
                "truncated": len(patch) > 300000}

    def run_check(self, ident):
        if not self.check_lock.acquire(blocking=False):
            raise Problem("A pipeline is already running.")
        try:
            with self.lock:
                proposal = self.proposal(ident)
                command = self.data_state["check"]
                root = self.root
                object_format = self.git("rev-parse", "--show-object-format", cwd=root).strip()
            if not command:
                raise Problem("Set a local pipeline command in Team settings first.")
            start = time.monotonic()
            with tempfile.TemporaryDirectory(prefix="neighbor-check-") as tmp:
                self.git("init", "-q", f"--object-format={object_format}", cwd=tmp)
                self.git("fetch", "--no-tags", "--", str(root), proposal["head"], cwd=tmp)
                self.git("checkout", "--detach", "-q", proposal["head"], cwd=tmp)
                with tempfile.TemporaryFile() as log:
                    with subprocess.Popen(
                        ["/bin/sh", "-c", command], cwd=tmp, env=GIT_ENV, stdin=subprocess.DEVNULL,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                    ) as process:
                        try:
                            code = process.wait(timeout=600)
                            footer = f"\nExited with status {code}."
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                            code, footer = 1, "\nPipeline timed out after 10 minutes."
                    size = log.tell()
                    log.seek(max(0, size - 60000))
                    output = log.read().decode(errors="replace")
                    if size > 60000:
                        output = "[Showing the end of the pipeline output]\n" + output
            result = {"passed": code == 0, "command": command, "output": output + footer,
                      "secs": round(time.monotonic() - start, 1)}
            with self.lock:
                self.save({**self.data_state, "runs": {**self.data_state["runs"], ident: result}})
            return result
        finally:
            self.check_lock.release()

    def shared(self):
        integrator = self.data_state["integrator"]
        latest = {}
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["kind"] != "shared" or record["who"] != integrator:
                continue
            branch = record["branch"]
            if branch not in latest or (record["at"], ident) > latest[branch][0]:
                latest[branch] = ((record["at"], ident), record)
        return {branch: item[1]["head"] for branch, item in latest.items()}

    def require_integrator(self):
        if self.data_state["integrator"] != self.me:
            raise Problem("Only the designated integrator can merge and publish shared branches.")

    def publish(self):
        self.require_integrator()
        branches, shared = self.branches(), self.shared()
        additions = {}
        for branch in BRANCHES:
            if branch not in branches or shared.get(branch) == branches[branch]:
                continue
            if branch in shared and not self.ancestor(shared[branch], branches[branch]):
                raise Problem(f"Local {branch} diverged from the last published tip.")
            ident, envelope = self.sign("shared", branch=branch, head=branches[branch])
            additions[ident] = envelope
        if additions:
            self.store(additions)
        message = ("Branch tips published. Paired teammates receive them when nearby."
                   if self.data_state.get("peer")
                   else "Shared branch tips published. Export an exchange to share them.")
        return {"message": message}

    def clean_branch(self, branch, expected=None):
        if self.git("status", "--porcelain").strip():
            raise Problem("Commit or stash your work before changing shared branches.")
        git_paths = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge",
                     "rebase-apply", "sequencer")
        for name in git_paths:
            path = self.git("rev-parse", "--path-format=absolute", "--git-path", name).strip()
            if Path(path).exists():
                raise Problem("Finish the current Git operation first.")
        if branch not in self.branches():
            if expected is None:
                raise Problem(f"Create the local {branch} branch first.")
            self.git("branch", "--no-track", branch, expected)
        current = self.git("branch", "--show-current").strip()
        if current != branch:
            self.git("switch", "--no-guess", "--", branch)
        if expected is not None and self.commit("HEAD") != expected:
            raise Problem(f"Local {branch} changed during the operation.")

    def integrate(self, ident):
        self.require_integrator()
        proposal = self.proposal(ident)
        if ident not in self.revisions():
            raise Problem("A newer revision is available. Merge it after review.")
        reviews = [item for item in self.reviews(ident) if item["who"] != proposal["who"]]
        if sum(item["vote"] == "approve" for item in reviews) < 2:
            raise Problem("This revision needs two teammate approvals.")
        if any(item["vote"] == "changes" for item in reviews):
            raise Problem("A reviewer has requested changes.")
        branch, head = proposal["target"], proposal["head"]
        current = self.commit(f"refs/heads/{branch}")
        if self.ancestor(head, current):
            raise Problem("This revision is already included in the target branch.")
        published = self.shared().get(branch)
        if published and not self.ancestor(published, current):
            raise Problem(f"Local {branch} diverged from the last published tip.")
        self.clean_branch(branch, current)
        try:
            self.git("merge", "--no-ff", "--no-edit", "--", head)
        except Problem as error:
            merge_head = self.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD").strip()
            if Path(merge_head).exists():
                self.git("merge", "--abort")
            raise Problem(f"Git could not merge {proposal['source']}.\n{error}") from error
        try:
            return self.publish()
        except Problem as error:
            raise Problem(f"Merged into {branch}. Publishing failed, so use Publish branch tips after resolving this issue.\n{error}") from error

    def sync(self, branch):
        if branch not in BRANCHES or branch not in self.shared():
            raise Problem("Import a published tip from your designated integrator first.")
        head = self.shared()[branch]
        current = self.branches().get(branch)
        if current and not self.ancestor(current, head):
            if self.ancestor(head, current):
                raise Problem(f"Local {branch} is already ahead of the published tip.")
            raise Problem(f"Local {branch} has diverged. Reconcile it in Git before syncing.")
        self.clean_branch(branch, current or head)
        self.git("merge", "--ff-only", "--", head)
        return {"message": f"{branch} is synced to {head[:9]}."}

    def team(self, data):
        action = data.get("action")
        state = dict(self.data_state)
        if action == "add":
            name, entry = data.get("name", "").strip(), data.get("key", "").strip()
            key_text, pin = decode_code(entry) if entry.startswith(PEER_CODE) else (entry, "")
            key = clean_key(key_text)
            ident = key_id(key)
            if not short_text(name, 80) or ident == self.me:
                raise Problem("Enter a teammate's name and verified pairing code or public key.")
            if pin and any(peer.get("pin") == pin for who, peer in state["peers"].items() if who != ident):
                raise Problem("That nearby certificate is already paired with another teammate.")
            old_peer = state["peers"].get(ident, {})
            if pin and old_peer.get("pin") and old_peer["pin"] != pin:
                raise Problem("This teammate has a different nearby identity. Confirm it in person, then use Reset pairing.")
            new_peer = {**old_peer, "name": name, "key": key}
            if pin:
                new_peer["pin"] = pin
            state["peers"] = {**state["peers"], ident: new_peer}
        elif action == "reset-pairing":
            ident = data.get("id")
            if ident not in state["peers"]:
                raise Problem("Choose a known teammate.")
            state["peers"] = {**state["peers"], ident: {
                key: value for key, value in state["peers"][ident].items() if key != "pin"
            }}
        elif action == "integrator":
            ident = data.get("id")
            if ident != self.me and ident not in state["peers"]:
                raise Problem("Choose a known teammate.")
            state["integrator"] = ident
        elif action == "check":
            check = data.get("command", "").strip()
            if len(check) > 1000:
                raise Problem("Keep the command under 1,000 characters.")
            state["check"] = check
        else:
            raise Problem("Unknown team setting.")
        self.save(state)
        return {"message": "Team settings saved."}

    def export(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "objects.bundle"
            if self.git("for-each-ref", "refs/neighbor-review/objects/").strip():
                self.git("bundle", "create", str(bundle), "--glob=refs/neighbor-review/objects/*")
                if bundle.stat().st_size > MAX_EXCHANGE - 2 * 1024 * 1024:
                    raise Problem("The Git bundle exceeds the 512 MB exchange limit.")
            memory = io.BytesIO()
            with zipfile.ZipFile(memory, "w") as out:
                out.writestr("records.json", encoded(list(self.records.values())))
                if bundle.exists():
                    out.write(bundle, "objects.bundle")
            return memory.getvalue()

    def share_exchange(self):
        if self.share_folder is None:
            self.share_folder = tempfile.TemporaryDirectory(prefix="neighbor-share-")
        stamp = time.strftime("%Y-%m-%d-%H%M%S")
        filename = f"neighbor-exchange-{stamp}-{secrets.token_hex(3)}.zip"
        path = Path(self.share_folder.name) / filename
        try:
            path.write_bytes(self.export())
            run(["/usr/bin/open", "-R", str(path)])
        except (OSError, Problem) as error:
            path.unlink(missing_ok=True)
            raise Problem(f"Could not reveal the exchange in Finder. {error}") from error
        return {"message": "Exchange selected in Finder. Choose Share → AirDrop and pick your teammate."}

    def import_exchange(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = archive.namelist()
                if ("records.json" not in names or len(names) != len(set(names))
                        or set(names) - {"records.json", "objects.bundle"}
                        or sum(item.file_size for item in archive.infolist()) > MAX_EXCHANGE
                        or archive.getinfo("records.json").file_size > 2 * 1024 * 1024):
                    raise Problem("Invalid or oversized exchange.")
                records = json.loads(archive.read("records.json"))
                if not isinstance(records, list):
                    raise Problem("Invalid exchange records.")
                additions = {}
                for envelope in records:
                    ident = self.verified(envelope, directory)
                    if ident not in self.records:
                        additions[ident] = envelope
                all_records = self.records | additions
                for item in additions.values():
                    record = item["record"]
                    if record["kind"] != "review":
                        continue
                    subject = all_records.get(record["proposal"], {}).get("record", {})
                    if subject.get("kind") != "proposal" or subject["who"] == record["who"]:
                        raise Problem("An exchange contains a review without a valid branch submission.")
                if additions and "objects.bundle" in names:
                    bundle = Path(archive.extract("objects.bundle", directory))
                    self.git("bundle", "verify", str(bundle))
                    self.git("bundle", "unbundle", str(bundle))
                for item in additions.values():
                    record = item["record"]
                    if record["kind"] == "proposal":
                        if not self.ancestor(record["base"], record["head"]):
                            raise Problem("A submitted branch has an invalid Git base.")
                self.store(additions)
                people = self.data_state["peers"]
                activity = []
                for item in additions.values():
                    record = item["record"]
                    name = people.get(record["who"], {}).get("name", self.data_state["name"])
                    if record["kind"] == "proposal":
                        activity.append(f"{name} submitted “{record['title']}” for review.")
                    elif record["kind"] == "review":
                        activity.append(f"{name} reviewed a submitted branch.")
                    else:
                        activity.append(f"{name} published a new {record['branch']} tip.")
                return {"message": f"Imported {len(additions)} new exchange records.",
                        "imported": len(additions), "activity": activity[:10]}

    def view(self):
        branches = self.branches()
        shared = self.shared()
        people = {ident: peer["name"] for ident, peer in self.data_state["peers"].items()}
        people[self.me] = self.data_state["name"]
        revisions = self.revisions()
        proposals = []
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["kind"] != "proposal":
                continue
            try:
                tip = branches.get(record["target"])
                published = shared.get(record["target"])
                merged = any(self.ancestor(record["head"], candidate)
                             for candidate in {tip, published} if candidate)
            except Problem:
                merged = False
            reviews = self.reviews(ident)
            approvals = sum(item["vote"] == "approve" for item in reviews)
            blocked = any(item["vote"] == "changes" for item in reviews)
            proposals.append({
                **record, "id": ident, "merged": merged, "ready": approvals >= 2 and not blocked,
                "superseded": ident not in revisions, "blocked": blocked,
                "approvals": approvals, "reviews": reviews,
                "run": self.data_state["runs"].get(ident),
            })
        return {
            "project": self.data_state["project"], "repo": str(self.root), "me": self.me,
            "public": self.public, "people": people, "integrator": self.data_state["integrator"],
            "paired": [who for who, peer in self.data_state["peers"].items() if peer.get("pin")],
            "check": self.data_state["check"], "branches": branches, "shared": shared,
            "worktrees": self.worktrees(),
            "proposals": sorted(proposals, key=lambda row: (
                row["merged"] or row["superseded"], -row["at"])),
        }


def handle(workspace, token):
    class Handler(BaseHTTPRequestHandler):
        def send(self, status, data, mime="application/json; charset=utf-8", attachment=None):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.end_headers()
            self.wfile.write(data)

        def dispatch(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                raise Problem("Use the local address printed by the app.")
            path = urlsplit(self.path).path
            if self.command == "GET":
                assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                          "/style.css": ("style.css", "text/css")}
                if path in assets:
                    name, mime = assets[path]
                    content = (ASSETS / name).read_text()
                    if path == "/":
                        content = content.replace("__SESSION_TOKEN__", html.escape(token))
                    self.send(200, content.encode(), mime + "; charset=utf-8")
                    return
            if not secrets.compare_digest(self.headers.get("X-Neighbor-Token", ""), token):
                self.send(403, encoded({"error": "Open the app's local page to use its API."}))
                return
            if self.command == "GET":
                with workspace.lock:
                    if path == "/api/state":
                        result = workspace.view()
                    elif path == "/api/nearby":
                        result = workspace.nearby()
                    elif path.startswith("/api/diff/"):
                        result = workspace.inspect(path.rsplit("/", 1)[1])
                    elif path == "/api/export":
                        self.send(200, workspace.export(), "application/zip", "neighbor-exchange.zip")
                        return
                    else:
                        self.send(404, encoded({"error": "Unknown request."}))
                        return
            else:
                size = int(self.headers.get("Content-Length", "0"))
                limit = MAX_EXCHANGE if path == "/api/import" else 16000
                if not 0 < size <= limit:
                    raise Problem("The request is empty or too large.")
                payload = self.rfile.read(size)
                if path == "/api/import":
                    with workspace.lock:
                        result = workspace.import_exchange(payload)
                else:
                    data = json.loads(payload)
                    if not isinstance(data, dict):
                        raise Problem("Expected an object.")
                    if path == "/api/check":
                        result = workspace.run_check(data.get("id"))
                    else:
                        with workspace.lock:
                            actions = {
                                "/api/propose": lambda: workspace.create(data),
                                "/api/share": workspace.share_exchange,
                                "/api/worktree": lambda: workspace.select_worktree(data.get("path")),
                                "/api/review": lambda: workspace.review(data),
                                "/api/team": lambda: workspace.team(data),
                                "/api/publish": workspace.publish,
                                "/api/sync": lambda: workspace.sync(data.get("branch")),
                                "/api/integrate": lambda: workspace.integrate(data.get("id")),
                            }
                            if path not in actions:
                                self.send(404, encoded({"error": "Unknown request."}))
                                return
                            result = actions[path]()
            self.send(200, encoded(result))

        def request(self):
            try:
                self.dispatch()
            except (Problem, ValueError, TypeError, AttributeError, zipfile.BadZipFile) as error:
                self.send(400, encoded({"error": str(error)}))
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = request
        do_POST = request

    return Handler


def main():
    parser = argparse.ArgumentParser(prog="peertree", description="Local Git review for three teammates.")
    parser.add_argument("--repo", default=".", help="path to an existing Git working copy")
    parser.add_argument("--project", help="shared project name, defaults to the origin repository name")
    parser.add_argument("--name", help="display name, defaults to Git user.name")
    parser.add_argument("--check", help="local pipeline shell command")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-open", action="store_true")
    network = parser.add_mutually_exclusive_group()
    network.add_argument("--lan", dest="lan", action="store_true", default=None,
                         help="enable and remember nearby review alerts")
    network.add_argument("--no-lan", dest="lan", action="store_false",
                         help="disable nearby review alerts")
    network.add_argument("--peer", dest="peer", action="store_true", default=None,
                         help="enable and remember encrypted nearby Wi-Fi exchanges")
    network.add_argument("--no-peer", dest="peer", action="store_false",
                         help="disable nearby Wi-Fi exchanges")
    args = parser.parse_args()
    if any(value is not None and not short_text(value, 80) for value in (args.name, args.project)):
        parser.error("Use a name and project between 1 and 80 characters.")
    if args.check is not None and len(args.check) > 1000:
        parser.error("Keep the check command under 1,000 characters.")
    try:
        workspace = Workspace(args.repo, args.project and args.project.strip(),
                              args.name and args.name.strip(), args.check, args.lan, args.peer)
        with ThreadingHTTPServer(("127.0.0.1", args.port), handle(workspace, secrets.token_urlsafe(32))) as server:
            url = f"http://127.0.0.1:{server.server_port}"
            print(f"PeerTree is open at {url}", flush=True)
            if workspace.data_state.get("lan"):
                workspace.announcements = Announcements(workspace.outgoing_notices, workspace.receive_notice)
                workspace.announcements.start()
            if workspace.data_state.get("peer"):
                workspace.peer_session = PeerSession(workspace, run)
                workspace.peer_session.start()
            try:
                if not args.no_open:
                    webbrowser.open(url)
                server.serve_forever()
            finally:
                if workspace.announcements:
                    workspace.announcements.close()
                if workspace.peer_session:
                    workspace.peer_session.close()
                if workspace.share_folder:
                    workspace.share_folder.cleanup()
    except (Problem, OSError) as error:
        parser.exit(1, f"{error}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
