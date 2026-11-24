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
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import agent
from lan import Announcements
from peer import PEER_CODE, PeerSession, decode_code, identity
from quorum import Ballots, QUORUM_RECORDS


BRANCHES = ("dev", "main")
NAMESPACE = "neighbor-review-v1"
MAX_EXCHANGE = 512 * 1024 * 1024
MAX_RECORDS = 2 * 1024 * 1024
DEPENDENT_KINDS = ("review", "comment", "check")
MAX_IMAGE_PREVIEW = 16 * 1024 * 1024
IMAGE_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".webp": "image/webp", ".avif": "image/avif", ".svg": "image/svg+xml",
    ".bmp": "image/bmp", ".ico": "image/x-icon",
}
ASSETS = Path(__file__).resolve().parent
POLICY_FILE = ".peertree.json"
NOTIFICATIONS = {"reviews": True, "decisions": True, "diverge": True, "peers": False}
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
GIT_ENV = {
    **os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


class Problem(RuntimeError):
    pass


class AlreadyOpen(Problem):
    pass


class PipelineBusy(Problem):
    pass


def open_markdown_link(url):
    if not isinstance(url, str) or not url or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise Problem("This link is invalid.")
    target = urlsplit(url)
    if target.scheme not in ("http", "https", "mailto") or (target.scheme != "mailto" and not target.hostname):
        raise Problem("Only web and email links can be opened externally.")
    run(["/usr/bin/open", url])
    return {}


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


def ref_name(value):
    return (short_text(value, 255) and not value.startswith("-")
            and not re.search(r"[\x00-\x20\x7f~^:?*\[\\]", value))


def ref_manifest(value):
    return isinstance(value, dict) and all(ref_name(ref) and is_hash(oid) for ref, oid in value.items())


def referenced_objects(records):
    commits = {record[field] for record in records for field in ("head", "base") if field in record}
    tags = set()
    for record in records:
        if record["kind"] in ("snapshot", "quorum_root"):
            commits.update(record["branches"].values())
            tags.update(record["tags"].values())
    return commits, tags


def rust_request(operation, request):
    configured = os.environ.get("PEERTREE_CORE")
    candidates = [Path(configured)] if configured else [
        ASSETS.parent / "Helpers" / "peertree-core",
        ASSETS / "target" / "release" / "peertree-core",
        ASSETS / "target" / "debug" / "peertree-core",
    ]
    executable = next((path for path in candidates if path.is_file()), None)
    if executable is None:
        raise Problem("Build the PeerTree Rust core first with cargo build --locked.")
    return json.loads(run([str(executable), operation], data=request))


def rust_policy(request):
    return rust_request("__policy", request)


def valid_comment_anchor(anchor):
    if not isinstance(anchor, dict) or set(anchor) != {"file", "side", "line"}:
        return False
    path, side, line = anchor["file"], anchor["side"], anchor["line"]
    return (short_text(path, 4096) and not re.search(r"[\x00-\x1f\x7f]", path)
            and all(part not in ("", ".", "..") for part in path.split("/"))
            and side in ("old", "new") and type(line) is int and 0 < line <= 2_147_483_647)


def record_ids(value, minimum, maximum):
    return (isinstance(value, list) and minimum <= len(value) <= maximum
            and all(is_hash(item, FINGERPRINT) for item in value) and len(set(value)) == len(value))


def validate(record):
    if not isinstance(record, dict) or type(record.get("at")) is not int or record["at"] < 0:
        raise Problem("Invalid record timestamp.")
    if not is_hash(record.get("who"), FINGERPRINT):
        raise Problem("Invalid record identity.")
    kind = record.get("kind")
    if kind == "proposal":
        valid = (ref_name(record.get("target")) and is_hash(record.get("head"))
                 and is_hash(record.get("base")) and short_text(record.get("title"), 120)
                 and short_text(record.get("source"), 255)
                 and ("quorum" not in record or is_hash(record["quorum"], FINGERPRINT)))
    elif kind == "review":
        valid = (is_hash(record.get("proposal"), FINGERPRINT)
                 and record.get("vote") in ("approve", "changes")
                 and isinstance(record.get("note"), str) and len(record["note"]) <= 1000
                 and ("policy" not in record or is_hash(record["policy"])))
    elif kind == "comment":
        valid = (is_hash(record.get("proposal"), FINGERPRINT) and short_text(record.get("body"), 4000)
                 and ("anchor" not in record or valid_comment_anchor(record["anchor"])))
    elif kind == "check":
        results = record.get("results")
        valid = (is_hash(record.get("proposal"), FINGERPRINT) and is_hash(record.get("policy"))
                 and isinstance(results, dict) and len(results) <= 32 and all(
                     re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key) and isinstance(value, bool)
                     for key, value in results.items()))
    elif kind == "shared":
        valid = ref_name(record.get("branch")) and is_hash(record.get("head"))
    elif kind == "introduction":
        valid = (short_text(record.get("key"), 200) and record["key"].startswith("ssh-ed25519 ")
                 and is_hash(record.get("pin"), FINGERPRINT) and short_text(record.get("name"), 80))
    elif kind in ("snapshot", "quorum_root"):
        branches, tags = record.get("branches"), record.get("tags")
        default = record.get("default")
        valid = (ref_manifest(branches) and branches and ref_manifest(tags)
                 and ref_name(default) and default in branches)
        if kind == "quorum_root":
            members = record.get("members")
            valid = valid and record_ids(members, 3, 3) and record["who"] in members
    elif kind in QUORUM_RECORDS:
        valid = is_hash(record.get("root"), FINGERPRINT)
        if kind == "quorum_prepare":
            valid = (valid and ref_name(record.get("branch")) and is_hash(record.get("base"))
                     and type(record.get("round")) is int and 1 <= record["round"] <= 2**53)
        elif kind == "quorum_promise":
            valid = (valid and is_hash(record.get("prepare"), FINGERPRINT)
                     and (record.get("accepted") is None or is_hash(record["accepted"], FINGERPRINT))
                     and "accepted" in record)
        elif kind == "quorum_choice":
            value = record.get("value")
            valid = (valid and is_hash(record.get("prepare"), FINGERPRINT)
                     and record_ids(record.get("promises"), 2, 2)
                     and isinstance(value, dict) and set(value) == {"proposal", "approval", "checks"}
                     and is_hash(value["proposal"], FINGERPRINT) and is_hash(value["approval"], FINGERPRINT)
                     and record_ids(value["checks"], 0, 32))
        else:
            valid = valid and is_hash(record.get("choice"), FINGERPRINT)
    else:
        valid = False
    if not valid:
        raise Problem("Invalid branch submission, review, or branch record.")


class Workspace:
    def __init__(self, repo, project, name, check, lan=None, peer=None, bootstrap=False, joining=False):
        self.root = Path(repo).resolve()
        self.root = Path(self.git("rev-parse", "--show-toplevel").strip())
        self.data = Path(self.git("rev-parse", "--path-format=absolute", "--git-common-dir").strip())
        self.data = self.data / "neighbor-review"
        self.data.mkdir(mode=0o700, exist_ok=True)
        self.instance = (self.data / "instance.lock").open("a")
        try:
            fcntl.flock(self.instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AlreadyOpen("PeerTree is already open for this repository.") from error
        self.key = self.data / "identity"
        self.file = self.data / "state.json"
        if not self.key.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "neighbor-review",
                 "-f", str(self.key)])
        self.public = clean_key(run(["ssh-keygen", "-y", "-f", str(self.key)]).decode())
        self.me = key_id(self.public)
        self.lock = threading.RLock()
        self.check_lock = threading.Lock()
        self.check_wake = threading.Event()
        self.check_stop = threading.Event()
        self.check_worker = None
        self.running_check = None
        self.ballot_cache = None
        self.quorum_error = ""
        self.quorum_progress = {}
        self.announcements = None
        self.peer_session = None
        self.notices = {}
        self.notice_packets = {}
        self.share_folder = None
        self.tracking_error = ""
        self.view_version = 0
        if self.file.exists():
            self.data_state = json.loads(self.file.read_text())
            if project is not None and project != self.data_state["project"]:
                raise Problem(f"This clone already uses project {self.data_state['project']}.")
        else:
            # A joining Mac learns its project from the host it pairs with.
            project = "" if joining else project or self.default_project()
            name = name or self.config("user.name") or getpass.getuser()
            self.data_state = {
                "project": project[:80], "name": name[:80], "peers": {}, "integrator": "",
                "records": {}, "runs": {}, "check": "",
                "bootstrap": bootstrap or joining,
            }
            if joining:
                self.data_state.update(joining=True, staging=True)
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
        self.view_version += 1
        self.check_wake.set()

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
            "version": self.view_version,
        }

    def commit(self, ref):
        return self.git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()

    def ancestor(self, earlier, later):
        return self.git("merge-base", earlier, later).strip() == earlier

    def pin(self, records):
        commits, tags = referenced_objects(records)
        for record in records:
            if record["kind"] in ("snapshot", "quorum_root"):
                for space in ("branches", "tags"):
                    category = "heads" if space == "branches" else "tags"
                    for ref in record[space]:
                        self.git("check-ref-format", f"refs/{category}/{ref}")
        for commit in commits:
            if self.commit(commit) != commit:
                raise Problem("An exchange references a non-commit Git object.")
        for tag in tags - commits:
            if self.git("cat-file", "-t", tag).strip() not in ("tag", "commit"):
                raise Problem("A published tag does not point to a tag or commit object.")
            self.commit(tag)
        if not (tags or commits):
            return
        updates = "".join(f"update refs/neighbor-review/objects/{oid} {oid}\n"
                          for oid in sorted(commits | tags))
        self.git("update-ref", "--stdin", data=updates.encode())

    def store(self, additions):
        if not additions:
            return
        old_tips = self.shared() if self.data_state.get("tracking") else None
        self.pin([envelope["record"] for envelope in additions.values()])
        self.save({**self.data_state, "records": {**self.records, **additions}})
        if self.data_state.get("quorum"):
            try:
                self.advance_quorum()
                self.quorum_error = ""
            except (Problem, OSError, ValueError) as error:
                self.quorum_error = str(error)
        self.update_tracking(old_tips)

    def refresh_tracking(self):
        snapshot = self.snapshot()
        default = snapshot["default"] if snapshot else "main"
        result = rust_request("__tracking", encoded({
            "root": str(self.root), "tips": self.shared(), "default": default,
        }))
        self.tracking_error = ""
        return result

    def enable_tracking(self):
        result = self.refresh_tracking()
        if not self.data_state.get("tracking"):
            self.save({**self.data_state, "tracking": True})
        return result

    def update_tracking(self, old_tips):
        if old_tips is not None and self.shared() != old_tips:
            try:
                self.refresh_tracking()
            except (Problem, OSError, ValueError) as error:
                self.tracking_error = str(error)

    def proposal(self, proposal_id):
        record = self.records.get(proposal_id, {}).get("record", {})
        if record.get("kind") != "proposal":
            raise Problem("This branch review is unavailable.")
        return record

    def revisions(self):
        latest = {}
        quorum = self.data_state.get("quorum")
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["kind"] == "proposal" and record.get("quorum") == quorum:
                branch = (record["who"], record["source"], record["target"])
                latest[branch] = max(latest.get(branch, (0, "")), (record["at"], ident))
        return {ident for _, ident in latest.values()}

    def branches(self):
        return self.refs("refs/heads/")

    def refs(self, prefix):
        output = self.git("for-each-ref", "--format=%(refname)%09%(objectname)%09%(symref)", prefix)
        rows = (line.split("\t") for line in output.splitlines())
        return {ref.removeprefix(prefix): oid for ref, oid, symref in rows if not symref}

    def snapshot_sources(self):
        return {**self.refs("refs/remotes/origin/"), **self.branches()}

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
        if self.root != Path(path):
            self.root = Path(path)
            self.view_version += 1
        return {"message": f"Using worktree {path}."}

    def code(self, path):
        if (len(path) > 4096 or "\0" in path
                or (path and any(part in ("", ".", "..") for part in path.split("/")))):
            raise Problem("Choose a path from the repository tree.")
        try:
            head = self.commit("HEAD")
        except Problem:
            return {"head": None, "entries": []}
        ref = f"{head}:{path}" if path else f"{head}^{{tree}}"
        try:
            oid = self.git("rev-parse", "--verify", "--end-of-options", ref).strip()
        except Problem as error:
            raise Problem("This path is absent from the selected worktree’s HEAD.") from error
        kind = self.git("cat-file", "-t", oid).strip()
        result = {"head": head, "kind": kind}
        if kind == "tree":
            entries = []
            for entry in self.git_bytes("ls-tree", "-z", oid).split(b"\0"):
                if not entry:
                    continue
                info, filename = entry.split(b"\t", 1)
                mode, item_kind, _ = info.decode().split()
                name = filename.decode(errors="replace")
                entries.append({"name": name, "kind": item_kind,
                                "preview": mode != "160000" and name.encode() == filename})
            result["entries"] = sorted(entries, key=lambda item: (item["kind"] != "tree", item["name"].casefold()))
            if not path:
                result["latest"] = self.history(head, limit=1)[0]
                readme = next((item["name"] for item in result["entries"]
                               if item["kind"] == "blob" and item["name"].lower() in ("readme.md", "readme")), None)
                if readme:
                    result["readme"] = {"name": readme, **self.code(readme)}
        elif kind == "blob":
            size = int(self.git("cat-file", "-s", oid))
            result["size"] = size
            mime = IMAGE_TYPES.get(Path(path).suffix.lower())
            if mime:
                result["image"] = {"mime": mime}
                if size <= MAX_IMAGE_PREVIEW:
                    raw = self.git_bytes("cat-file", "blob", oid)
                    result["image"]["data"] = base64.b64encode(raw).decode("ascii")
            elif size <= 256 * 1024:
                raw = self.git_bytes("cat-file", "blob", oid)
                if b"\0" not in raw:
                    try:
                        result["text"] = raw.decode()
                    except UnicodeDecodeError:
                        pass
        return result

    def history(self, head=None, limit=60):
        if head is None:
            try:
                head = self.commit("HEAD")
            except Problem:
                return []
        rows = self.git_bytes("log", "-z", f"-{limit}", "--format=%H%x00%an%x00%ct%x00%s", head, "--")
        fields = rows.removesuffix(b"\0").decode(errors="replace").split("\0") if rows else []
        return [{"id": ident, "author": author, "at": int(at), "title": title}
                for ident, author, at, title in zip(fields[::4], fields[1::4], fields[2::4], fields[3::4])]

    def commit_diff(self, ident):
        if not is_hash(ident) or not any(item["id"] == ident for item in self.history()):
            raise Problem("This commit is no longer in the worktree’s recent history.")
        return self.read_patch("show", "--format=", "--diff-merges=first-parent", "--no-notes",
                               "--no-show-signature", ident, "--")

    def activity(self):
        records = sorted((item["record"] for item in self.records.values()),
                         key=lambda row: row["at"], reverse=True)
        return [{key: row[key] for key in ("kind", "at", "who", "proposal", "branch", "title", "vote") if key in row}
                for row in records if row["kind"] not in QUORUM_RECORDS or row["kind"] == "quorum_root"][:100]

    def branch_status(self, branches, shared):
        status = {}
        for branch in self.protected_branches():
            local, remote = branches.get(branch), shared.get(branch)
            if not remote:
                status[branch] = "unpublished"
            elif not local:
                status[branch] = "missing"
            elif local == remote:
                status[branch] = "synced"
            else:
                ahead, behind = map(int, self.git("rev-list", "--left-right", "--count", f"{local}...{remote}").split())
                status[branch] = "diverged" if ahead and behind else "ahead" if ahead else "behind"
        return status

    def refresh_exchange(self):
        if not self.data_state.get("bootstrap"):
            self.enable_tracking()
        if self.peer_session and self.peer_session.request_sync():
            return {"message": "Nearby sync requested. Keep PeerTree open while paired Macs exchange updates."}
        if self.peer_session:
            return {"message": "Nearby Wi-Fi is unavailable or still starting. Check Peers for status."}
        return {"message": "Nearby Wi-Fi is off. Import an exchange to receive updates." if self.data_state.get("bootstrap")
                else "Team tracking refs refreshed. Nearby Wi-Fi is off."}

    def create(self, data):
        source, target, title = (data.get(field, "").strip() for field in ("source", "target", "title"))
        branches = self.branches()
        quorum = self.data_state.get("quorum")
        tips = self.shared() if quorum else branches
        if source not in branches or target not in self.protected_branches() or target not in tips:
            raise Problem("Select an existing source branch and shared target branch.")
        policy = self.policy_for(target)
        if policy and target not in policy[1]["protected_branches"]:
            raise Problem(f"{target} is outside the committed protected branch list.")
        head = branches[source]
        base = self.git("merge-base", tips[target], head).strip()
        if quorum and base != tips[target]:
            raise Problem(f"Rebase {source} onto the current shared {target} tip before submitting.")
        if base == head:
            raise Problem("The source branch has no commits ahead of the target.")
        for envelope in self.records.values():
            record = envelope["record"]
            if (record.get("kind") == "proposal" and record["who"] == self.me
                    and record["head"] == head and record["target"] == target
                    and record.get("quorum") == quorum):
                raise Problem("You already submitted this commit for that branch.")
        fields = {"quorum": quorum} if quorum else {}
        ident, envelope = self.sign("proposal", title=title, source=source,
                                    target=target, head=head, base=base, **fields)
        self.store({ident: envelope})
        if self.announcements:
            self.announcements.wake()
        return {"selected": ident}

    def reviews(self, proposal_id, policy_id=None):
        people = self.data_state["peers"] | {self.me: {}}
        latest = {}
        for ident, envelope in self.records.items():
            record = envelope["record"]
            who = record["who"]
            if (record["kind"] != "review" or record["proposal"] != proposal_id
                    or who not in people or record.get("policy") != policy_id):
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
        if data.get("revision") is not None and data["revision"] != proposal["head"]:
            raise Problem("The reviewed commit does not match this branch submission.")
        if self.data_state.get("quorum") and self.quorum_stale(proposal):
            raise Problem("The target branch moved. Ask the author to rebase and submit this revision again.")
        policy = self.policy_for(proposal["target"])
        check = self.data_state["check"]
        if vote == "approve" and policy is None and (check or not self.data_state.get("quorum")):
            result = self.data_state["runs"].get(ident, {})
            if not check or not result.get("passed") or result.get("command") != check:
                raise Problem("Run a successful local pipeline before approving this revision.")
        fields = {"policy": policy[0]} if policy else {}
        review_id, envelope = self.sign("review", proposal=ident, vote=vote, note=note, **fields)
        self.store({review_id: envelope})
        message = ("Review saved. Paired teammates receive it when nearby."
                   if self.data_state.get("peer") else "Review saved. Export an exchange to share it.")
        return {"message": message}

    def comment(self, data):
        ident, body = data.get("id"), data.get("body", "").strip()
        self.proposal(ident)
        fields = {}
        if "anchor" in data:
            anchor = data["anchor"]
            if not valid_comment_anchor(anchor) or not self.diff_has_line(self.inspect(ident), anchor):
                raise Problem("Choose a line in this revision’s diff.")
            fields["anchor"] = anchor
        comment_id, envelope = self.sign("comment", proposal=ident, body=body, **fields)
        self.store({comment_id: envelope})
        return {"id": comment_id, "message": "Comment saved."}

    def comments(self, ident):
        records = ((item["record"]["at"], key, item["record"]) for key, item in self.records.items()
                   if item["record"]["kind"] == "comment" and item["record"]["proposal"] == ident)
        return [{**record, "id": key} for _, key, record in sorted(records)]

    def policy_at(self, tip):
        item = self.git("ls-tree", tip, "--", POLICY_FILE).strip()
        if not item:
            return None
        mode, kind, oid = item.split("\t", 1)[0].split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise Problem(".peertree.json must be a regular tracked file.")
        if int(self.git("cat-file", "-s", oid)) > 65536:
            raise Problem(".peertree.json exceeds 64 KB.")
        raw = self.git_bytes("cat-file", "blob", oid)
        config = rust_policy(b'{"operation":"validate","policy":' + raw + b'}')
        return oid, config

    def policy_for(self, target):
        shared = self.shared()
        if self.data_state.get("quorum"):
            return self.policy_at(shared[target]) if target in shared else None
        local = self.branches()
        snapshot = self.snapshot()
        default = snapshot["default"] if snapshot else "main"
        for branch in dict.fromkeys((target, default)):
            tip = shared.get(branch) or local.get(branch)
            policy = self.policy_at(tip) if tip else None
            if policy:
                return policy
        return None

    def merge_gate(self, ident, proposal, policy):
        reviews = self.reviews(ident, policy[0] if policy else None)
        # Peer majority needs one approval from the other two peers; the integrator workflow needs both.
        required = 1 if self.data_state.get("quorum") else 2
        if policy:
            policy_id, config = policy
            newest = {}
            for key, item in self.records.items():
                record = item["record"]
                if (record["kind"] == "check" and record["proposal"] == ident
                        and record["policy"] == policy_id and record["who"] != proposal["who"]
                        and (record["who"] == self.me or record["who"] in self.data_state["peers"])):
                    for check, passed in record["results"].items():
                        slot = (record["who"], check)
                        candidate = (record["at"], key, passed)
                        if slot not in newest or candidate > newest[slot]:
                            newest[slot] = candidate
            passed = sorted({check for (_, check), result in newest.items() if result[2]})
            gate = rust_policy(encoded({"operation": "evaluate", "policy": config,
                                        "target": proposal["target"], "author": proposal["who"],
                                        "required": required, "reviews": reviews, "passed": passed}))
            return {**gate, "check_runs": [
                {"who": who, "check": check, "passed": result[2], "at": result[0]}
                for (who, check), result in sorted(newest.items())
            ]}
        approvals = sum(item["vote"] == "approve" for item in reviews)
        blocked = any(item["vote"] == "changes" for item in reviews)
        return {"approvals": approvals, "required": required, "blocked": blocked, "missing": [],
                "ready": approvals >= required and not blocked}

    def inspect(self, ident):
        proposal = self.proposal(ident)
        revisions = (proposal["base"], proposal["head"], "--")
        stats = self.git("diff", "--stat", "--no-ext-diff", "--no-textconv",
                         *revisions)
        fields = iter(self.git("diff", "--name-status", "-z", "--find-renames", *revisions).rstrip("\0").split("\0"))
        paths = []
        for status in fields:
            if not status:
                break
            path = next(fields)
            old = path if status != "A" else None
            new = next(fields) if status.startswith(("R", "C")) else path if status != "D" else None
            paths.append({"old": old, "new": new})
        return {"stats": stats[:16000], "paths": paths,
                **self.read_patch("diff", "--find-renames", "--unified=3", "--diff-algorithm=myers",
                                  "--indent-heuristic", *revisions)}

    def diff_has_line(self, diff, anchor):
        files = iter(diff["paths"])
        file = {}
        side = anchor["side"]
        for line in diff["patch"].split("\n"):
            if line.startswith("diff --git "):
                file = next(files, {})
            elif file.get(side) == anchor["file"] and line.startswith("@@ "):
                hunk = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                if hunk:
                    start, count = (hunk.group(1, 2) if side == "old" else hunk.group(3, 4))
                    if int(start) <= anchor["line"] < int(start) + int(count or 1):
                        return True
        return False

    def read_patch(self, command, *args):
        with subprocess.Popen(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false", command, "--no-color",
             "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", *args],
            cwd=self.root, env=GIT_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ) as process:
            patch = process.stdout.read(300001)
            if len(patch) > 300000 and process.poll() is None:
                process.terminate()
            if process.wait() and len(patch) <= 300000:
                raise Problem("Git could not read the diff for this revision.")
        return {"patch": patch[:300000].decode(errors="replace"), "truncated": len(patch) > 300000}

    def start_checks(self):
        self.check_worker = threading.Thread(target=self.run_queued_checks, name="review-pipelines", daemon=True)
        self.check_worker.start()

    def stop_checks(self):
        self.check_stop.set()
        self.check_wake.set()
        if self.check_worker:
            self.check_worker.join(timeout=3)

    def run_queued_checks(self):
        while not self.check_stop.is_set():
            changed = self.check_wake.wait(5 if self.data_state.get("quorum") else None)
            self.check_wake.clear()
            if self.check_stop.is_set():
                break
            try:
                with self.lock:
                    if self.data_state.get("quorum"):
                        old_tips = self.shared()
                        if changed:
                            self.advance_quorum()
                        if self.peer_session:
                            self.retry_stalled_quorum()
                        self.update_tracking(old_tips)
                    if not changed:
                        continue
                    pending = [review["id"] for review in self.view()["proposals"]
                               if review["pipeline_status"] == "queued"]
            except (Problem, OSError, ValueError):
                continue  # A later workspace change can make the checks runnable.
            for ident in pending:
                if self.check_stop.is_set():
                    return
                try:
                    self.run_check(ident, automatic=True)
                except PipelineBusy:
                    break  # The running check wakes the queue when it finishes.
                except (Problem, OSError, ValueError):
                    continue  # The configuration or review may have changed since the scan.

    def merged_proposal(self, proposal, branches, shared):
        target = proposal["target"]
        local = None if self.data_state.get("quorum") else branches.get(target)
        try:
            return any(self.ancestor(proposal["head"], tip)
                       for tip in {local, shared.get(target)} if tip)
        except Problem:
            return False

    def run_check(self, ident, worktree=None, *, automatic=False):
        if not self.check_lock.acquire(blocking=False):
            raise PipelineBusy("A pipeline is already running.")
        started = False
        try:
            with self.lock:
                proposal = self.proposal(ident)
                policy = self.policy_for(proposal["target"])
                command = self.data_state["check"]
                root = worktree or self.root
                if automatic:
                    # Checks execute the submitted revision's code, so only the author's
                    # own branches run unattended. Reviewers start teammates' runs.
                    run = self.data_state["runs"].get(ident, {})
                    if (proposal["who"] != self.me or self.data_state.get("bootstrap")
                            or not policy or not policy[1]["checks"]
                            or run.get("policy") == policy[0] or ident not in self.revisions()
                            or self.quorum_stale(proposal)
                            or self.merged_proposal(proposal, self.branches(), self.shared())):
                        return None
                if policy is None and not command:
                    raise Problem("Set a local pipeline command in Team settings first.")
                checks = policy[1]["checks"] if policy else {"pipeline": ["/bin/sh", "-c", command]}
                self.running_check = ident
                self.view_version += 1
                started = True
            results = {}
            output = []
            start = time.monotonic()
            try:
                object_format = self.git("rev-parse", "--show-object-format", cwd=root).strip()
                with tempfile.TemporaryDirectory(prefix="neighbor-check-") as tmp:
                    self.git("init", "-q", f"--object-format={object_format}", cwd=tmp)
                    self.git("fetch", "--no-tags", "--", str(root), proposal["head"], cwd=tmp)
                    self.git("checkout", "--detach", "-q", proposal["head"], cwd=tmp)
                    for name, argv in checks.items():
                        passed, log = self.execute_check(argv, tmp, start + 600)
                        results[name] = passed
                        output.append(f"{name}\n{log}")
            except (Problem, OSError, ValueError) as error:
                if not automatic or self.check_stop.is_set():
                    raise
                output.append(str(error))
            complete = len(results) == len(checks)
            result = {"passed": complete and all(results.values()), "command": command, "output": "\n\n".join(output)[-60000:],
                      "checks": results, "policy": policy[0] if policy else None,
                      "secs": round(time.monotonic() - start, 1)}
            with self.lock:
                if self.check_stop.is_set():
                    raise Problem("PeerTree closed before the pipeline finished.")
                if policy and complete:
                    check_id, envelope = self.sign("check", proposal=ident, policy=policy[0], results=results)
                    self.store({check_id: envelope})
                self.save({**self.data_state, "runs": {**self.data_state["runs"], ident: result}})
            return result
        finally:
            with self.lock:
                if started:
                    self.running_check = None
                    self.view_version += 1
                self.check_lock.release()
            if not automatic:
                self.check_wake.set()

    def execute_check(self, argv, cwd, deadline):
        if self.check_stop.is_set():
            raise Problem("PeerTree closed before the pipeline finished.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, "The pipeline reached its 10-minute limit."
        with tempfile.TemporaryFile() as log:
            try:
                with subprocess.Popen(argv, cwd=cwd, env=GIT_ENV, stdin=subprocess.DEVNULL,
                                      stdout=log, stderr=subprocess.STDOUT, start_new_session=True) as process:
                    while not self.check_stop.is_set() and remaining > 0:
                        try:
                            code = process.wait(timeout=min(remaining, 0.25))
                            footer = f"\nExited with status {code}."
                            break
                        except subprocess.TimeoutExpired:
                            remaining = deadline - time.monotonic()
                    else:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                        if self.check_stop.is_set():
                            raise Problem("PeerTree closed before the pipeline finished.")
                        code, footer = 1, "\nPipeline timed out after 10 minutes."
            except OSError as error:
                return False, str(error)
            size = log.tell()
            log.seek(max(0, size - 60000))
            output = log.read().decode(errors="replace")
            if size > 60000:
                output = "[Showing the end of the check output]\n" + output
            return code == 0, output + footer

    def quorum_candidates(self):
        members = {self.me, *self.data_state["peers"]}
        return {ident: item["record"] for ident, item in self.records.items()
                if item["record"]["kind"] == "quorum_root" and set(item["record"]["members"]) == members}

    def create_quorum(self):
        if self.data_state.get("quorum") or self.data_state.get("bootstrap"):
            raise Problem("Create the starting snapshot from an existing repository before joining peer majority.")
        members = sorted({self.me, *self.data_state["peers"]})
        if len(members) != 3:
            raise Problem("Add both teammates before creating a three-peer snapshot.")
        if self.quorum_candidates():
            raise Problem("A peer starting snapshot is already available. Confirm and join that snapshot.")
        previous = self.snapshot()
        default = previous["default"] if previous else next(
            (branch for branch in ("main", "dev") if branch in self.branches()), "main")
        tips = self.shared()
        if not tips:
            sources = self.snapshot_sources()
            policy = self.policy_for(default)
            branches = policy[1]["protected_branches"] if policy else [ref for ref in BRANCHES if ref in sources]
            if default not in branches or any(branch not in sources for branch in branches):
                raise Problem("Make the protected branches and their default branch available before starting the team.")
            tips = {branch: sources[branch] for branch in branches}
        if default not in tips:
            default = next(iter(tips))
        tags = previous["tags"] if previous else {
            tag: oid for tag, oid in self.refs("refs/tags/").items()
            if any(self.ancestor(self.commit(oid), tip) for tip in tips.values())
        }
        ident, envelope = self.sign("quorum_root", members=members, branches=tips, default=default, tags=tags)
        self.store({ident: envelope})
        return {"message": f"Starting snapshot {ident[:12]} created. Confirm and join it on each Mac.", "id": ident}

    def join_quorum(self, ident):
        if self.data_state.get("quorum"):
            raise Problem("This replica already uses a pinned peer-majority snapshot.")
        if not is_hash(ident, FINGERPRINT) or ident not in self.quorum_candidates():
            raise Problem("Choose a starting snapshot that contains the same three trusted identities.")
        self.save({**self.data_state, "quorum": ident, "tracking": True})
        if not self.data_state.get("bootstrap"):
            self.advance_quorum()
            self.update_tracking({})
        return {"message": "Peer majority enabled. Approvals and branch decisions can sync through any teammate."}

    def ballots(self):
        root_id = self.data_state["quorum"]
        if self.ballot_cache and self.ballot_cache[0] == root_id and self.ballot_cache[1] is self.records:
            return self.ballot_cache[2]
        records = {ident: item["record"] for ident, item in self.records.items()}
        members = set(records[root_id]["members"])
        policies = {}
        eligibility = {}

        def valid(slot, value):
            key = (slot, value["proposal"], value["approval"], tuple(value["checks"]))
            if key in eligibility:
                return eligibility[key]
            branch, base = slot
            proposal = records.get(value["proposal"], {})
            approval = records.get(value["approval"], {})
            eligible = (
                proposal.get("kind") == "proposal" and proposal.get("quorum") == root_id
                and proposal["target"] == branch and proposal["base"] == base and proposal["head"] != base
                and proposal["who"] in members and approval.get("kind") == "review"
                and approval["proposal"] == value["proposal"] and approval["vote"] == "approve"
                and approval["who"] in members and approval["who"] != proposal["who"]
            )
            if eligible:
                try:
                    if base not in policies:
                        policies[base] = self.policy_at(base)
                    policy = policies[base]
                    policy_id, names = (policy[0], set(policy[1]["checks"])) if policy else (None, set())
                    passed = set()
                    for ident in value["checks"]:
                        result = records.get(ident, {})
                        if (result.get("kind") == "check" and result["proposal"] == value["proposal"]
                                and result["policy"] == policy_id and result["who"] in members
                                and result["who"] != proposal["who"]):
                            passed.update(name for name, ok in result["results"].items() if ok)
                    eligible = (approval.get("policy") == policy_id and names <= passed
                                and (not policy or branch in policy[1]["protected_branches"])
                                and self.ancestor(base, proposal["head"]))
                except Problem:
                    eligible = False
            eligibility[key] = eligible
            return eligible

        protocol = Ballots(root_id, records, valid)
        self.ballot_cache = (root_id, self.records, protocol)
        return protocol

    def quorum_value(self, branch, base, requested=None):
        policy = self.policy_at(base)
        if policy and branch not in policy[1]["protected_branches"]:
            return None
        policy_id, names = (policy[0], set(policy[1]["checks"])) if policy else (None, set())
        proposals = []
        for ident in self.revisions():
            if requested is not None and ident != requested:
                continue
            record = self.records[ident]["record"]
            if record.get("quorum") == self.data_state["quorum"] and record["target"] == branch and record["base"] == base:
                proposals.append((record["at"], ident, record))
        for _, ident, record in sorted(proposals):
            if record["head"] == base or not self.ancestor(base, record["head"]):
                continue
            reviews = self.reviews(ident, policy_id)
            if any(review["vote"] == "changes" for review in reviews):
                continue
            approvals = sorted(self.record_id(review) for review in reviews if review["vote"] == "approve"
                               and review["who"] != record["who"])
            if not approvals:
                continue
            passed = {}
            for check_id, envelope in self.records.items():
                check = envelope["record"]
                if (check["kind"] != "check" or check["proposal"] != ident or check["policy"] != policy_id
                        or check["who"] == record["who"]):
                    continue
                for name, result in check["results"].items():
                    key = (name, check["who"])
                    proof = (check["at"], check_id, result)
                    if name in names and (key not in passed or proof > passed[key]):
                        passed[key] = proof
            proofs = {name: check_id for (name, _), (_, check_id, ok) in passed.items() if ok}
            if names <= proofs.keys():
                return {"proposal": ident, "approval": approvals[0], "checks": sorted(set(proofs.values()))}
        return None

    def advance_quorum(self, requested=None, retry_slot=None):
        if self.data_state.get("bootstrap"):
            return
        root = self.data_state["quorum"]
        while True:
            protocol = self.ballots()
            for branch, base in sorted(protocol.tips().items()):
                slot = branch, base
                retry = slot == retry_slot or (requested is not None and self.proposal(requested)["target"] == branch)
                active = max(protocol.slots[slot], key=protocol.ballot, default=None)
                needs_value = not active or retry or protocol.prepares[active]["who"] == self.me
                value = self.quorum_value(branch, base, requested if retry else None) if needs_value else None
                message = protocol.next_message(self.me, slot, value, retry)
                if message is None:
                    continue
                kind, fields = message
                ident, envelope = self.sign(kind, root=root, **fields)
                self.save({**self.data_state, "records": {**self.records, ident: envelope}})
                if retry:
                    requested = None
                    retry_slot = None
                break
            else:
                return

    def retry_stalled_quorum(self):
        if not self.peer_session.status()["reachable"]:
            self.quorum_progress.clear()
            return
        protocol = self.ballots()
        tips = protocol.tips()
        progress = {}
        now = time.monotonic()
        delay = 35 + int(self.me[:8], 16) % 20
        for slot in tips.items():
            active = max(protocol.slots[slot], key=protocol.ballot, default=None)
            if not active:
                continue
            choices = [ident for ident, record in protocol.choices.items() if record["prepare"] == active]
            marker = (active, len(protocol.promises[active]), sum(len(protocol.accepts[choice]) for choice in choices))
            old, since = self.quorum_progress.get(slot, (None, now))
            if old != marker:
                since = now
            elif now - since >= delay:
                self.advance_quorum(retry_slot=slot)
                since = now
            progress[slot] = marker, since
        self.quorum_progress = progress

    def quorum_stale(self, proposal, shared=None):
        root = self.data_state.get("quorum")
        if not root:
            return False
        tips = self.shared() if shared is None else shared
        return proposal.get("quorum") != root or proposal["base"] != tips.get(proposal["target"])

    def shared(self):
        if self.data_state.get("quorum"):
            return self.ballots().tips()
        integrator = self.data_state["integrator"]
        latest = {}
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["who"] != integrator:
                continue
            tips = record["branches"] if record["kind"] == "snapshot" else (
                {record["branch"]: record["head"]} if record["kind"] == "shared" else {})
            for branch, head in tips.items():
                candidate = ((record["at"], ident), head)
                if branch not in latest or candidate > latest[branch]:
                    latest[branch] = candidate
        return {branch: latest[branch][1] for branch in self.protected_branches() if branch in latest}

    def snapshot(self):
        if self.data_state.get("quorum"):
            return self.records[self.data_state["quorum"]]["record"]
        integrator = self.data_state["integrator"]
        candidates = [(item["record"]["at"], ident, item["record"])
                      for ident, item in self.records.items()
                      if item["record"]["kind"] == "snapshot" and item["record"]["who"] == integrator]
        return max(candidates)[2] if candidates else None

    def protected_branches(self):
        snapshot = self.snapshot()
        return tuple(snapshot["branches"]) if snapshot else BRANCHES

    def verify_branch_publication(self, branches, authorized):
        for ref, old in self.shared().items():
            tip = branches.get(ref)
            if not tip or tip == old:
                continue
            if not self.ancestor(old, tip):
                raise Problem(f"{ref} diverged from its last published tip.")
            if authorized.get(ref) != tip and self.policy_for(ref):
                raise Problem(f"Publish changes to {ref} by merging an approved branch review.")

    def publish_snapshot(self, data, authorized=None):
        self.require_integrator()
        refs = self.snapshot_sources()
        selected, default = data.get("branches"), data.get("default")
        if (not isinstance(selected, list) or not selected or not all(ref_name(ref) for ref in selected)
                or not ref_name(default) or default not in selected or any(ref not in refs for ref in selected)):
            raise Problem("Choose the protected branches and a default branch from the available refs.")
        branches = {ref: refs[ref] for ref in sorted(set(selected))}
        previous = self.snapshot()
        default_policy = self.policy_for(previous["default"] if previous else default)
        if default_policy and not authorized and set(branches) != set(default_policy[1]["protected_branches"]):
            raise Problem("Choose every protected branch from the committed PeerTree policy.")
        self.verify_branch_publication(branches, authorized or {})
        all_tags = self.refs("refs/tags/")
        reachable_tags = set()
        if all_tags:
            for tip in set(branches.values()):
                reachable_tags.update(self.git("tag", "--merged", tip).splitlines())
        tags = {ref: all_tags[ref] for ref in sorted(reachable_tags)}
        fields = {"branches": branches, "tags": tags, "default": default}
        if not previous or any(previous[field] != value for field, value in fields.items()):
            ident, envelope = self.sign("snapshot", **fields)
            self.store({ident: envelope})
        return {"message": "Repository snapshot published for paired teammates."}

    def bootstrap_checkout(self):
        if not self.data_state.get("bootstrap"):
            raise Problem("This repository has already been cloned.")
        if self.data_state.get("staging"):
            raise Problem("Choose a folder for the project first.")
        snapshot = self.snapshot()
        if not snapshot:
            raise Problem("Choose the integrator and receive their signed repository snapshot first.")
        branches = self.shared() if self.data_state.get("quorum") else snapshot["branches"]
        tags, default = snapshot["tags"], snapshot["default"]
        current = self.branches()
        current_tags = self.refs("refs/tags/")
        if any(branches.get(ref) != oid for ref, oid in current.items()) or any(
                tags.get(ref) != oid for ref, oid in current_tags.items()):
            raise Problem("The destination already contains branches or tags outside the signed snapshot.")
        if self.git("status", "--porcelain", "--untracked-files=all", "--ignored").strip():
            raise Problem("The clone destination contains local changes or files. Move them before continuing.")
        # Checkout before creating refs so an interrupted first checkout can be retried.
        self.git("switch", "--detach", "--", branches[default])
        updates = [f"create refs/heads/{ref} {oid}\n" for ref, oid in branches.items() if ref not in current]
        updates += [f"create refs/tags/{ref} {oid}\n" for ref, oid in tags.items() if ref not in current_tags]
        if updates:
            self.git("update-ref", "--stdin", data="".join(updates).encode())
        self.git("symbolic-ref", "HEAD", f"refs/heads/{default}")
        self.save({**self.data_state, "bootstrap": False})
        if self.data_state.get("quorum"):
            self.advance_quorum()
            self.update_tracking({})
        return {"message": f"Checked out {default}. Protected branches and release tags are ready locally."}

    def require_integrator(self):
        if self.data_state.get("quorum"):
            raise Problem("Protected branch tips advance through peer-majority reviews.")
        if self.data_state["integrator"] != self.me:
            raise Problem("Only the designated integrator can merge and publish shared branches.")

    def publish(self):
        self.require_integrator()
        pending = self.data_state.get("pending_publication", {})
        authorized = {}
        for branch, merge in pending.items():
            if self.shared().get(branch) == merge["from"] and merge["proposal"] in self.revisions():
                proposal = self.proposal(merge["proposal"])
                policy = self.policy_for(branch)
                if self.merge_gate(merge["proposal"], proposal, policy)["ready"]:
                    authorized[branch] = merge["head"]
        result = self.publish_tips(authorized)
        completed = {branch: merge for branch, merge in pending.items()
                     if self.shared().get(branch) != merge["head"]}
        if completed != pending:
            self.save({**self.data_state, "pending_publication": completed})
        return result

    def publish_tips(self, authorized):
        snapshot = self.snapshot()
        if snapshot:
            return self.publish_snapshot(
                {"branches": list(snapshot["branches"]), "default": snapshot["default"]}, authorized,
            )
        branches, shared = self.branches(), self.shared()
        default = next((branch for branch in ("main", "dev") if branch in branches), "main")
        policy = self.policy_for(default)
        if policy:
            return self.publish_snapshot({"branches": policy[1]["protected_branches"], "default": default},
                                         authorized)
        self.verify_branch_publication({ref: head for ref, head in branches.items() if ref in BRANCHES},
                                       authorized or {})
        additions = {}
        for branch in BRANCHES:
            if branch not in branches or shared.get(branch) == branches[branch]:
                continue
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

    def integrate(self, ident, revision=None):
        quorum = self.data_state.get("quorum")
        if not quorum:
            self.require_integrator()
        proposal = self.proposal(ident)
        if revision is not None and revision != proposal["head"]:
            raise Problem("The reviewed commit does not match this branch submission.")
        if proposal["target"] not in self.protected_branches():
            raise Problem("This branch is outside the current protected branch list.")
        if ident not in self.revisions():
            raise Problem("A newer revision is available. Merge it after review.")
        if quorum and self.quorum_stale(proposal):
            raise Problem("Rebase onto the current shared target tip and submit again.")
        policy = self.policy_for(proposal["target"])
        gate = self.merge_gate(ident, proposal, policy)
        if gate["blocked"]:
            raise Problem("A reviewer has requested changes.")
        if gate["approvals"] < gate["required"]:
            raise Problem(f"This revision has {gate['approvals']} of {gate['required']} required teammate approvals.")
        if gate["missing"]:
            raise Problem(f"Required checks have not passed: {', '.join(gate['missing'])}.")
        if quorum:
            old = self.shared()
            self.advance_quorum(ident)
            self.update_tracking(old)
            return {"message": "Peer merge started. Sync with a teammate to certify the branch tip."}
        branch, head = proposal["target"], proposal["head"]
        current = self.commit(f"refs/heads/{branch}")
        if self.ancestor(head, current):
            raise Problem("This revision is already included in the target branch.")
        published = self.shared().get(branch)
        if policy and current != published:
            raise Problem(f"Start the merge from the last published {branch} tip.")
        if published and not self.ancestor(published, current):
            raise Problem(f"Local {branch} diverged from the last published tip.")
        targets = self.snapshot_sources() if self.snapshot() else self.branches()
        targets = {ref: tip for ref, tip in targets.items() if ref in self.protected_branches()}
        self.verify_branch_publication(targets, {})
        self.clean_branch(branch, current)
        try:
            self.git("merge", "--no-ff", "--no-edit", "--", head)
        except Problem as error:
            merge_head = self.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD").strip()
            if Path(merge_head).exists():
                self.git("merge", "--abort")
            raise Problem(f"Git could not merge {proposal['source']}.\n{error}") from error
        try:
            pending = {**self.data_state.get("pending_publication", {}),
                       branch: {"from": current, "head": self.commit("HEAD"), "proposal": ident}}
            self.save({**self.data_state, "pending_publication": pending})
            return self.publish()
        except Problem as error:
            raise Problem(f"Merged into {branch}. Publishing failed, so use Publish branch tips after resolving this issue.\n{error}") from error

    def sync(self, branch):
        if self.data_state.get("bootstrap"):
            raise Problem("Finish the initial repository checkout before syncing branches.")
        if branch not in self.shared():
            raise Problem("Receive a shared branch tip before syncing.")
        head = self.shared()[branch]
        current = self.branches().get(branch)
        if current and not self.ancestor(current, head):
            if self.ancestor(head, current):
                raise Problem(f"Local {branch} is already ahead of the published tip.")
            raise Problem(f"Local {branch} has diverged. Reconcile it in Git before syncing.")
        self.clean_branch(branch, current or head)
        self.git("merge", "--ff-only", "--", head)
        self.view_version += 1
        return {"message": f"{branch} is synced to {head[:9]}."}

    def team(self, data):
        action = data.get("action")
        if action == "quorum-init":
            return self.create_quorum()
        if action == "quorum-join":
            return self.join_quorum(data.get("id"))
        old_tips = self.shared() if self.data_state.get("tracking") and action == "integrator" else None
        state = dict(self.data_state)
        if action == "add":
            name, entry = data.get("name", "").strip(), data.get("key", "").strip()
            key_text, pin = decode_code(entry) if entry.startswith(PEER_CODE) else (entry, "")
            key = clean_key(key_text)
            ident = key_id(key)
            if not short_text(name, 80) or ident == self.me:
                raise Problem("Enter a teammate's name and verified pairing code or public key.")
            if state.get("quorum") and ident not in self.snapshot()["members"]:
                raise Problem("The peer-majority snapshot pins these three signing identities.")
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
            if state.get("quorum"):
                raise Problem("This repository uses peer majority to publish branch tips.")
            ident = data.get("id")
            if ident == self.me and state.get("bootstrap"):
                raise Problem("Select the teammate providing the repository snapshot.")
            if ident != self.me and ident not in state["peers"]:
                raise Problem("Choose a known teammate.")
            state["integrator"] = ident
        elif action == "check":
            check = data.get("command", "").strip()
            if len(check) > 1000:
                raise Problem("Keep the command under 1,000 characters.")
            state["check"] = check
        elif action == "notification":
            category, enabled = data.get("category"), data.get("enabled")
            if category not in NOTIFICATIONS or type(enabled) is not bool:
                raise Problem("Choose a notification preference.")
            state["notifications"] = {**state.get("notifications", {}), category: enabled}
        else:
            raise Problem("Unknown team setting.")
        self.save(state)
        self.update_tracking(old_tips)
        return {"message": "Team settings saved."}

    def pairing_offer(self, role):
        """What this Mac tells a newly paired Mac once both people confirm the code."""
        offer = {"key": self.public, "name": self.data_state["name"]}
        if role == "host":
            offer.update(
                project=self.data_state["project"],
                object_format=self.git("rev-parse", "--show-object-format").strip(),
                integrator=self.data_state["integrator"] or self.me,
                teammates=[{"key": peer["key"], "name": peer["name"], **({"pin": peer["pin"]} if peer.get("pin") else {})}
                           for peer in self.data_state["peers"].values()],
            )
        return offer

    def apply_pairing(self, result):
        offer, pin, role = result.get("offer"), result.get("pin"), result.get("role")
        if not isinstance(offer, dict) or not is_hash(pin, FINGERPRINT) or role not in ("host", "join"):
            raise Problem("The pairing reply was incomplete.")
        if not short_text(offer.get("name"), 80):
            raise Problem("The other Mac sent an invalid name.")
        key = clean_key(str(offer.get("key", "")))
        ident = key_id(key)
        state = dict(self.data_state)
        peers = dict(state["peers"])
        if ident == self.me:
            raise Problem("This Mac cannot pair with itself.")
        if any(peer.get("pin") == pin for who, peer in peers.items() if who != ident):
            raise Problem("That Mac's certificate is already paired with another teammate.")
        peers[ident] = {**peers.get(ident, {}), "name": offer["name"], "key": key, "pin": pin}
        if role == "host":
            if state.get("quorum") and ident not in self.snapshot()["members"]:
                raise Problem("The peer-majority snapshot pins these three signing identities.")
            self.save({**state, "peers": peers})
            # Teammates who already trust this Mac learn about the new one when they next sync.
            intro_id, envelope = self.sign("introduction", key=key, pin=pin, name=offer["name"])
            self.store({intro_id: envelope})
            return {"message": f"Paired with {offer['name']}.", "name": offer["name"]}
        if not state.get("joining"):
            raise Problem("This Mac already belongs to a project.")
        project, object_format = offer.get("project"), offer.get("object_format")
        if not short_text(project, 80) or object_format not in ("sha1", "sha256"):
            raise Problem("The host sent an invalid project.")
        teammates = offer.get("teammates")
        if not isinstance(teammates, list) or len(teammates) > 16:
            raise Problem("The host sent an invalid team.")
        for teammate in teammates:
            if not isinstance(teammate, dict) or not short_text(teammate.get("name"), 80):
                raise Problem("The host sent an invalid teammate.")
            teammate_key = clean_key(str(teammate.get("key", "")))
            teammate_id = key_id(teammate_key)
            teammate_pin = teammate.get("pin")
            if teammate_id in (self.me, ident) or (teammate_pin is not None and not is_hash(teammate_pin, FINGERPRINT)):
                continue
            peers[teammate_id] = {"name": teammate["name"], "key": teammate_key,
                                  **({"pin": teammate_pin} if teammate_pin else {})}
        integrator = offer.get("integrator") if offer.get("integrator") in peers else ident
        if object_format != self.git("rev-parse", "--show-object-format").strip():
            self.reinitialize(object_format)
        self.save({**state, "project": project, "peers": peers, "integrator": integrator, "joining": False})
        return {"message": f"Joined {project} with {offer['name']}.", "name": offer["name"]}

    def pairing_status(self):
        session = self.peer_session
        status = session.pairing_status() if session else {"available": False}
        return {**status, "joining": bool(self.data_state.get("joining")),
                "staging": bool(self.data_state.get("staging")), "project": self.data_state["project"],
                "name": self.data_state["name"], "path": str(self.root)}

    def pairing_action(self, data):
        session = self.peer_session
        if not session or session.directory is None:
            raise Problem("Turn on nearby Wi-Fi to pair Macs.")
        action = data.get("action")
        if action == "host":
            return session.host_open()
        if action == "start":
            return session.pair_start(data.get("id"))
        if action == "confirm":
            return session.pair_confirm(data.get("code"))
        if action == "cancel":
            return session.pair_cancel()
        raise Problem("Unknown pairing action.")

    def apply_introductions(self, additions):
        """Trust Macs that a trusted teammate paired in person, so one approval reaches the team."""
        peers = dict(self.data_state["peers"])
        members = set(self.snapshot()["members"]) if self.data_state.get("quorum") and self.snapshot() else None
        for envelope in additions.values():
            record = envelope["record"]
            if record["kind"] != "introduction":
                continue
            try:
                key = clean_key(record["key"])
            except Problem:
                continue
            ident = key_id(key)
            existing = peers.get(ident, {})
            if (ident in (self.me, record["who"]) or existing.get("pin")
                    or (members is not None and ident not in members)
                    or any(peer.get("pin") == record["pin"] for who, peer in peers.items() if who != ident)):
                continue
            peers[ident] = {**existing, "name": existing.get("name", record["name"]), "key": key, "pin": record["pin"]}
        if peers != self.data_state["peers"]:
            self.save({**self.data_state, "peers": peers})

    def reinitialize(self, object_format):
        """Recreate a joining Mac's still-empty repository with the host's object format."""
        if self.records or not self.data_state.get("joining"):
            raise Problem("This repository already has history.")
        git_dir = self.root / ".git"
        keep = self.root / ".peertree-joining"
        os.replace(self.data, keep)
        shutil.rmtree(git_dir)
        run(["git", "init", "--quiet", "--initial-branch=peertree-unborn", f"--object-format={object_format}"],
            cwd=self.root)
        os.replace(keep, self.data)

    def choose_destination(self):
        """Ask where the joined project lives, then move the staging repository there."""
        with self.lock:
            if not self.data_state.get("staging"):
                raise Problem("This repository already has a folder.")
            project = self.data_state["project"]
            if not project:
                raise Problem("Pair with a teammate first.")
        script = ["/usr/bin/osascript", "-e", "on run argv", "-e", "activate",
                  "-e", "POSIX path of (choose folder with prompt (item 1 of argv) default location (path to home folder))",
                  "-e", "end run", f"Choose where to put {project}"]
        result = subprocess.run(script, capture_output=True, text=True)
        if result.returncode:
            return {"message": "No folder chosen."}
        chosen = Path(result.stdout.strip()).resolve()
        folder_name = re.sub(r"[/:\x00]", "-", project).strip(". ") or "project"
        destination = chosen if not any(chosen.iterdir()) else chosen / folder_name
        if destination.exists() and any(destination.iterdir()):
            raise Problem(f"{destination} already exists. Choose another folder.")
        with self.lock:
            self.relocate(destination)
        return {"message": f"{project} will live in {destination}.", "path": str(destination)}

    def relocate(self, destination):
        source = self.root
        if destination == source:
            return
        if destination.exists():
            destination.rmdir()
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.rename(source, destination)
        except OSError:
            shutil.move(str(source), str(destination))
            # A copied lock file is a new file, so take the instance lock again.
            self.instance.close()
            self.instance = (destination / ".git" / "neighbor-review" / "instance.lock").open("a")
            fcntl.flock(self.instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.root = destination
        self.data = destination / ".git" / "neighbor-review"
        self.key = self.data / "identity"
        self.file = self.data / "state.json"
        self.save({key: value for key, value in self.data_state.items() if key != "staging"})

    def cached_helpers(self):
        return [path for path in self.data.glob("neighbor-peer-*")
                if re.fullmatch(r"neighbor-peer-[0-9a-f]{16}", path.name)
                and path.is_file() and not path.is_symlink()]

    def removable_helpers(self, paths):
        session = self.peer_session
        if session and session.initializing:
            return []
        if session and session.helper and session.helper.poll() is None:
            running = Path(session.helper.args[0])
            return [path for path in paths if path != running]
        return paths

    def storage(self):
        sizes = dict(line.split(": ", 1) for line in self.git("count-objects", "-v").splitlines()
                     if line.startswith(("size: ", "size-pack: ")))
        helpers = self.cached_helpers()
        session_path = self.peer_session.directory if self.peer_session else None
        pending = ([path for direction in ("incoming", "outgoing")
                    for path in (session_path / direction).glob("*.zip")] if session_path else [])

        def total(paths):
            size = 0
            for path in paths:
                try:
                    size += path.stat().st_size
                except FileNotFoundError:
                    continue  # The Wi-Fi helper can finish a transfer while storage is measured.
            return size

        home = Path.home()
        return {
            "repository": 1024 * sum(int(value) for value in sizes.values()),
            "cache": total(helpers),
            "pending": total(pending),
            "path": str(Path("~") / self.data.relative_to(home)) if home in self.data.parents else str(self.data),
            "can_prune": bool(self.removable_helpers(helpers)),
        }

    def prune_cache(self):
        helpers = self.removable_helpers(self.cached_helpers())
        for path in helpers:
            path.unlink(missing_ok=True)
        return {"message": "Cleared cached peer helpers." if helpers else "There are no unused peer helpers to clear."}

    def inventory_plan(self, remote, local=None):
        local = list(self.records) if local is None else local
        return rust_request("__inventory", encoded({"local": local, "remote": remote}))

    def export(self, plan=None):
        with self.lock:
            parts = self.export_records(plan)
        return self.export_archive(*parts)

    def export_records(self, plan=None):
        """Choose an exchange's records and Git refs. This is quick enough to run under the lock."""
        if not plan:
            selected = list(self.records.values())
            metadata = encoded(selected)
            if len(metadata) > MAX_RECORDS:
                raise Problem("The signed exchange records exceed 2 MB.")
            return metadata, None, None
        # A teammate who is far behind catches up over several exchanges. Submissions go
        # before the reviews, comments, and checks that reference them, so every packet
        # imports on its own and the next one follows once the teammate's inventory updates.
        missing = sorted((self.records[ident] for ident in plan["missing"]),
                         key=lambda item: (item["record"]["kind"] in DEPENDENT_KINDS, item["record"]["at"]))
        selected, size = [], 2
        for item in missing:
            size += len(encoded(item)) + 1
            if selected and size > MAX_RECORDS:
                break
            selected.append(item)
        wanted, tags = referenced_objects([item["record"] for item in selected])
        known, known_tags = referenced_objects([self.records[ident]["record"] for ident in plan["common"]])
        return encoded(selected), (wanted | tags) - (known | known_tags), known | known_tags

    def export_archive(self, metadata, refs, known):
        """Bundle the Git objects for chosen records. Runs without the lock; Git allows concurrent reads."""
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "objects.bundle"
            if refs:
                spec = "".join(f"refs/neighbor-review/objects/{oid}\n" for oid in sorted(refs))
                spec += "".join(f"^{oid}\n" for oid in sorted(known))
                if self.git_bytes("rev-list", "--objects", "--stdin", data=spec.encode()):
                    self.git("bundle", "create", str(bundle), "--stdin", data=spec.encode())
            elif refs is None and self.git("for-each-ref", "refs/neighbor-review/objects/").strip():
                self.git("bundle", "create", str(bundle), "--glob=refs/neighbor-review/objects/*")
            if bundle.exists() and bundle.stat().st_size > MAX_EXCHANGE - MAX_RECORDS:
                raise Problem("The Git bundle exceeds the 512 MB exchange limit.")
            memory = io.BytesIO()
            with zipfile.ZipFile(memory, "w") as out:
                out.writestr("records.json", metadata)
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
                        or archive.getinfo("records.json").file_size > MAX_RECORDS):
                    raise Problem("Invalid or oversized exchange.")
                records = json.loads(archive.read("records.json"))
                if not isinstance(records, list):
                    raise Problem("Invalid exchange records.")
                # Checking signatures is the slow part, so it runs before taking the lock, and
                # records this Mac already holds are skipped: teammates resend a batch until
                # they hear that it arrived.
                with self.lock:
                    known = self.records
                    bootstrapping = self.data_state.get("bootstrap", False)
                    trusted = {self.me, *self.data_state["peers"]}
                verified = {}
                for envelope in records:
                    record = envelope.get("record") if isinstance(envelope, dict) else None
                    if (bootstrapping and isinstance(record, dict)
                            and is_hash(record.get("who"), FINGERPRINT) and record["who"] not in trusted):
                        continue
                    if isinstance(record, dict) and self.record_id(record) in known:
                        continue
                    ident = self.verified(envelope, directory)
                    verified[ident] = envelope
                with self.lock:
                    additions = {ident: envelope for ident, envelope in verified.items()
                                 if ident not in self.records}
                    all_records = self.records | additions
                    for ident, item in list(additions.items()):
                        record = item["record"]
                        if record["kind"] not in ("review", "comment", "check"):
                            continue
                        subject = all_records.get(record["proposal"], {}).get("record", {})
                        if not subject and bootstrapping:
                            del additions[ident]
                            continue
                        if (subject.get("kind") != "proposal"
                                or (record["kind"] == "review" and subject["who"] == record["who"])):
                            raise Problem("An exchange contains a comment, check, or review without a valid submission.")
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
                    self.apply_introductions(additions)
                    people = self.data_state["peers"]
                    activity = []
                    for item in additions.values():
                        record = item["record"]
                        name = people.get(record["who"], {}).get("name", self.data_state["name"])
                        if record["kind"] == "proposal":
                            activity.append(f"{name} submitted “{record['title']}” for review.")
                        elif record["kind"] == "review":
                            activity.append(f"{name} reviewed a submitted branch.")
                        elif record["kind"] == "comment":
                            activity.append(f"{name} commented on a submitted branch.")
                        elif record["kind"] == "check":
                            activity.append(f"{name} ran local checks on a submitted branch.")
                        elif record["kind"] in ("snapshot", "quorum_root"):
                            activity.append(f"{name} published a repository snapshot.")
                        elif record["kind"] == "shared":
                            activity.append(f"{name} published a new {record['branch']} tip.")
                        elif record["kind"] == "introduction":
                            activity.append(f"{name} paired {record['name']} with the team.")
                    return {"message": f"Imported {len(additions)} new exchange records.",
                            "imported": len(additions), "activity": activity[:10]}

    def view(self):
        branches = self.branches()
        shared = self.shared()
        snapshot = self.snapshot()
        people = {ident: peer["name"] for ident, peer in self.data_state["peers"].items()}
        people[self.me] = self.data_state["name"]
        revisions = self.revisions()
        quorum = self.data_state.get("quorum")
        protocol = self.ballots() if quorum else None
        policies = {}
        proposals = []
        for ident, envelope in self.records.items():
            record = envelope["record"]
            if record["kind"] != "proposal":
                continue
            if not quorum and record.get("quorum"):
                continue
            merged = self.merged_proposal(record, branches, shared)
            stale = self.quorum_stale(record, shared) and not merged
            target = record["target"]
            if target not in policies:
                try:
                    policies[target] = (self.policy_for(target), "")
                except Problem as issue:
                    policies[target] = (None, str(issue))
            policy, issue = policies[target]
            reviews = self.reviews(ident, policy[0] if policy else None)
            try:
                gate = self.merge_gate(ident, record, policy) if not issue else {}
            except Problem as error:
                gate, issue = {}, str(error)
            checks = list(policy[1]["checks"]) if policy else []
            run = self.data_state["runs"].get(ident)
            pipeline_status = "running" if self.running_check == ident else None
            if (not pipeline_status and self.check_worker and record["who"] == self.me
                    and not self.data_state.get("bootstrap")
                    and not merged and not stale and ident in revisions and not issue and checks
                    and (not run or run.get("policy") != policy[0])):
                pipeline_status = "queued"
            proposals.append({
                **record, **{"ready": False, "blocked": False, "approvals": 0, "required": 2,
                             "missing": []}, **gate,
                "id": ident, "merged": merged, "superseded": ident not in revisions and not merged,
                "quorum_stale": stale,
                "quorum_pending": bool(protocol and not stale and not merged
                                       and protocol.slots[target, record["base"]]),
                "policy": policy[0] if policy else None, "policy_error": issue,
                "checks": checks, "pipeline_status": pipeline_status,
                "reviews": reviews, "comments": self.comments(ident),
                "run": run,
            })
        return {
            "project": self.data_state["project"], "repo": str(self.root), "me": self.me,
            "version": self.view_version,
            "running_check": self.running_check,
            "public": self.public, "people": people, "integrator": self.data_state["integrator"],
            "quorum": quorum, "quorum_error": self.quorum_error,
            "quorum_snapshots": [{"id": ident, "who": root["who"], "branches": root["branches"]}
                                 for ident, root in self.quorum_candidates().items()] if not quorum else [],
            "paired": [who for who, peer in self.data_state["peers"].items() if peer.get("pin")],
            "check": self.data_state["check"], "branches": branches, "shared": shared,
            "policy_in_worktree": (self.root / POLICY_FILE).is_file(),
            "notifications": {**NOTIFICATIONS, **self.data_state.get("notifications", {})},
            "branch_status": self.branch_status(branches, shared),
            "protected": list(self.protected_branches()), "bootstrap": self.data_state.get("bootstrap", False),
            "joining": bool(self.data_state.get("joining")), "staging": bool(self.data_state.get("staging")),
            "snapshot": ({"branches": list(snapshot["branches"]), "tags": len(snapshot["tags"]),
                          "default": snapshot["default"]} if snapshot else None),
            "snapshot_sources": list(self.snapshot_sources()) if self.data_state["integrator"] == self.me else [],
            "worktrees": self.worktrees(),
            "tracking_error": self.tracking_error,
            "proposals": sorted(proposals, key=lambda row: (
                row["merged"] or row["superseded"], -row["at"])),
        }


def handle(workspace, token):
    class Handler(BaseHTTPRequestHandler):
        def send(self, status, data, mime="application/json; charset=utf-8", attachment=None, etag=None):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            if status != 304:
                self.send_header("Content-Length", str(len(data)))
            if etag:
                self.send_header("Cache-Control", "no-cache")
                self.send_header("ETag", etag)
            else:
                self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.end_headers()
            self.wfile.write(data)

        def dispatch(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                raise Problem("Use the local address printed by the app.")
            request_url = urlsplit(self.path)
            path = request_url.path
            if self.command == "GET":
                assets = {
                    "/": ("index.html", "text/html; charset=utf-8"),
                    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                    "/style.css": ("style.css", "text/css; charset=utf-8"),
                    "/assets/marked/marked.umd.js": ("assets/marked/marked.umd.js", "text/javascript; charset=utf-8"),
                    "/assets/peertree-mark.png": ("assets/peertree-mark.png", "image/png"),
                    "/assets/seti/theme.json": ("assets/seti/theme.json", "application/json; charset=utf-8"),
                    "/assets/seti/seti.woff": ("assets/seti/seti.woff", "font/woff"),
                }
                if path in assets:
                    name, mime = assets[path]
                    content = (ASSETS / name).read_bytes()
                    if path == "/":
                        # The page carries this session's token, so it is never cached.
                        content = content.replace(b"__SESSION_TOKEN__", html.escape(token).encode())
                        self.send(200, content, mime)
                        return
                    etag = '"' + hashlib.sha256(content).hexdigest()[:32] + '"'
                    if etag in (self.headers.get("If-None-Match") or "").replace(" ", "").split(","):
                        self.send(304, b"", mime, etag=etag)
                        return
                    self.send(200, content, mime, etag=etag)
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
                    elif path == "/api/code":
                        result = workspace.code(parse_qs(request_url.query).get("path", [""])[0])
                    elif path == "/api/history":
                        result = workspace.history()
                    elif path.startswith("/api/commit/"):
                        result = workspace.commit_diff(path.rsplit("/", 1)[1])
                    elif path == "/api/activity":
                        result = workspace.activity()
                    elif path == "/api/storage":
                        result = workspace.storage()
                    elif path.startswith("/api/diff/"):
                        result = workspace.inspect(path.rsplit("/", 1)[1])
                    elif path == "/api/pairing":
                        result = workspace.pairing_status()
                    elif path == "/api/export":
                        self.send(200, workspace.export(), "application/zip", "neighbor-exchange.zip")
                        return
                    else:
                        self.send(404, encoded({"error": "Unknown request."}))
                        return
            else:
                size = int(self.headers.get("Content-Length", "0"))
                limit = (MAX_EXCHANGE if path == "/api/import" else
                         65536 if path in ("/api/comment", "/api/agent") else 16000)
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
                    elif path == "/api/destination":
                        result = workspace.choose_destination()
                    elif path == "/api/pairing":
                        result = workspace.pairing_action(data)
                    elif path == "/api/agent":
                        result = agent.execute(workspace, data, MAX_EXCHANGE, pairing_code)
                    else:
                        with workspace.lock:
                            actions = {
                                "/api/propose": lambda: workspace.create(data),
                                "/api/share": workspace.share_exchange,
                                "/api/worktree": lambda: workspace.select_worktree(data.get("path")),
                                "/api/review": lambda: workspace.review(data),
                                "/api/comment": lambda: workspace.comment(data),
                                "/api/team": lambda: workspace.team(data),
                                "/api/publish": workspace.publish,
                                "/api/snapshot": lambda: workspace.publish_snapshot(data),
                                "/api/checkout": workspace.bootstrap_checkout,
                                "/api/sync": lambda: workspace.sync(data.get("branch")),
                                "/api/refresh": workspace.refresh_exchange,
                                "/api/prune-cache": workspace.prune_cache,
                                "/api/open-link": lambda: open_markdown_link(data.get("url")),
                                "/api/integrate": lambda: workspace.integrate(data.get("id"), data.get("revision")),
                            }
                            if path not in actions:
                                self.send(404, encoded({"error": "Unknown request."}))
                                return
                            result = actions[path]()
            self.send(200, encoded(result))

        def request(self):
            try:
                self.dispatch()
            except (Problem, ValueError, TypeError, AttributeError, KeyError, zipfile.BadZipFile) as error:
                self.send(400, encoded({"error": str(error)}))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except OSError as error:
                self.send(400, encoded({"error": str(error)}))

        do_GET = request
        do_POST = request

    return Handler


def pairing_code(workspace):
    return identity(workspace.data / "peer-identity", workspace.public, run)[1]


def prepare_clone(destination, object_format):
    root = Path(destination).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        state_file = root / ".git" / "neighbor-review" / "state.json"
        if not state_file.is_file() or not json.loads(state_file.read_text()).get("bootstrap"):
            raise Problem("Choose a new or empty directory for the clone.")
        if object_format:
            existing = run(["git", "rev-parse", "--show-object-format"], cwd=root).decode().strip()
            if existing != object_format:
                raise Problem(f"This pending clone already uses {existing}.")
        return root, False
    else:
        run(["git", "init", "--quiet", "--initial-branch=peertree-unborn",
             f"--object-format={object_format or 'sha1'}"], cwd=root)
    return root, True


def main():
    if sys.argv[1:2] == ["--agent-cli"]:
        return agent.cli(sys.argv[2:], Workspace, AlreadyOpen, MAX_EXCHANGE, pairing_code)
    parser = argparse.ArgumentParser(
        prog="peertree", description="Local Git review for three teammates.",
        epilog="Use peertree pr --help for branch reviews and peertree --agent-help for agent commands.",
    )
    parser.add_argument("command", choices=["clone"], nargs="?", help="start a fresh clone from a paired teammate")
    parser.add_argument("destination", nargs="?", help="new or empty clone directory")
    parser.add_argument("--repo", help="path to an existing Git working copy")
    parser.add_argument("--project", help="shared project name, defaults to the origin repository name")
    parser.add_argument("--name", help="display name, defaults to Git user.name")
    parser.add_argument("--check", help="local pipeline shell command")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--desktop-ready", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--object-format", choices=["sha1", "sha256"], help="object format for a fresh clone")
    parser.add_argument("--join", action="store_true",
                        help="with clone: wait for a nearby teammate to add this Mac instead of naming a project")
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
    if args.command == "clone" and (not args.destination or args.repo or bool(args.project) == args.join):
        parser.error("Use peertree clone DESTINATION --project PROJECT, or peertree clone DESTINATION --join.")
    if args.join and (args.command != "clone" or args.peer is False):
        parser.error("Joining a teammate needs peertree clone DESTINATION --join with nearby Wi-Fi.")
    if not args.command and (args.destination or args.object_format):
        parser.error("A destination and object format require the clone command.")
    workspace = None
    try:
        bootstrap = args.command == "clone"
        repo, new_clone = prepare_clone(args.destination, args.object_format) if bootstrap else (args.repo or ".", False)
        peer = True if new_clone and args.peer is None and args.lan is None else args.peer
        try:
            workspace = Workspace(repo, args.project and args.project.strip(),
                                  args.name and args.name.strip(), args.check, args.lan,
                                  True if args.join else peer, bootstrap, joining=args.join)
        except AlreadyOpen:
            if not args.desktop_ready:
                raise
            port = agent.reuse_desktop(repo, peer is True, args.project.strip() if args.project else None)
            print(json.dumps({"port": port, "owned": False}), flush=True)
            return 0
        token = secrets.token_urlsafe(32)
        with ThreadingHTTPServer(("127.0.0.1", args.port), handle(workspace, token)) as server:
            session = workspace.data / agent.SESSION_FILE
            with tempfile.NamedTemporaryFile(dir=workspace.data, delete=False) as staged:
                staged.write(encoded({"port": server.server_port, "token": token}))
            os.replace(staged.name, session)
            url = f"http://127.0.0.1:{server.server_port}"
            previous_term_handler = None
            if args.desktop_ready:
                previous_term_handler = signal.signal(signal.SIGTERM, signal.default_int_handler)
            if workspace.data_state.get("lan"):
                workspace.announcements = Announcements(workspace.outgoing_notices, workspace.receive_notice)
                workspace.announcements.start()
            if workspace.data_state.get("peer"):
                workspace.peer_session = PeerSession(workspace, run)
                workspace.peer_session.start()
            try:
                workspace.start_checks()
                if args.desktop_ready:
                    print(json.dumps({"port": server.server_port, "owned": True}), flush=True)
                else:
                    print(f"PeerTree is open at {url}", flush=True)
                if not args.no_open and not args.desktop_ready:
                    webbrowser.open(url)
                server.serve_forever()
            finally:
                session.unlink(missing_ok=True)
                workspace.stop_checks()
                if workspace.announcements:
                    workspace.announcements.close()
                if workspace.peer_session:
                    workspace.peer_session.close()
                if workspace.share_folder:
                    workspace.share_folder.cleanup()
                if previous_term_handler is not None:
                    signal.signal(signal.SIGTERM, previous_term_handler)
    except (Problem, OSError, ValueError) as error:
        if args.desktop_ready:
            print(json.dumps({"error": str(error)}), flush=True)
            return 1
        parser.exit(1, f"{error}\n")
    except KeyboardInterrupt:
        pass
    finally:
        if workspace is not None:
            workspace.instance.close()


if __name__ == "__main__":
    sys.exit(main())
