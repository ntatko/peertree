"""Shared service actions for PeerTree's noninteractive Rust commands."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

SESSION_FILE = "agent-session.json"


class AgentError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise AgentError(message)


def add_body(parser, name, limit, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument(f"--{name}")
    group.add_argument("--body-file", type=Path)
    parser.set_defaults(body_key=name, body_limit=limit)


def parse_cli(arguments):
    global_flags = Parser(add_help=False, allow_abbrev=False)
    global_flags.add_argument("--repo", type=Path, default=Path.cwd())
    global_flags.add_argument("--json", action="store_true")
    global_flags.add_argument("--project")
    global_flags.add_argument("--name")
    flags, arguments = global_flags.parse_known_args(arguments)
    cli = Parser(prog="peertree", allow_abbrev=False)
    groups = cli.add_subparsers(required=True, dest="group")

    pr = groups.add_parser("pr", help="Inspect and update branch reviews")
    actions = pr.add_subparsers(required=True, dest="action")
    actions.add_parser("list")
    submit = actions.add_parser("submit")
    submit.add_argument("--source", help="Defaults to the current worktree branch")
    submit.add_argument("--base", required=True)
    submit.add_argument("--title", required=True)
    for action in ("diff", "show", "comment", "review", "merge"):
        operation = actions.add_parser(action)
        operation.add_argument("id")
        if action == "comment":
            add_body(operation, "body", 4000, required=True)
            operation.add_argument("--file", help="File path in the review diff")
            operation.add_argument("--line", type=int, help="Line number in the review diff")
            operation.add_argument("--side", choices=("old", "new"), help="Defaults to new for line comments")
        elif action == "review":
            votes = operation.add_mutually_exclusive_group(required=True)
            votes.add_argument("--approve", action="store_const", const="approve", dest="vote")
            votes.add_argument("--request-changes", action="store_const", const="changes", dest="vote")
            operation.add_argument("--revision", required=True)
            add_body(operation, "note", 1000)
        elif action == "merge":
            operation.add_argument("--revision")

    checks = groups.add_parser("checks", help="Run the committed local checks")
    run = checks.add_subparsers(required=True, dest="action").add_parser("run")
    run.add_argument("id")

    sync = groups.add_parser("sync", help="Exchange signed updates or fast-forward a local branch")
    transfer = sync.add_mutually_exclusive_group()
    transfer.add_argument("--export", dest="export_path", type=Path)
    transfer.add_argument("--import", dest="import_path", type=Path)
    transfer.add_argument("--inventory", dest="inventory_path", type=Path)
    sync.add_argument("--since", type=Path, help="Send records missing from this teammate's inventory")
    sync.add_argument("branch", nargs="?")

    policy = groups.add_parser("policy", help="Inspect the policy on the last published branch")
    show = policy.add_subparsers(required=True, dest="action").add_parser("show")
    show.add_argument("--base", default="main")

    team = groups.add_parser("team", help="Configure a local PeerTree identity")
    settings = team.add_subparsers(required=True, dest="action")
    identity = settings.add_parser("identity")
    identity.add_argument("--pairing", action="store_true")
    trust = settings.add_parser("trust")
    trust.add_argument("teammate")
    supplied = trust.add_mutually_exclusive_group(required=True)
    supplied.add_argument("--key")
    supplied.add_argument("--key-file", type=Path)
    integrator = settings.add_parser("integrator")
    integrator.add_argument("id")
    settings.add_parser("quorum-init", help="Create the shared three-peer starting snapshot")
    quorum = settings.add_parser("quorum-join", help="Join a verified starting snapshot by its full ID")
    quorum.add_argument("id")
    pipeline = settings.add_parser("pipeline")
    pipeline.add_argument("command")

    publish = groups.add_parser("publish", help="Publish accepted branch tips or the initial snapshot")
    publish.add_argument("--branch", dest="branches", action="append")
    publish.add_argument("--default")
    if not arguments:
        cli.print_help()
        raise SystemExit(0)
    request = vars(cli.parse_args(arguments))
    key = request.pop("body_key", None)
    path = request.pop("body_file", None)
    if key:
        limit = request.pop("body_limit")
        request[key] = limited_text(path, limit) if path else (request.get(key) or "")
    if request["group"] == "pr" and request["action"] == "comment":
        file, line, side = (request.pop(field) for field in ("file", "line", "side"))
        if any(value is not None for value in (file, line, side)):
            if not file or not line or line < 1:
                raise AgentError("Use --file and a positive --line together for a line comment.")
            request["anchor"] = {"file": file, "line": line, "side": side or "new"}
    key_file = request.pop("key_file", None)
    if key_file:
        request["key"] = limited_text(key_file, 1024)
    for field in ("export_path", "import_path", "inventory_path", "since"):
        if request.get(field):
            request[field] = str(request[field].expanduser().resolve())
    if request.get("branch") and any(request.get(field) for field in ("import_path", "export_path", "inventory_path")):
        raise AgentError("Choose a branch or a file transfer.")
    if request.get("since") and not request.get("export_path"):
        raise AgentError("--since requires --export.")
    if bool(request.get("branches")) != bool(request.get("default")):
        raise AgentError("Use --branch and --default together to publish a snapshot.")
    return flags, request


def limited_text(path, limit):
    with path.open("rb") as source:
        raw = source.read(limit * 4 + 1)
    value = raw.decode("utf-8")
    if len(value) > limit:
        raise AgentError(f"The text file exceeds {limit:,} characters.")
    return value


def worktree_root(path):
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=path,
                            capture_output=True, text=True)
    if result.returncode:
        raise AgentError(result.stderr.strip() or "Run PeerTree inside a Git worktree.")
    return Path(result.stdout.strip()).resolve()


def git_common(root):
    return Path(subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=root, text=True,
    ).strip())


def resolve_pr(workspace, value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8,64}", value):
        raise AgentError("Enter a branch review ID of at least eight hexadecimal characters.")
    found = [ident for ident, envelope in workspace.records.items()
             if ident.startswith(value) and envelope["record"]["kind"] == "proposal"]
    if len(found) != 1:
        raise AgentError("Unknown or ambiguous branch review ID.")
    return found[0]


def execute(workspace, request, max_exchange, identity_for):
    root = Path(request["root"]).resolve()
    with workspace.lock:
        if not any(root == Path(entry["path"]).resolve() for entry in workspace.worktrees()):
            raise AgentError("The requested worktree is outside this repository.")
        if request["group"] == "checks":
            ident = resolve_pr(workspace, request["id"])
        else:
            previous = workspace.root
            workspace.root = root
            try:
                return act(workspace, request, max_exchange, identity_for)
            finally:
                workspace.root = previous
    return workspace.run_check(ident, worktree=root)


def write_new(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent) as staged:
        staged.write(data)
        staged.flush()
        os.link(staged.name, path)


def act(workspace, request, max_exchange, identity_for):
    group, action = request["group"], request.get("action")
    if group == "pr":
        if action == "list":
            return {"prs": workspace.view()["proposals"]}
        if action == "submit":
            branch = request["source"] or workspace.git("branch", "--show-current").strip()
            result = workspace.create({"source": branch, "target": request["base"], "title": request["title"]})
            return {"id": result["selected"], "message": "Branch submitted for review."}
        ident = resolve_pr(workspace, request["id"])
        if action == "show":
            return next(pr for pr in workspace.view()["proposals"] if pr["id"] == ident)
        if action == "diff":
            return workspace.inspect(ident)
        if action == "comment":
            return workspace.comment({**request, "id": ident})
        if action == "review":
            return workspace.review({**request, "id": ident})
        if action == "merge":
            return workspace.integrate(ident, request.get("revision"))
    if group == "policy" and action == "show":
        policy = workspace.policy_for(request["base"])
        return {"branch": request["base"], "blob": policy[0] if policy else None,
                "policy": policy[1] if policy else None}
    if group == "sync":
        if request.get("branch"):
            return workspace.sync(request["branch"])
        if request.get("import_path"):
            with Path(request["import_path"]).open("rb") as archive:
                data = archive.read(max_exchange + 1)
            if len(data) > max_exchange:
                raise AgentError("The exchange exceeds 512 MB.")
            return workspace.import_exchange(data)
        if request.get("export_path"):
            path = Path(request["export_path"])
            plan = None
            if request.get("since"):
                inventory = json.loads(limited_text(Path(request["since"]), 1_048_576))
                plan = workspace.inventory_plan(inventory)
            write_new(path, workspace.export(plan))
            return {"path": str(path), "message": f"Exported exchange to {path}."}
        if request.get("inventory_path"):
            path = Path(request["inventory_path"])
            write_new(path, json.dumps(sorted(workspace.records), separators=(",", ":")).encode())
            return {"path": str(path), "message": f"Exported signed record IDs to {path}."}
        replica = workspace.enable_tracking()
        return {"replica": replica, "nearby": workspace.nearby(),
                "message": "Updated the local team remote. Checked-out branches have not moved."}
    if group == "publish":
        if request.get("branches"):
            return workspace.publish_snapshot(request)
        return workspace.publish()
    if group == "team":
        if action == "identity":
            info = {"id": workspace.me, "name": workspace.data_state["name"],
                    "project": workspace.data_state["project"], "key": workspace.public}
            if request["pairing"]:
                info["pairing_code"] = identity_for(workspace)
            return info
        if action == "trust":
            return workspace.team({"action": "add", "name": request["teammate"], "key": request["key"]})
        if action == "integrator":
            return workspace.team({"action": "integrator", "id": request["id"]})
        if action in ("quorum-init", "quorum-join"):
            return workspace.team(request)
        if action == "pipeline":
            return workspace.team({"action": "check", "command": request["command"]})
    raise AgentError("Unknown PeerTree command.")


def local_service_request(session, path, request=None, timeout=640):
    config = json.loads(session.read_bytes())
    if not isinstance(config, dict):
        raise AgentError("Invalid local PeerTree session. Restart the desktop or headless service.")
    port, token = config.get("port"), config.get("token")
    if (type(port) is not int or not 0 < port < 65536 or not isinstance(token, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)):
        raise AgentError("Invalid local PeerTree session. Restart the desktop or headless service.")
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    payload = json.dumps(request).encode() if request is not None else None
    msg = urllib.request.Request(f"http://127.0.0.1:{port}{path}", payload,
                                 {"X-Neighbor-Token": token, "Content-Type": "application/json"})
    try:
        with http.open(msg, timeout=timeout) as result:
            return port, json.load(result)
    except urllib.error.HTTPError as error:
        raise AgentError(json.load(error)["error"]) from error
    except OSError as error:
        raise AgentError("Could not reach the running local PeerTree service.") from error


def use_running_service(session, request):
    return local_service_request(session, "/api/agent", request)[1]


def reuse_desktop(path, enable_peer, project=None):
    root = worktree_root(Path(path).expanduser())
    session = git_common(root) / "neighbor-review" / SESSION_FILE
    if not session.is_file():
        raise AgentError("PeerTree is starting or finishing a command. Try opening the worktree again.")
    if project:
        _, state = local_service_request(session, "/api/state", timeout=5)
        if state["project"] != project:
            raise AgentError(f"The running workspace uses project {state['project']}.")
    if enable_peer:
        _, nearby = local_service_request(session, "/api/nearby", timeout=5)
        if not nearby["peer"]["enabled"]:
            raise AgentError("The running PeerTree service has nearby Wi-Fi off. Close it before enabling Wi-Fi.")
    port, _ = local_service_request(session, "/api/worktree", {"path": str(root)}, timeout=5)
    return port


def print_human(result):
    if "prs" in result:
        for pr in result["prs"]:
            print(f"{pr['id'][:12]}  {pr['target']}  {pr['title']}")
        if not result["prs"]:
            print("No submitted branches.")
    elif "patch" in result:
        print(result["patch"], end="")
    elif "output" in result:
        print(result["output"])
    elif "message" in result:
        identifier = result.get("id")
        print(f"{result['message']} {identifier}" if identifier else result["message"])
    else:
        print(json.dumps(result, indent=2, ensure_ascii=True))


def cli(arguments, workspace_type, already_open, max_exchange, identity_for):
    machine = "--json" in arguments
    try:
        flags, request = parse_cli(arguments)
        root = worktree_root(flags.repo.expanduser())
        request["root"] = str(root)
        try:
            workspace = workspace_type(root, flags.project, flags.name, None)
        except already_open:
            session = git_common(root) / "neighbor-review" / SESSION_FILE
            if not session.is_file():
                raise AgentError("PeerTree is starting or still finishing a different command. Try again.")
            result = use_running_service(session, request)
        else:
            result = execute(workspace, request, max_exchange, identity_for)
        if machine:
            print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
        else:
            print_human(result)
        return 2 if result.get("passed") is False else 0
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        if machine:
            print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True))
        else:
            print(error, file=sys.stderr)
        return 1
