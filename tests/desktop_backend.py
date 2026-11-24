"""Check the desktop's repository service contract without binding a socket."""

from contextlib import redirect_stdout
import base64
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agent
import app


class LocalServer:
    server_port = 49901

    def __init__(self, address, handler):
        assert address == ("127.0.0.1", 0)
        assert handler

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def serve_forever(self):
        pass


def run_main(repo):
    output = io.StringIO()
    with patch.object(sys, "argv", ["app.py", "--desktop-ready", "--repo", str(repo)]):
        with redirect_stdout(output), patch("app.webbrowser.open") as browser:
            app.main()
            browser.assert_not_called()
    return json.loads(output.getvalue())


def web_request(workspace, path, data=None, authorized=True):
    token = "test-session"
    handler_type = app.handle(workspace, token)
    request = handler_type.__new__(handler_type)
    request.server = LocalServer(("127.0.0.1", 0), handler_type)
    request.path = path
    request.command = "GET" if data is None else "POST"
    request.headers = {"Host": f"127.0.0.1:{LocalServer.server_port}"}
    if authorized:
        request.headers["X-Neighbor-Token"] = token
    if data is not None:
        payload = data if isinstance(data, bytes) else json.dumps(data).encode()
        request.headers["Content-Length"] = str(len(payload))
        request.rfile = io.BytesIO(payload)
    replies = []
    request.send = lambda status, body, *_: replies.append((status, body))
    request.request()
    status, body = replies[0]
    return status, json.loads(body) if path.startswith("/api/") and path != "/api/export" else body


def run_workspace_ui_test(folder):
    repo = folder / "source"
    worktree = folder / "review"
    replica = folder / "replica"

    def git(cwd, *args):
        return app.run(["git", "-c", "user.name=Alex", "-c", "user.email=test@example.invalid", *args], cwd=cwd)

    git(folder, "init", "-qb", "main", str(repo))
    git(folder, "init", "-qb", "main", str(replica))
    (repo / "README.md").write_text("PeerTree demo\n")
    (repo / "src").mkdir()
    (repo / "src" / "tree #1.txt").write_text("Committed text 🌳\n")
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle r="8" cx="8" cy="8"/></svg>'
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    (repo / "src" / "pear.SVG").write_bytes(svg)
    (repo / "src" / "photo.gif").write_bytes(gif)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "First commit")
    git(repo, "branch", "dev")
    git(repo, "tag", "v1")
    git(repo, "worktree", "add", "-qb", "feature", str(worktree))
    provider = app.Workspace(repo, "Shared demo", "Alex", None)
    receiver = app.Workspace(replica, "Shared demo", "Blair", None, bootstrap=True)
    try:
        page = web_request(provider, "/", authorized=False)[1]
        assert b'data-view="reviews"' in page and b'id="repo-mark"' in page
        assert b'id="embedded-file-icons"' in page
        assert b"marked v17.0.5" in web_request(provider, "/assets/marked/marked.umd.js", authorized=False)[1]
        assert web_request(provider, "/peertree-icon.png", authorized=False)[1].startswith(b"\x89PNG\r\n\x1a\n")
        status, raw_theme = web_request(provider, "/assets/seti/theme.json", authorized=False)
        assert status == 200
        theme = json.loads(raw_theme)
        assert theme["fileExtensions"]["tsx"] == "_react"
        assert theme["fileExtensions"]["py"] == "_python"
        status, font = web_request(provider, "/assets/seti/seti.woff", authorized=False)
        assert status == 200 and font.startswith(b"wOFF")
        assert web_request(provider, "/api/open-link", {"url": "javascript:alert(1)"})[0] == 400
        with patch.object(app, "run") as launcher:
            assert web_request(provider, "/api/open-link", {"url": "https://example.invalid/docs"})[0] == 200
            launcher.assert_called_once_with(["/usr/bin/open", "https://example.invalid/docs"])
        assert web_request(provider, "/api/code", authorized=False)[0] == 403
        cache_file = provider.data / "neighbor-peer-0123456789abcdef"
        active_helper = provider.data / "neighbor-peer-fedcba9876543210"
        cache_file.write_bytes(b"old helper")
        active_helper.write_bytes(b"active helper")
        pending = folder / "peer-session" / "outgoing"
        pending.mkdir(parents=True)
        staged = pending / "exchange.zip"
        staged.write_bytes(b"an exchange")
        provider.peer_session = SimpleNamespace(
            directory=pending.parent, initializing=False,
            helper=SimpleNamespace(args=[str(active_helper)], poll=lambda: None),
        )
        storage = web_request(provider, "/api/storage")[1]
        assert storage["repository"] > 0 and storage["cache"] == 23 and storage["pending"] == 11
        assert storage["can_prune"]
        assert web_request(provider, "/api/prune-cache", {})[0] == 200
        assert not cache_file.exists() and active_helper.is_file() and staged.is_file() and provider.key.is_file()
        assert not web_request(provider, "/api/storage")[1]["can_prune"]
        provider.peer_session = None

        assert web_request(provider, "/api/state")[1]["notifications"]["reviews"]
        preferences = {"action": "notification", "category": "reviews"}
        assert web_request(provider, "/api/team", {**preferences, "enabled": "false"})[0] == 400
        assert web_request(provider, "/api/team", {**preferences, "enabled": False})[0] == 200
        assert not web_request(provider, "/api/state")[1]["notifications"]["reviews"]
        assert json.loads(provider.file.read_text())["notifications"] == {"reviews": False}
        code = web_request(provider, "/api/code")[1]
        assert code["readme"]["text"] == "PeerTree demo\n"
        assert code["latest"]["title"] == "First commit"
        assert [item["name"] for item in code["entries"]] == ["src", "README.md"]
        assert web_request(provider, "/api/code?path=src%2Ftree%20%231.txt")[1]["text"] == "Committed text 🌳\n"
        for name, mime, contents in (("pear.SVG", "image/svg+xml", svg), ("photo.gif", "image/gif", gif)):
            assert web_request(provider, "/api/code?path=src%2F" + name, authorized=False)[0] == 403
            status, file = web_request(provider, "/api/code?path=src%2F" + name)
            assert status == 200 and "text" not in file
            assert file["image"]["mime"] == mime and base64.b64decode(file["image"]["data"]) == contents
        with patch.object(app, "MAX_IMAGE_PREVIEW", 1):
            assert web_request(provider, "/api/code?path=src%2Fphoto.gif")[1]["image"] == {"mime": "image/gif"}
        assert web_request(provider, "/api/code?path=..%2F.git%2Fconfig")[0] == 400
        assert "+PeerTree demo" in web_request(provider, f"/api/commit/{code['head']}")[1]["patch"]
        assert web_request(receiver, "/api/code")[1]["head"] is None
        assert web_request(receiver, "/api/checkout", {})[0] == 400
        assert web_request(provider, "/api/team", {"action": "integrator", "id": provider.me})[0] == 200
        assert web_request(provider, "/api/snapshot", {"branches": ["main", "dev"], "default": "main"})[0] == 200
        assert web_request(provider, "/api/state")[1]["branch_status"] == {"dev": "synced", "main": "synced"}

        version = web_request(provider, "/api/state")[1]["version"]
        assert web_request(provider, "/api/worktree", {"path": str(worktree)})[0] == 200
        assert web_request(provider, "/api/nearby")[1]["version"] > version
        (worktree / "README.md").write_text("New README text.\n")
        git(worktree, "add", "README.md")
        git(worktree, "commit", "-qm", "Update README")
        history = web_request(provider, "/api/history")[1]
        assert [row["title"] for row in history] == ["Update README", "First commit"]
        status, result = web_request(provider, "/api/propose",
                                     {"source": "feature", "target": "dev", "title": "Update README"})
        assert status == 200, result
        assert web_request(provider, "/api/state")[1]["version"] == web_request(provider, "/api/nearby")[1]["version"]
        review_id = result["selected"]
        draft_policy = worktree / ".peertree.json"
        draft_policy.write_text('{"version":1,"protected_branches":["dev"],'
                                '"review":{"required_approvals":1},'
                                '"checks":{"lint":["true"]}}\n')
        draft_view = web_request(provider, "/api/state")[1]
        assert draft_view["policy_in_worktree"] and draft_view["proposals"][0]["policy"] is None
        assert web_request(provider, "/api/check", {"id": review_id})[0] == 400
        draft_policy.unlink()
        diff = web_request(provider, f"/api/diff/{review_id}")[1]
        assert "+New README text." in diff["patch"]
        assert diff["paths"] == [{"old": "README.md", "new": "README.md"}]
        assert web_request(provider, "/api/comment", {"id": review_id, "body": "Review context"})[0] == 200
        line = {"id": review_id, "body": "Inline comment", "anchor": {"file": "README.md", "side": "new", "line": 1}}
        assert web_request(provider, "/api/comment", line)[0] == 200
        assert web_request(provider, "/api/comment", {**line, "anchor": {**line["anchor"], "line": 2}})[0] == 400
        assert {row["kind"] for row in web_request(provider, "/api/activity")[1]} == {"proposal", "snapshot", "comment"}

        assert web_request(receiver, "/api/team", {"action": "add", "name": "Alex", "key": provider.public})[0] == 200
        assert web_request(receiver, "/api/team", {"action": "integrator", "id": provider.me})[0] == 200
        assert web_request(receiver, "/api/import", web_request(provider, "/api/export")[1])[0] == 200
        assert web_request(receiver, "/api/state")[1]["snapshot"]["branches"] == ["dev", "main"]
        assert web_request(receiver, "/api/checkout", {})[0] == 200
        assert web_request(receiver, "/api/refresh", {})[0] == 200
        assert git(replica, "rev-parse", "team/dev") == git(replica, "rev-parse", "dev")
        assert git(replica, "tag", "--list").strip() == b"v1"
        comments = web_request(receiver, "/api/state")[1]["proposals"][0]["comments"]
        assert {message["body"]: message.get("anchor") for message in comments} == {
            "Review context": None, "Inline comment": line["anchor"],
        }

        git(repo, "commit", "--allow-empty", "-qm", "Local main")
        git(repo, "branch", "-f", "dev", "main")
        assert web_request(provider, "/api/state")[1]["branch_status"] == {"dev": "ahead", "main": "ahead"}
        git(repo, "reset", "--hard", "HEAD~1")
        git(repo, "commit", "--allow-empty", "-qm", "Replacement main")
        assert provider.branch_status(provider.branches(), {"main": provider.commit("dev")})["main"] == "diverged"
    finally:
        provider.instance.close()
        receiver.instance.close()


def run_automatic_pipeline_test(folder):
    repo = folder / "source"
    peer = folder / "peer"

    def git(cwd, *args):
        return app.run(["git", "-c", "user.name=Pipeline", "-c", "user.email=test@example.invalid", *args], cwd=cwd)

    def run_for(workspace, ident):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            with workspace.lock:
                run = workspace.data_state["runs"].get(ident)
                if run is not None and workspace.running_check != ident:
                    return run
            time.sleep(0.025)
        raise AssertionError("The automatic pipeline did not finish.")

    git(folder, "init", "-qb", "main", str(repo))
    (repo / ".peertree.json").write_text(json.dumps({
        "version": 1, "protected_branches": ["main"],
        "review": {"required_approvals": 2},
        "checks": {"test": ["python3", "check.py"]},
    }))
    (repo / "check.py").write_text(
        'from pathlib import Path\nrevision = Path("revision").read_text()\nprint(revision)\n'
        'raise SystemExit(revision == "second")\n')
    (repo / "revision").write_text("base")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "Policy and test")
    git(folder, "clone", "-q", str(repo), str(peer))
    workspace = app.Workspace(repo, "Pipeline demo", "Author", None)
    receiver = app.Workspace(peer, "Pipeline demo", "Reviewer", None)
    try:
        receiver.team({"action": "add", "name": "Author", "key": workspace.public})
        workspace.start_checks()
        receiver.start_checks()
        git(repo, "switch", "-qc", "feature")
        (repo / "revision").write_text("first")
        git(repo, "commit", "-qam", "First revision")
        _, first = web_request(workspace, "/api/propose", {"source": "feature", "target": "main", "title": "Feature"})
        first_id = first["selected"]
        completed = run_for(workspace, first_id)
        assert completed["checks"] == {"test": True} and "first" in completed["output"]
        assert workspace.run_check(first_id, automatic=True) is None

        (repo / "revision").write_text("second")
        git(repo, "commit", "-qam", "Second revision")
        _, second = web_request(workspace, "/api/propose", {"source": "feature", "target": "main", "title": "Feature"})
        second_id = second["selected"]
        completed = run_for(workspace, second_id)
        assert completed["checks"] == {"test": False} and "second" in completed["output"]
        assert workspace.run_check(second_id, automatic=True) is None

        assert web_request(receiver, "/api/import", web_request(workspace, "/api/export")[1])[0] == 200
        completed = run_for(receiver, second_id)
        assert completed["checks"] == {"test": False} and "second" in completed["output"]
        assert first_id not in receiver.data_state["runs"]
        assert receiver.run_check(second_id, automatic=True) is None
        assert receiver.run_check(second_id)["checks"] == {"test": False}
    finally:
        workspace.stop_checks()
        receiver.stop_checks()
        workspace.instance.close()
        receiver.instance.close()


def run_test(repo):
    with patch.object(app, "ThreadingHTTPServer", LocalServer):
        assert run_main(repo) == {"port": LocalServer.server_port, "owned": True}
    assert not (repo / ".git" / "neighbor-review" / agent.SESSION_FILE).exists()

    workspace = app.Workspace(repo, None, None, None)
    try:
        session = workspace.data / agent.SESSION_FILE
        session.write_text(json.dumps({"port": LocalServer.server_port, "token": "x" * 43}))
        session.chmod(stat.S_IRUSR | stat.S_IWUSR)
        calls = []

        def request(path, endpoint, data=None, timeout=None):
            assert path == session
            calls.append((endpoint, data, timeout))
            return LocalServer.server_port, {}

        with patch.object(agent, "local_service_request", request):
            assert run_main(repo) == {"port": LocalServer.server_port, "owned": False}
        assert calls == [("/api/worktree", {"path": str(repo)}, 5)]
        assert session.is_file()
    finally:
        workspace.instance.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="peertree-desktop-test-") as temporary:
        repository = Path(temporary).resolve()
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        run_test(repository)
    with tempfile.TemporaryDirectory(prefix="peertree-workspace-ui-test-") as temporary:
        run_workspace_ui_test(Path(temporary).resolve())
    with tempfile.TemporaryDirectory(prefix="peertree-automatic-pipeline-test-") as temporary:
        run_automatic_pipeline_test(Path(temporary).resolve())
    print("Passed desktop startup, repository browser, settings, signed reviews, automatic pipelines, and clone checks.")
