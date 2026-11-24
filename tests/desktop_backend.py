"""Check the desktop's repository service contract without binding a socket."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
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
    print("Passed owned desktop startup, session cleanup, and reuse of the headless service.")
