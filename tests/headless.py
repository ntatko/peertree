"""Exercise the Rust CLI, shared policy, and relay using three disposable Git clones."""

import json
from pathlib import Path
import subprocess
import tempfile
from zipfile import ZipFile


LAUNCHER = Path(__file__).resolve().parents[1] / "peertree"
POLICY = {
    "version": 1,
    "protected_branches": ["main", "dev"],
    "review": {"required_approvals": 2, "allow_self_approval": False},
    "checks": {"lint": ["/bin/sh", "./lint.sh"], "test": ["/bin/sh", "./test.sh"]},
}


def git(path, *args):
    return subprocess.check_output(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        cwd=path, text=True, stderr=subprocess.STDOUT,
    ).strip()


def cli(repo, *args, error=None):
    command = [str(LAUNCHER), "--repo", str(repo), "--json", *map(str, args)]
    result = subprocess.run(command, cwd=repo, text=True, capture_output=True)
    assert result.returncode == (1 if error else 0), (command, result.stdout, result.stderr)
    response = json.loads(result.stdout)
    if error:
        assert not response["ok"] and error in response["error"], response
        return
    assert response["ok"], response
    return response["result"]


def relay(sender, recipient, folder, exchange, kinds):
    inventory = folder / f"{exchange}-have.json"
    archive = folder / f"{exchange}.zip"
    cli(recipient, "sync", "--inventory", inventory)
    cli(sender, "sync", "--export", archive, "--since", inventory)
    with ZipFile(archive) as contents:
        records = json.loads(contents.read("records.json"))
        assert {item["record"]["kind"] for item in records} == kinds, records
    assert cli(recipient, "sync", "--import", archive)["imported"] > 0


def run_test(root):
    seed = root / "seed"
    seed.mkdir()
    git(seed, "init", "-q", "-b", "main")
    (seed / ".peertree.json").write_text(json.dumps(POLICY))
    (seed / "lint.sh").write_text("test -f code\n")
    (seed / "test.sh").write_text("grep -q new code\n")
    (seed / "code").write_text("old\n")
    git(seed, "add", ".")
    git(seed, "commit", "-qm", "Repository policy")
    git(seed, "branch", "dev")
    team, identities = {}, {}
    for name in ("Alex", "Blair", "Casey"):
        clone = root / name
        git(seed, "clone", "-q", str(seed), str(clone))
        git(clone, "branch", "dev", "origin/dev")
        git(clone, "config", "user.name", name)
        git(clone, "config", "user.email", "test@example.invalid")
        team[name] = clone
        identities[name] = cli(clone, "team", "identity", "--project", "Test", "--pairing")
    alex, blair, casey = team.values()
    for name, repo in team.items():
        for other, info in identities.items():
            if other != name:
                cli(repo, "team", "trust", other, "--key", info["pairing_code"])
        cli(repo, "team", "integrator", identities["Casey"]["id"])

    cli(casey, "publish", "--branch", "main", "--branch", "dev", "--default", "main")
    initial = root / "initial.zip"
    cli(casey, "sync", "--export", initial)
    for repo in (alex, blair):
        cli(repo, "sync", "--import", initial)
    assert cli(blair, "sync")["replica"]["remote"] == "team"
    assert git(blair, "rev-parse", "team/dev") == git(blair, "rev-parse", "refs/heads/dev")

    git(alex, "switch", "-qc", "feature", "dev")
    (alex / "code").write_text("new\n")
    future = {**POLICY, "review": {"required_approvals": 1}, "checks": {}}
    (alex / ".peertree.json").write_text(json.dumps(future))
    git(alex, "add", ".")
    git(alex, "commit", "-qm", "Change code and propose changing policy")
    commit = git(alex, "rev-parse", "HEAD")
    pr = cli(alex, "pr", "submit", "--base", "dev", "--title", "Agent change")["id"]
    assert cli(alex, "policy", "show", "--base", "dev")["policy"] == POLICY
    cli(alex, "pr", "review", pr, "--revision", commit, "--approve", error="teammate")

    relay(alex, blair, root, "submission", {"proposal"})
    assert "+new" in cli(blair, "pr", "diff", pr)["patch"]
    cli(blair, "pr", "review", pr, "--approve", "--revision", "0" * 40, error="does not match")
    comment = root / "comment.md"
    comment.write_text("Relay this review 🌳\n")
    cli(blair, "pr", "comment", pr, "--body-file", comment)
    cli(blair, "pr", "comment", pr, "--file", "code", "--line", 1, "--body", "Explain this change")
    cli(blair, "pr", "comment", pr, "--file", "code", "--line", 1, "--side", "old", "--body", "Old behavior")
    cli(blair, "pr", "comment", pr, "--file", "code", "--line", 20, "--body", "Outside the diff", error="Choose a line")
    cli(blair, "pr", "review", pr, "--approve", "--revision", commit)
    relay(blair, casey, root, "review", {"proposal", "comment", "review"})
    view = cli(casey, "pr", "show", pr)
    comments = {row["body"]: row.get("anchor") for row in view["comments"]}
    assert comments == {
        "Relay this review 🌳": None,
        "Explain this change": {"file": "code", "side": "new", "line": 1},
        "Old behavior": {"file": "code", "side": "old", "line": 1},
    }
    assert view["approvals"] == 1 and view["required"] == 2
    cli(casey, "pr", "merge", pr, error="1 of 2")
    cli(casey, "pr", "review", pr, "--approve", "--revision", commit)
    cli(casey, "pr", "merge", pr, error="Required checks have not passed")

    # The author's own check results never satisfy the policy.
    assert cli(alex, "checks", "run", pr)["checks"] == {"lint": True, "test": True}
    relay(alex, casey, root, "author-checks", {"check"})
    cli(casey, "pr", "merge", pr, error="Required checks have not passed")

    assert cli(blair, "checks", "run", pr)["checks"] == {"lint": True, "test": True}
    relay(blair, casey, root, "checks", {"check"})
    checked = cli(casey, "pr", "show", pr)
    assert not checked["missing"]
    assert {(row["who"], row["check"], row["passed"]) for row in checked["check_runs"]} == {
        (identities["Blair"]["id"], "lint", True),
        (identities["Blair"]["id"], "test", True),
    }
    git(casey, "switch", "-q", "dev")
    git(casey, "commit", "--allow-empty", "-qm", "Local bypass in test fixture")
    cli(casey, "publish", error="approved branch review")
    git(casey, "reset", "--hard", "HEAD~1")
    cli(casey, "pr", "merge", pr, "--revision", commit)
    assert cli(casey, "pr", "show", pr)["merged"]
    assert cli(casey, "policy", "show", "--base", "dev")["policy"] == future

    relay(casey, blair, root, "published", {"snapshot", "review", "check"})
    published = git(casey, "rev-parse", "refs/heads/dev")
    assert git(blair, "rev-parse", "team/dev") == published
    assert git(blair, "rev-parse", "refs/heads/dev") != published
    git(blair, "fetch", "team")
    cli(blair, "sync", "dev")
    assert git(blair, "rev-parse", "refs/heads/dev") == published


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="peertree-headless-test-") as temporary:
        run_test(Path(temporary).resolve())
    print("Passed signed relay, policy gating, and local Git remote checks across three clones.")
