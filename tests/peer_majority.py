"""Exercise signed peer-majority branch updates with three disposable replicas."""

from pathlib import Path
import sys
import tempfile

from headless import cli, git

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from quorum import Ballots


def exchange(sender, recipient, folder):
    with tempfile.TemporaryDirectory(dir=folder) as transfer:
        archive = Path(transfer) / "exchange.zip"
        cli(sender, "sync", "--export", archive)
        cli(recipient, "sync", "--import", archive)


def shared_tip(repo):
    return git(repo, "rev-parse", "team/main")


def test_takeover_preserves_accepted_value():
    root = "root"
    left = {"proposal": "left", "approval": "review-left", "checks": []}
    right = {"proposal": "right", "approval": "review-right", "checks": []}
    slot = ("main", "base")
    records = {
        root: {"who": "a", "members": ["a", "b", "c"], "branches": {"main": "base"}},
        "left": {"who": "a", "head": "left-tip"},
        "right": {"who": "b", "head": "right-tip"},
    }

    def add(ident, kind, who, **fields):
        records[ident] = {"kind": "quorum_" + kind, "root": root, "who": who, **fields}

    add("round1", "prepare", "a", branch="main", base="base", round=1)
    add("promise-a", "promise", "a", prepare="round1", accepted=None)
    add("promise-b", "promise", "b", prepare="round1", accepted=None)
    add("choice1", "choice", "a", prepare="round1", promises=["promise-a", "promise-b"], value=left)
    add("accepted-a", "accept", "a", choice="choice1")
    assert Ballots(root, records, lambda *_: True).tips() == {"main": "base"}

    add("round2", "prepare", "c", branch="main", base="base", round=2)
    add("promise-a2", "promise", "a", prepare="round2", accepted="accepted-a")
    add("promise-c", "promise", "c", prepare="round2", accepted=None)
    protocol = Ballots(root, records, lambda *_: True)
    kind, fields = protocol.next_message("c", slot, right)
    assert kind == "quorum_choice" and fields["value"] == left
    add("invalid-choice", "choice", "c", prepare="round2", promises=fields["promises"], value=right)
    add("invalid-a", "accept", "a", choice="invalid-choice")
    add("invalid-c", "accept", "c", choice="invalid-choice")
    assert Ballots(root, records, lambda *_: True).tips() == {"main": "base"}
    add("choice2", "choice", "c", **fields)
    add("accepted-a2", "accept", "a", choice="choice2")
    add("accepted-c", "accept", "c", choice="choice2")
    assert Ballots(root, records, lambda *_: True).tips() == {"main": "left-tip"}


def run_test(folder):
    a, b, c = (folder / name for name in ("Alex", "Blair", "Casey"))
    a.mkdir()
    c.mkdir()
    git(a, "init", "-qb", "main")
    (a / ".peertree.json").write_text(
        '{"version":1,"protected_branches":["main"],'
        '"checks":{"test":["/bin/sh","-c","test -f .peertree.json"]}}\n'
    )
    git(a, "add", ".")
    git(a, "commit", "-qm", "Starting policy")
    initial = git(a, "rev-parse", "HEAD")
    git(a, "clone", "-q", str(a), str(b))
    git(c, "init", "-qb", "main")
    clone = app.Workspace(c, "Majority", "Casey", None, bootstrap=True)
    clone.instance.close()

    peers = (a, b, c)
    identities = {repo: cli(repo, "team", "identity", "--project", "Majority") for repo in peers}
    for repo in peers:
        for other in peers:
            if other != repo:
                cli(repo, "team", "trust", other.name, "--key", identities[other]["key"])

    root = cli(a, "team", "quorum-init")["id"]
    exchange(a, b, folder)
    for repo in (a, b):
        cli(repo, "team", "quorum-join", root)
        assert shared_tip(repo) == initial
        cli(repo, "team", "integrator", identities[a]["id"], error="uses peer majority")

    git(a, "switch", "-qc", "first", "team/main")
    (a / "first").write_text("First change\n")
    git(a, "add", "first")
    git(a, "commit", "-qm", "First change")
    first = git(a, "rev-parse", "HEAD")
    review = cli(a, "pr", "submit", "--base", "main", "--title", "First")["id"]
    exchange(a, b, folder)
    cli(b, "pr", "review", review, "--revision", first, "--approve")
    assert cli(b, "pr", "show", review)["required"] == 1
    exchange(b, a, folder)
    assert shared_tip(a) == shared_tip(b) == initial
    cli(b, "checks", "run", review)
    for sender, recipient in ((b, a), (a, b), (b, a), (a, b)):
        exchange(sender, recipient, folder)
    assert shared_tip(a) == shared_tip(b) == first
    assert git(a, "rev-parse", "refs/heads/main") == initial
    assert cli(b, "pr", "show", review)["merged"]

    exchange(b, c, folder)
    cli(c, "team", "quorum-join", root)
    clone = app.Workspace(c, None, None, None)
    try:
        clone.bootstrap_checkout()
    finally:
        clone.instance.close()
    assert git(c, "rev-parse", "HEAD") == shared_tip(c) == first

    competing = []
    for repo, topic in ((a, "left"), (b, "right")):
        git(repo, "switch", "-qc", topic, "team/main")
        (repo / topic).write_text(topic + "\n")
        git(repo, "add", topic)
        git(repo, "commit", "-qm", topic)
        head = git(repo, "rev-parse", "HEAD")
        submission = cli(repo, "pr", "submit", "--base", "main", "--title", topic)["id"]
        competing.append((head, submission))
    exchange(a, b, folder)
    exchange(b, a, folder)
    for repo, (head, submission) in zip((a, b), reversed(competing)):
        cli(repo, "pr", "review", submission, "--revision", head, "--approve")
        cli(repo, "checks", "run", submission)
        assert shared_tip(repo) == first
    for _ in range(4):
        exchange(a, b, folder)
        exchange(b, a, folder)
    decided = shared_tip(a)
    assert decided == shared_tip(b) and decided in {head for head, _ in competing}
    losing = next(submission for head, submission in competing if head != decided)
    assert cli(a, "pr", "show", losing)["quorum_stale"]
    cli(a, "pr", "merge", losing, error="Rebase")
    exchange(a, c, folder)
    assert shared_tip(c) == decided


if __name__ == "__main__":
    test_takeover_preserves_accepted_value()
    with tempfile.TemporaryDirectory(prefix="peertree-peer-majority-test-") as temporary:
        run_test(Path(temporary).resolve())
    print("Passed three-peer merge, offline catch-up and checkout, and competing branch decisions.")
