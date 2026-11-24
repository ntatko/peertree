# PeerTree

PeerTree is a local browser interface for three people working in separate clones during a GitLab outage. It packages Git history, branch reviews, signed decisions, and published branch tips into ZIP exchanges. Share the app and the exchanges through approved channels.

## Install with Homebrew

After the GitHub release is published, install from the project repository:

```sh
brew tap ntatko/peertree https://github.com/ntatko/peertree.git
brew install --cask ntatko/peertree/peertree
```

The cask installs **PeerTree.app** and links the `peertree` command. It supports Apple Silicon and Intel on macOS 15 or later. PeerTree uses the Mac's Python 3.9+, Git, and OpenSSH. The Command Line Tools provide these dependencies.

To run directly from source, build the core with `cargo build --locked --offline` and use the checked-in `./peertree` launcher. Nearby Wi-Fi builds its native helper on demand using the Apple Swift toolchain.

The headless smoke test transfers signed exchanges through three disposable clones. Run it with `python3 -B tests/headless.py` after building the core.

## Native desktop preview

The Tauri launcher opens an existing worktree or starts a clone from a teammate. The review opens in a PeerTree desktop window. Closing it returns to the repository picker. The desktop process owns services it starts and attaches to running headless services for the same worktree.

```sh
cargo build --locked --offline
cargo run --manifest-path desktop/Cargo.toml
```

The first desktop build resolves Tauri crates from crates.io. To open a specific working copy, add `-- --repo /path/to/worktree` to the second command. The agent CLI can run against the same worktree while its review window is open.

## Build a release

Install the Rust standard libraries for Apple Silicon and Intel on the build Mac before packaging. With rustup, run `rustup target add aarch64-apple-darwin x86_64-apple-darwin`. The Rust core builds offline with the checked-in lockfile.

Pass `--desktop` to bundle the Tauri preview with the usual Homebrew CLI. Desktop releases build from the committed `desktop/Cargo.lock`, so update it deliberately with `cargo update --manifest-path desktop/Cargo.toml`.

```sh
python3 package-brew.py --owner ntatko
```

The build writes a universal ZIP to `dist/` and updates the cask's release URL and SHA-256 checksum. A default build uses an ad-hoc signature for local testing. For distribution on Macs that require Gatekeeper verification, build with a Developer ID Application certificate and a configured notarytool profile:

```sh
python3 package-brew.py --owner ntatko \
  --sign-identity "Developer ID Application: YOUR NAME (TEAMID)" \
  --notary-profile YOUR_PROFILE
```

Commit and push the regenerated cask before attaching the matching ZIP to the release tag. The cask expects the release asset URL to be reachable by Homebrew.

## Open a repository

From any directory inside a Git worktree, run:

```sh
peertree
```

The command opens your browser, selects the current worktree, and lists the other worktrees for that clone. Keep the terminal open. You can also open **PeerTree** from Applications and pick a repository in the folder chooser. Use the **Worktree** menu to switch. If the app is already running for this clone, use the open window to switch worktrees.

On first launch the project defaults to the Git origin's repository name and your display name defaults to Git's `user.name`. When teammates' origins use different names, launch with the same `--project "your-project"` on all three Macs from the start. Use `--name "Your Name"` on first launch to override your display name.

In **Settings**, choose the same integrator on every laptop and configure your fallback local pipeline command, such as `./scripts/check.sh` or `npm test`. For nearby Wi-Fi, add teammates with **Add a teammate** as described below. For manual exchanges alone, compare and trust public keys in person. The integrator needs a configured Git name and email to create merge commits. The repo's Git metadata directory stores identities, reviews, and settings across sessions and worktrees.

## Use nearby Wi-Fi

On each Mac, from the project worktree, run:

```sh
peertree --peer
```

Use this mode where direct device-to-device transfers are approved. Keep Wi-Fi enabled. PeerTree uses Apple peer-to-peer Wi-Fi through Network.framework and discovers peers with Bonjour. The Macs can discover and connect directly without an office access point. macOS local-network permissions and device management settings still apply.

To add a teammate, open PeerTree on the new Mac and choose **Join a teammate's project**. On a Mac that already has the project, choose **Add a teammate** and select the new Mac from the list. Both screens show the same six-digit code. Type it on the new Mac, and once it shows **Code accepted**, confirm on the host. The code covers both Macs' certificates and a random value from each, so a device in between can't make the two screens agree. Confirming swaps signing keys and certificate fingerprints. The new Mac also learns the project, its integrator, and the host's other teammates, and the host signs an introduction so those teammates trust the new Mac when they next sync. Both Macs must present their pinned certificate before a connection carries an exchange.

For ZIP exchanges without nearby Wi-Fi, use **Pair without nearby Wi-Fi** in the same window to compare and trust public keys in person.

With both apps open and in range, submitted branches, comments, check results, decisions, and published tips sync automatically. Paired teammates reconnect on later launches. They compare the signed record IDs they hold and exchange the missing records and Git objects. A teammate can relay a record signed by its original author to another teammate who trusts that signer. Nearby sync uses the new protocol in 0.5.0, and pairing uses the join flow in 0.5.1, so upgrade all three Macs together. A Mac that is far behind catches up in batches. Use **Sync now** to request a nearby exchange and refresh the `team/` tracking refs. In **Branches**, choose **Fast-forward** when you're ready to update a local branch. Use `peertree --no-peer` to turn nearby Wi-Fi off.

## Agent CLI and local Git remote

CLI and browser actions share the same signing keys, records, and merge gates. When a repository's app is running, the CLI uses that local service. With the app closed, commands operate on the local repository. Start a background sync session in a terminal with `peertree --peer --no-open`.

```sh
peertree --agent-help
peertree pr submit --base dev --title "Describe the change" --json
peertree pr list --json
peertree pr show "$PR_ID" --json
peertree pr diff "$PR_ID"
peertree checks run "$PR_ID" --json
peertree pr comment "$PR_ID" --body-file review.md --json
peertree pr comment "$PR_ID" --file src/main.rs --line 42 --body "Can we simplify this?" --json
peertree pr review "$PR_ID" --approve --revision "$COMMIT_SHA" --json
peertree pr merge "$PR_ID" --revision "$COMMIT_SHA" --json
```

Use `--json` for a machine-readable result. A completed check run with failing checks exits with status 2. The `team` commands configure identities, pairing, and the integrator without a window.

Run `peertree sync` to create a local Git remote named `team`. It exposes the integrator's published branches, such as `team/dev`, and advances the tracking refs as signed tips arrive. `git fetch team` reads this local replica. Run `peertree sync dev` to fast-forward the local branch when ready.

For a manual transfer, `peertree sync --export exchange.zip` creates a full exchange and `peertree sync --import exchange.zip` receives one. To send a smaller exchange, the receiver first writes their record inventory with `peertree sync --inventory have.json`. The sender runs `peertree sync --export updates.zip --since have.json`.

## Peer majority for three Macs

On all three Macs, update PeerTree and trust both teammates' signing keys. On the Mac with the existing repository, open **Settings → Team settings** and choose **Create peer starting snapshot**. This captures the current shared tips when migrating an existing team. Sync or exchange the snapshot, compare its full ID on all three Macs, and choose **Join peer majority** everywhere. An empty clone can join the same snapshot and check out the latest agreed tip.

The snapshot pins the three signing identities and the initial protected branches. Any two peers can agree on the next tip. One teammate's approval and passing committed checks make the exact submitted commit eligible. PeerTree exchanges its signed branch decisions over nearby Wi-Fi or ZIP, so a teammate who was offline can catch up through either peer.

Submit a commit based on the current shared tip. If two reviews compete, PeerTree settles one branch update first. Rebase the other branch onto that tip and submit its new revision. The agreed tip advances under team/main or team/dev. Use **Fast-forward** to update a checked-out branch when you are ready. **Retry peer merge** lets another peer resume a stalled vote.

Teams that keep their existing integrator settings continue to use the integrator workflow below.

## Repository merge policy

Add `.peertree.json` to a protected branch, then publish the initial snapshot as the integrator. Use the same scripts in your GitLab CI jobs and in PeerTree. The check values are executable arguments, with one array per named check.

```json
{
  "version": 1,
  "protected_branches": ["main", "dev"],
  "checks": {
    "lint": ["./ci/lint.sh"],
    "test": ["./ci/test.sh"]
  }
}
```

```sh
peertree publish --branch main --branch dev --default main
peertree policy show --base dev --json
```

The last published target commit supplies the active policy. A branch can change this file through review. Its old policy continues to govern the merge, and signed checks and approvals count against the reviewed commit and policy. While the PeerTree service is running, committed checks run automatically for each revision you submit. Checks execute the submitted commit's code, so a teammate's revision waits until you review it and click **Run local pipeline**. Checks run on this Mac from a temporary checkout of the exact commit, and only results signed by someone other than the author count toward the policy. The Pipeline tab shows queued and running states and lets you rerun a check manually. Merges need two teammate approvals in the integrator workflow and one in peer majority, with no outstanding change request, and authors can't approve their own branches. A repository without a committed policy uses the manually run fallback pipeline command.

PeerTree's own policy protects `main` and requires one teammate approval plus the lint and test checks. Both run offline on a Mac with the Apple command-line tools, Rust with rustfmt and Clippy, and Node.js.

```sh
python3 ci/checks.py lint
python3 ci/checks.py test
```

## Clone from a teammate

Use PeerTree 0.5.1 or later on every Mac. The integrator opens an existing working copy with nearby Wi-Fi enabled and chooses **Branches → Publish repository snapshot**. Select the branches you were protecting and the default checkout branch. PeerTree can offer local branches and cached `origin` branch tips. The signed snapshot includes those branches' Git history and the local tags reachable from them. It stays current as the integrator publishes branch tips.

On the new Mac, open PeerTree from Applications and choose **Join a teammate's project**. You don't need a folder or the project name yet. On a Mac that has the project, choose **Add a teammate**, select the new Mac, and check the six-digit code together as described in Nearby Wi-Fi. The repository starts arriving right away. Choose **Choose folder…** to pick where it lives, then **Check out repository** once the snapshot is in. PeerTree creates the protected branches and tags locally and opens the default branch.

From Terminal, `peertree clone ./staging --join` does the same, and `peertree clone ./my-project --project "my-project"` still clones by project name with manually trusted keys. If direct Wi-Fi is unavailable, the integrator can export the same signed snapshot as a ZIP for the new Mac to import.

When cloning by project name, use `--object-format sha256` for a SHA-256 project; joining picks the host's format automatically. PeerTree carries Git refs and tracked files. GitLab access rules, merge request state, CI variables, and runner configuration are server-side. LFS objects and submodule repositories need their own approved transfer.

## Share a ZIP manually

If AirDrop is approved on your managed Macs, click **Settings → Share in Finder**. PeerTree creates a temporary exchange ZIP and selects it in Finder. Choose **Share → AirDrop** and pick the recipient. AirDrop uses Bluetooth and a direct Wi-Fi connection between the Macs, independent of the office network. Keep PeerTree open until the transfer completes.

The recipient accepts the AirDrop request, then picks the received ZIP with **Settings → Import exchange** or drags it onto that button. A signed exchange still uses the teammate keys you configured earlier. If AirDrop is unavailable, use **Export exchange** to save a ZIP for an approved transfer channel.

## Optional alerts on networks that allow peer traffic

Run `peertree --lan` from the repo to enable and remember LAN alerts for this clone. Use `peertree --no-lan` to turn them off. Start the app on each Mac on an approved network that allows IPv4 broadcast between devices, and allow local-network access if macOS prompts. VPNs or guest Wi-Fi may isolate clients.

Submitting a branch broadcasts a signed alert containing a project fingerprint, signing key ID, review ID, and timestamp. Branch names, titles, diffs, and files stay out of alerts. The receiving app verifies the signature against trusted teammate keys. Open review alerts are periodically reannounced, so teammates can see them on their next overlapping session. Enable desktop alerts in the browser if you also want system notifications while the app is open. Source and review decisions travel in ZIP exchanges.

## Review and sync

1. Commit your work on a topic branch and choose **Submit branch for review**. Select the branch and its target. If nearby Wi-Fi is off, share an exchange with both teammates.
2. Teammates import the ZIP and inspect **Changes** and **Pipeline**, then choose **Approve revision** or **Request changes**. Inspect the code before running the pipeline, since checks run with the account's permissions.
3. Review decisions sync to the integrator over nearby Wi-Fi or via ZIP. The integrator can merge after two approvals and no outstanding change request. A new commit submitted from the same topic branch starts a fresh review. **Publish tips** lets the integrator share the current `dev` and `main` tips.
4. When everyone receives the merged state, choose **Fast-forward** for the relevant branch in **Branches**. Sync requires a clean checkout and moves existing branches only by fast-forward. It may switch branches in the selected worktree. If a target branch is already checked out in another worktree, select that worktree first. Resolve divergence or merge conflicts in Git before retrying.

An exchange forwards the signed records it already holds. Bundles can contain the full histories reachable from shared commits, including earlier versions of deleted files. Exchanges are limited to 512 MB. Git LFS objects and submodule repositories use their own storage and transfer workflows. Hosted GitLab CI runners and services need local equivalents.
