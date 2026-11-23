# PeerTree

PeerTree is a local browser interface for three people working in separate clones during a GitLab outage. It packages Git history, branch reviews, signed decisions, and published branch tips into ZIP exchanges. Share the app and the exchanges through approved channels.

## Install with Homebrew

After the GitHub release is published, install from the project repository:

```sh
brew tap ntatko/peertree https://github.com/ntatko/peertree.git
brew install --cask ntatko/peertree/peertree
```

The cask installs **PeerTree.app** and links the `peertree` command. It supports Apple Silicon and Intel on macOS 15 or later. PeerTree uses the Mac's Python 3.9+, Git, and OpenSSH. The Command Line Tools provide these dependencies.

To run directly from source, use the full path to the checked-in `peertree` launcher. Nearby Wi-Fi builds its native helper on demand using the Apple Swift toolchain.

## Build a release

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

In **Team settings**, choose the same integrator on every laptop and configure your local check command, such as `./scripts/check.sh` or `npm test`. For nearby Wi-Fi, add both teammates using the pairing codes below. For manual exchanges alone, use their public keys. Verify the codes or keys in person. The integrator needs a configured Git name and email to create merge commits. The repo's Git metadata directory stores identities, reviews, and settings across sessions and worktrees.

## Use nearby Wi-Fi

On each Mac, from the project worktree, run:

```sh
peertree --peer
```

Use this mode where direct device-to-device transfers are approved. Keep Wi-Fi enabled. PeerTree uses Apple peer-to-peer Wi-Fi through Network.framework and discovers peers with Bonjour. The Macs can discover and connect directly without an office access point. macOS local-network permissions and device management settings still apply.

In **Team settings**, each person copies their **nearby pairing code**. Exchange and verify the codes in person, then paste each teammate's code into **Trust a teammate**. Add both teammates on all three Macs. If you previously trusted their public keys, add their pairing codes once to enable encrypted connections. The pairing code contains the review signing key and the certificate fingerprint. Both Macs must present their pinned certificate before a connection carries an exchange.

With both apps open and in range, submitted branches, decisions, and published tips sync automatically. Paired teammates reconnect on later launches. The app verifies signatures before applying records and shows new activity in the browser. Use **Sync dev** or **Sync main** when you're ready to move those local branches. Use `peertree --no-peer` to turn nearby Wi-Fi off.

## Share a ZIP manually

If AirDrop is approved on your managed Macs, click **Share in Finder**. PeerTree creates a temporary exchange ZIP and selects it in Finder. Choose **Share → AirDrop** and pick the recipient. AirDrop uses Bluetooth and a direct Wi-Fi connection between the Macs, independent of the office network. Keep PeerTree open until the transfer completes.

The recipient accepts the AirDrop request, then picks the received ZIP with **Import exchange** or drags it onto that button. A signed exchange still uses the teammate keys you configured earlier. If AirDrop is unavailable, use **Export exchange** to save a ZIP for an approved transfer channel.

## Optional alerts on networks that allow peer traffic

Run `peertree --lan` from the repo to enable and remember LAN alerts for this clone. Use `peertree --no-lan` to turn them off. Start the app on each Mac on an approved network that allows IPv4 broadcast between devices, and allow local-network access if macOS prompts. VPNs or guest Wi-Fi may isolate clients.

Submitting a branch broadcasts a signed alert containing a project fingerprint, signing key ID, review ID, and timestamp. Branch names, titles, diffs, and files stay out of alerts. The receiving app verifies the signature against trusted teammate keys. Open review alerts are periodically reannounced, so teammates can see them on their next overlapping session. Enable desktop alerts in the browser if you also want system notifications while the app is open. Source and review decisions travel in ZIP exchanges.

## Review and sync

1. Commit your work on a topic branch and choose **Submit branch for review**. Select the branch and its target. If nearby Wi-Fi is off, share an exchange with both teammates.
2. Teammates import the ZIP, inspect **Changes**, run the **Pipeline**, then approve or request changes under **Reviews**. The pipeline checks out the exact submitted commit in a temporary directory and runs the locally configured command with your account's permissions. Review the code it will execute first.
3. Review decisions sync to the integrator over nearby Wi-Fi or via ZIP. The integrator can merge after two approvals and no outstanding change request. A new commit submitted from the same topic branch starts a fresh review. **Publish tips** lets the integrator share the current `dev` and `main` tips.
4. When everyone receives the merged state, choose **Sync dev** or **Sync main** as needed. Sync requires a clean checkout and moves existing branches only by fast-forward. It may switch branches in the selected worktree. If a target branch is already checked out in another worktree, select that worktree first. Resolve divergence or merge conflicts in Git before retrying.

An exchange forwards the signed records it already holds. Bundles can contain the full histories reachable from shared commits, including earlier versions of deleted files. Exchanges are limited to 512 MB. Git LFS objects and submodule repositories use their own storage and transfer workflows. Hosted GitLab CI runners and services need local equivalents.
