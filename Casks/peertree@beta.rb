cask "peertree@beta" do
  version "0.5.1-beta.3"
  sha256 "522ae4a18e022d2bc3652ca78d863e1a7a2e37bf62cf601a7bf1df173e00a34b"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree Beta"
  desc "Peer-to-peer Git review and branch sync (beta)"
  homepage "https://github.com/ntatko/peertree"

  conflicts_with cask: "peertree"
  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
