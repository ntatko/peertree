cask "peertree@beta" do
  version "0.5.1-beta.1"
  sha256 "f4c4d546966ce2c4efec6a446f84fa1925b30f731207126336c69b0c25bd1177"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree Beta"
  desc "Peer-to-peer Git review and branch sync (beta)"
  homepage "https://github.com/ntatko/peertree"

  conflicts_with cask: "peertree"
  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
