cask "peertree" do
  version "0.4.2"
  sha256 "6f7b1f4c9c113ece0e66353394b9bc4070646b035dfdd24c910dbddee5704d83"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/ntatko/peertree"

  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
