cask "peertree" do
  version "0.4.0"
  sha256 "71887a4607658f917128f1b9d07d2cf2101988550da3218841cb5fd14b2f91dd"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/ntatko/peertree"

  depends_on macos: ">= :sequoia"

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
