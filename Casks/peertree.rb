cask "peertree" do
  version "0.4.1"
  sha256 "90d73cf6fa7703b035a591072eaf8a2c511ebd1a474defab9e161e48df2202d3"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/ntatko/peertree"

  depends_on macos: ">= :sequoia"

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
