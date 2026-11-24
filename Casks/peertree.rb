cask "peertree" do
  version "0.5.0"
  sha256 "83b6b0c09c047c3343dc2934cde54f40f1d9341ace2a0f3c7365df212d2994d2"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/ntatko/peertree"

  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
