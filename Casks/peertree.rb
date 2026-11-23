cask "peertree" do
  version "0.3.0"
  sha256 "61138733a8db78153d86ddf8961b489fc8a271c58e4702ddfa2b80bcfcdc4b12"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree"
  desc "Peer-to-peer Git review and branch sync"
  homepage "https://github.com/ntatko/peertree"

  depends_on macos: ">= :sequoia"

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
