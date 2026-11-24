cask "peertree@beta" do
  version "0.5.1-beta.2"
  sha256 "d32e3c346e868f2b1d9075ad2f565d443ac042df99cb119c50e2ed108b1a6fd0"

  url "https://github.com/ntatko/peertree/releases/download/v#{version}/PeerTree-#{version}-macOS.zip"
  name "PeerTree Beta"
  desc "Peer-to-peer Git review and branch sync (beta)"
  homepage "https://github.com/ntatko/peertree"

  conflicts_with cask: "peertree"
  depends_on macos: :sequoia

  app "PeerTree.app"
  binary "#{appdir}/PeerTree.app/Contents/MacOS/peertree"
end
