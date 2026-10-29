# Homebrew formula for wtree.
#
# From a git checkout the supported install is:
#   cargo install --path . --locked
#
# For a tap, point `url` at a release tarball and fill in `sha256`, or:
#   brew install --HEAD ./packaging/homebrew/wtree.rb
class Wtree < Formula
  desc "Read-only inspector for Grok Build worktrees, origins, and git repos"
  homepage "https://github.com/maxfalstein/wtree"
  license "MIT"
  version "0.1.0"
  head "https://github.com/maxfalstein/wtree.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "wtree", shell_output("#{bin}/wtree --version")
  end
end
